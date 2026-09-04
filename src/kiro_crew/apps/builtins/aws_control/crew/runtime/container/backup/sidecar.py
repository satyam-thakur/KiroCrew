"""The asynchronous backup sidecar: the long-running copier.

One public seam, ``run_sidecar(settings)`` (see ``container/CONTRACT.md``). The
real work is factored into ``run_backup_cycle`` so a single pass can be tested
directly against a fake store and real temporary files.

Three on-disk facts shape the copier, each proven wrong-if-ignored by a test:

1. The transcript is atomically replaced, sometimes shorter. So we upload whole
   objects (``store.put`` has no offset/append). An incremental splice would be
   incorrect, not merely slow.
2. mtime is restored after every rewrite. So change detection is size PLUS a
   content hash, never mtime.
3. Writes hold a per-session advisory ``flock`` on ``<transcript>.lock``. So a
   read of a live transcript takes a shared ``flock`` on the same sidecar file
   and waits, rather than reading a half-replaced file.

Artifacts are write-once and heavy: an object already recorded in the state is
skipped without being re-hashed.
"""

from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..common import Settings
from . import layout
from .state import BackupState, ObjMeta, backup_status, state_path
from .store import ObjectStore, S3ObjectStore

logger = logging.getLogger("smc.backup.sidecar")

# How long a single file read will wait for the writer's lock before giving up
# for this cycle. Bounded so one wedged writer cannot stall the whole loop; the
# file is simply retried next cycle. The design accepts lag.
LOCK_WAIT_SECS = 5.0
_LOCK_POLL_SECS = 0.05

__all__ = ["run_sidecar", "run_backup_cycle", "CycleResult", "backup_status"]


@dataclass
class CycleResult:
    scanned: int = 0
    uploaded: int = 0
    skipped_unchanged: int = 0
    skipped_artifact: int = 0
    deferred_locked: int = 0
    uploaded_bytes: int = 0


class _Contended(Exception):
    """The writer's lock could not be taken within the wait budget."""


def _read_locked(path: Path, lock_path: Path, wait_secs: float) -> bytes:
    """Read ``path`` while holding a shared ``flock`` on ``lock_path``.

    Polls ``LOCK_SH | LOCK_NB`` to a deadline instead of a bare blocking
    ``flock``, so the wait is bounded. The exclusive writer blocks us and we
    block no writer for longer than the read itself (a few milliseconds on a
    small transcript). Raises ``_Contended`` on timeout rather than reading
    through the lock.
    """
    fd = None
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
        deadline = time.monotonic() + wait_secs
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise _Contended(str(path))
                time.sleep(_LOCK_POLL_SECS)
        try:
            return path.read_bytes()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        if fd is not None:
            os.close(fd)


def run_backup_cycle(
    settings: Settings,
    store: ObjectStore,
    state: BackupState,
    *,
    lock_wait_secs: float = LOCK_WAIT_SECS,
) -> CycleResult:
    """One backup pass over the whole unit. Mutates ``state`` in place.

    Whole-object upload; size+hash change detection; write-once artifact skip;
    lock-respecting reads of live transcripts.
    """
    result = CycleResult()
    art_prefix = layout.artifact_prefix(settings)

    for local_path, rel_key in layout.iter_backup_files(settings):
        result.scanned += 1
        prev = state.objects.get(rel_key)

        # Write-once artifacts: if we have already uploaded this object, do not
        # re-hash the file or re-upload it. (Presence is enough; artifacts are
        # never rewritten.)
        if rel_key.startswith(art_prefix) and prev is not None:
            result.skipped_artifact += 1
            continue

        try:
            if layout.needs_lock(settings, local_path):
                lock_path = local_path.parent / (local_path.name + ".lock")
                data = _read_locked(local_path, lock_path, lock_wait_secs)
            else:
                data = local_path.read_bytes()
        except _Contended:
            result.deferred_locked += 1
            logger.debug("backup: %s locked, deferring to next cycle", rel_key)
            continue
        except FileNotFoundError:
            # Rotated/removed between listing and read; picked up next cycle
            # (its content now lives under a new archive key).
            continue

        size = len(data)
        digest = hashlib.sha256(data).hexdigest()
        if prev is not None and prev.size == size and prev.hash == digest:
            result.skipped_unchanged += 1
            continue

        store.put(layout.full_key(settings, rel_key), data)
        state.objects[rel_key] = ObjMeta(size, digest)
        result.uploaded += 1
        result.uploaded_bytes += size

    return result


def _build_store(settings: Settings) -> ObjectStore | None:
    if not settings.backup_bucket:
        return None
    return S3ObjectStore(settings.backup_bucket)


def run_sidecar(
    settings: Settings,
    *,
    store: ObjectStore | None = None,
    stop: "threading.Event | None" = None,
    max_cycles: int | None = None,
) -> None:
    """Run the copier until ``stop`` is set (the container's normal case).

    ``store``/``stop``/``max_cycles`` exist for tests; the container calls this
    with only ``settings``. If no bucket is configured the sidecar logs and
    returns rather than crashing the task — backup is then disabled, which is a
    degraded state the owner can see, not a dead container.
    """
    if store is None:
        store = _build_store(settings)
    if store is None:
        logger.warning(
            "backup: SMC_BACKUP_BUCKET is not set; backup is DISABLED for this "
            "task. Conversations will not survive the container."
        )
        return

    stop = stop or threading.Event()
    spath = state_path(settings)
    state = BackupState.load(spath)

    # Seed the object index from what is already in the bucket so a task restart
    # does not re-upload every write-once artifact.
    try:
        existing = store.list(layout.object_prefix(settings))
        seed: dict[str, ObjMeta | int] = {}
        for full, size in existing.items():
            rel = layout.rel_from_full(settings, full)
            if rel is not None:
                seed[rel] = size
        state.seed_sizes(seed)
    except Exception:  # noqa: BLE001 - seeding is an optimisation, never fatal
        logger.warning("backup: could not seed state from bucket", exc_info=True)

    n = 0
    while not stop.is_set():
        started = time.time()
        try:
            res = run_backup_cycle(settings, store, state)
            state.cycles += 1
            state.last_cycle_ts = time.time()
            state.last_success_ts = state.last_cycle_ts
            state.save(spath)
            logger.info(
                "backup cycle=%d scanned=%d uploaded=%d (%d B) unchanged=%d "
                "artifacts_skipped=%d deferred_locked=%d lag=0.0s",
                state.cycles,
                res.scanned,
                res.uploaded,
                res.uploaded_bytes,
                res.skipped_unchanged,
                res.skipped_artifact,
                res.deferred_locked,
            )
        except Exception:  # noqa: BLE001 - one bad cycle must not kill the loop
            logger.exception("backup: cycle failed; will retry next interval")

        n += 1
        if max_cycles is not None and n >= max_cycles:
            break
        elapsed = time.time() - started
        stop.wait(max(0.0, settings.backup_interval_secs - elapsed))
