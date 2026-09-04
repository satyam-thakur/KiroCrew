"""Durable provenance for the ``settings.local.json`` seed Crew writes.

Crew seeds ``<work_dir>/.claude/settings.local.json`` for a claude-agent-acp
session and overwrites or removes ONLY the file it owns. Ownership used to be
proven entirely from per-instance memory ("this client created it" plus "the
bytes it wrote"), which answers the question correctly inside one session and
wrongly outside one: a seed left behind by a session that was killed, or by an
earlier app version, reads as a stranger's file forever after. The writer then
takes its leave-it-alone branch on every subsequent session, so a stale
``availableModels`` allowlist (and a stale ``permissions.defaultMode``, up to an
inherited ``bypassPermissions``) becomes permanent project state that Crew can
neither refresh nor clean up.

This module is the missing half: a small record, under Crew's OWN data home, of
the bytes Crew last wrote to a given settings path. It is a **provenance
credential, not a permission grant** — a record alone proves nothing, because
adoption additionally requires the file on disk to still hash to the recorded
digest. A user-authored file (or a Crew file the user has since edited) never
matches, so it is still left untouched; only Crew's own orphan is recognized and
re-seeded.

Four properties the callers depend on:

* **Nothing is added to the user's project.** The record lives beside Crew's
  other sidecars in ``config_dir()``, keyed by the settings path, so a checked-out
  repository gains no extra file to notice, ignore or commit.
* **Lookups never touch the disk.** ``_reset_state`` consults ownership
  synchronously ON the event loop, so the sidecar is read once at import and
  served from memory afterwards. Only the two MUTATIONS write, and only one of
  them (:func:`forget`, revoking a grant whose file has just been unlinked) runs
  on the loop — on a path that already unlinks and hashes there.
* **Every failure answers "not ours".** An unreadable or corrupt sidecar, a
  missing entry, a malformed entry — all degrade to the pre-existing behaviour of
  leaving the file alone, which is the safe direction.
* **A record is adoptable only once nobody here still holds it.** Ownership is
  scoped to an owner token, so an orphan is adopted by the next session while a
  path a LIVE client in this process is seeding stays that client's own.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from kiro_crew.atomic_write import atomic_write
from kiro_crew.config.paths import config_dir

logger = logging.getLogger(__name__)

# Bumped when the SHAPE OF THE SEEDED FILE changes in a way that makes an older
# seed worth rewriting rather than trusting. Recorded per entry so a future
# version can tell which format wrote a seed it finds. Nothing compares it today,
# deliberately: one format exists, so there is nothing to distinguish, and
# adoption is decided by the digest alone.
SEED_SCHEMA = 1

# One entry per work_dir that has ever been seeded. Capped: a long-lived install
# that rotates through many disposable work dirs must not grow the sidecar
# without bound, and the oldest entries are the ones least likely to still have
# a matching file on disk.
_MAX_ENTRIES = 64

# Process-wide runtime state, like model_registry._ADVERTISED_MODELS: loaded once
# at import, mutated in memory, persisted on write. Tests isolate it by
# monkeypatching this dict and :func:`_sidecar_path`.
_RECORDS: dict[str, dict[str, Any]] = {}

# Which owner token, if any, is CURRENTLY seeding each path in this process.
# Adoption is for orphans, and only a record with no live holder is one: two
# keyless sessions share the default work_dir (``config_dir() / "workspace"``),
# so without this a second session would recognize the FIRST session's live seed
# as an orphan, re-seed it with its own ``permissions.defaultMode``, and unlink it
# on its own reset -- out from under a session still running against it. Records
# loaded from the sidecar at import have no live holder by construction, which is
# exactly right: whoever wrote them is a previous process.
_LIVE: dict[str, str] = {}

# Serializes the record transaction: mutate ``_RECORDS``, prune, snapshot, publish.
# Without it two seeds running concurrently under ``asyncio.to_thread`` can each
# build a snapshot and publish in the opposite order, so an OLDER snapshot lands
# last and the newer seed's provenance is lost -- the surviving file then reads as
# a stranger's on the next run, which is the whole failure this module removes.
#
# Held across the ``atomic_write``, because the snapshot and its publish are one
# step: releasing between them is exactly the reordering above. Holders are
# :func:`record` (off-loop, on the already-offloaded seed path) and :func:`forget`
# (on-loop, revoking a grant beside an unlink that already blocks there), so the
# worst wait is one bounded sidecar write. The read-only and claim-only entry
# points deliberately do NOT take it -- see :func:`recorded` and :func:`release`.
_LOCK = threading.Lock()


def _sidecar_path() -> Path:
    """Path to the seed-provenance sidecar under Crew's data home.

    ``config_dir()`` is resolved per call rather than folded into a module
    constant, so ``KIROCREW_HOME`` and test overrides are honoured and home
    resolution can never run as an import side effect.
    """
    return config_dir() / "settings_seeds.json"


def _key(path: Path | str) -> str:
    """Sidecar key for a settings path.

    Deliberately the path as GIVEN, not ``resolve()``d: resolution follows
    symlinks, and every caller derives this from the same
    ``work_dir / ".claude" / "settings.local.json"`` expression, so the
    unresolved string is both stable across sessions and free of a filesystem
    round-trip on the lookup path.
    """
    return os.fspath(path)


def digest(payload: str) -> str:
    """The digest recorded for *payload* — sha256 of its UTF-8 bytes."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load() -> None:
    """Load the persisted sidecar into ``_RECORDS`` (best-effort).

    Called once at import. A missing file is normal (nothing seeded yet); a
    corrupt one is logged at debug and ignored, which leaves every path looking
    unowned — the same answer Crew gave before this record existed.
    """
    try:
        path = _sidecar_path()
        if not path.is_file():
            return
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        seeds = data.get("seeds") if isinstance(data, dict) else None
        if not isinstance(seeds, dict):
            return
        for key, entry in seeds.items():
            if not isinstance(key, str) or not isinstance(entry, dict):
                continue
            size, sha = entry.get("size"), entry.get("sha256")
            if isinstance(size, int) and size >= 0 and isinstance(sha, str) and sha:
                _RECORDS[key] = {
                    "size": size,
                    "sha256": sha,
                    "schema": entry.get("schema"),
                }
    except (OSError, ValueError, TypeError):  # pragma: no cover - corrupt/absent sidecar
        logger.debug(
            "seed-provenance sidecar unreadable; seeds will read as unowned", exc_info=True
        )


_load()


def _persist() -> None:
    """Write ``_RECORDS`` to the sidecar (best-effort, blocking).

    Prunes to ``_MAX_ENTRIES``, dropping entries whose file is gone first: those
    can never be adopted again, so they are pure growth. A persist failure is
    logged, not raised — the in-memory record still serves this process, and the
    only cost is that a future process re-reads the path as unowned.

    Callers hold :data:`_LOCK`; the prune, the snapshot and the publish are one
    transaction. Two processes still race the sidecar last-writer-wins — an
    ``atomic_write`` rename cannot arbitrate across processes — and that residual
    is benign in the same way a missing entry is: the loser's path reads as unowned
    next run, so its seed is left alone rather than adopted wrongly.
    """
    try:
        if len(_RECORDS) > _MAX_ENTRIES:
            for key in [k for k in list(_RECORDS) if not os.path.isfile(k)]:
                if len(_RECORDS) <= _MAX_ENTRIES:
                    break
                _RECORDS.pop(key, None)
                _LIVE.pop(key, None)
            # Still over the cap with every entry live: drop from the front, which
            # is insertion order, so the least recently seeded path loses first.
            while len(_RECORDS) > _MAX_ENTRIES:
                _LIVE.pop(next(iter(_RECORDS)), None)
                _RECORDS.pop(next(iter(_RECORDS)))
        snapshot = {"version": 1, "seeds": {k: dict(v) for k, v in dict(_RECORDS).items()}}
        # 0o600: the sidecar names the work dirs this install has seeded.
        atomic_write(_sidecar_path(), json.dumps(snapshot), mode=0o600)
    except (OSError, ValueError, TypeError):  # pragma: no cover - disk full / perms
        logger.debug("could not persist seed-provenance sidecar", exc_info=True)


def claim(path: Path | str, owner: str) -> bool:
    """Take *path*'s live slot for *owner*; ``False`` if somebody else has it.

    Called by an adopter BEFORE it rewrites an orphan, and it is the decision
    itself rather than bookkeeping after one: :func:`recorded` only reports the
    live holder at the moment it is asked, so two clients starting together can
    both read the same orphan as adoptable, and both would then take the
    ``O_TRUNC`` re-seed — one session left running under the other's
    ``permissions.defaultMode``. ``setdefault`` is a single atomic dict
    operation, so exactly one of them can win it no matter how they interleave.

    Idempotent for a holder that already owns the slot, so re-seeding the same
    path in the same client is not a self-refusal.

    A winner that then FAILS to write must hand the slot back with
    :func:`release`, or the orphan it was about to repair stays wedged behind a
    claim nobody is using for the rest of the process.
    """
    return _LIVE.setdefault(_key(path), owner) == owner


def release(path: Path | str, owner: str) -> None:
    """Give up *owner*'s live claim on *path* without disowning the record.

    The counterpart to a :func:`claim` whose write did not land. Only ``_LIVE``
    is dropped, deliberately NOT ``_RECORDS``: the record is what makes the path
    adoptable at all, so clearing it would leave an orphan seed -- possibly one
    carrying ``bypassPermissions`` -- that no later session is permitted to
    rewrite or delete. That is the harm this exists to avoid, not a smaller
    version of it. Compare :func:`forget`, which is for a path Crew genuinely no
    longer owns because the file is gone.

    A no-op when a different owner holds the slot, so a loser cannot evict the
    winner. In-memory only and lock-free (one atomic dict operation), so it is
    safe from a failure path on the event loop.
    """
    key = _key(path)
    if _LIVE.get(key) == owner:
        _LIVE.pop(key, None)


def record(path: Path | str, payload: str, owner: str) -> None:
    """Record that *owner* just wrote *payload* to *path*.

    Blocking (persists the sidecar) and serialized on :data:`_LOCK`; callers run it
    on the already-off-loop seed path. Re-recording the same bytes still rewrites,
    which is cheap and keeps the entry at the back of the insertion order used for
    pruning. *owner* is also claimed as the path's LIVE holder, so a sibling client
    in this process reads it as somebody's live seed rather than as an orphan.
    """
    key = _key(path)
    with _LOCK:
        _RECORDS.pop(key, None)  # re-insert at the back
        _RECORDS[key] = {
            "size": len(payload.encode("utf-8")),
            "sha256": digest(payload),
            "schema": SEED_SCHEMA,
        }
        _LIVE[key] = owner
        _persist()


def recorded(path: Path | str, owner: str) -> tuple[int, str] | None:
    """The ``(size, sha256)`` Crew wrote to *path*, as far as *owner* may claim it.

    ``None`` when nothing was recorded, or when a DIFFERENT owner in this process
    is still seeding that path: the record then describes a live session's file,
    not an orphan, and re-seeding it would overwrite that session's permission
    mode and delete its file on this client's reset.

    In-memory only, so this is safe to call from the event loop — and deliberately
    LOCK-FREE for the same reason: :data:`_LOCK` is held across the sidecar write,
    so taking it here would let a worker's disk I/O stall the one loop. Each
    statement below is a single dict read, which is atomic under CPython, so a
    concurrent :func:`record` can only make this return the older or the newer
    entry, never a torn one. The size is returned alongside the digest so a caller
    can reject a mismatched file without reading it, and bound its read to exactly
    the bytes it will hash.
    """
    key = _key(path)
    live = _LIVE.get(key)
    if live is not None and live != owner:
        return None
    entry = _RECORDS.get(key)
    if not entry:
        return None
    size, sha = entry.get("size"), entry.get("sha256")
    if not isinstance(size, int) or not isinstance(sha, str) or not sha:
        return None
    return size, sha


def forget(path: Path | str, owner: str) -> None:
    """Drop *owner*'s claim on *path* — Crew no longer claims it.

    A no-op when a different owner holds the path live, so a client that could
    not adopt a sibling's seed cannot revoke the sibling's claim either.

    **Persists.** Dropping the entry from memory alone would leave the sidecar
    naming a path Crew has just deleted, and the digest check does not make that
    inert: the next process reloads the entry, and any file that happens to hash
    to it -- most plainly the very seed a user committed to the repository and
    then restored -- is adopted, overwritten with this install's
    ``permissions.defaultMode``, and unlinked on reset. So the grant has to die
    with the file it described, not merely leave this process's memory.

    That costs a small blocking write on the event loop, since ``_reset_state``
    calls this from the loop. Accepted deliberately: that same path already
    unlinks the file and reads-and-hashes it to decide ownership, so the persist
    adds one more write beside I/O that is already there, and it is bounded by
    ``_MAX_ENTRIES``. The property callers actually depend on is that *lookups*
    stay off the disk (see :func:`recorded`), and this is not a lookup.
    """
    key = _key(path)
    with _LOCK:
        live = _LIVE.get(key)
        if live is not None and live != owner:
            return
        _LIVE.pop(key, None)
        if _RECORDS.pop(key, None) is not None:
            _persist()
