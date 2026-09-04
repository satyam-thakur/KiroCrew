"""A desktop build must record WHICH Electron it was packaged against.

``website/electron/package.json`` pins a RANGE (``^43.x``), so two builds a
month apart can resolve to different Electron versions with nothing recording
which was which. That matters more than it sounds: symbolizing a crash against
the wrong Electron does not fail loudly. ``atos`` happily prints the nearest
neighbouring symbol for every frame, producing a stack that reads like a real
call chain and is not -- which is how one main-process crash got filed against a
component that never appeared in it.

``scripts/emit-symbols-manifest.mjs`` writes the resolved version plus the exact
symbol-archive names and URLs, and ``scripts/symbolize-crash.sh`` consumes it.
The two ways that plumbing silently rots are what this file pins:

1. The emit step running BEFORE the build, where ``node_modules/electron`` does
   not yet exist or still holds a previous resolution.
2. The manifest not being in the upload globs, so it is written and discarded.

Neither shows up as a red build -- the artifact is simply missing the one file
that makes a future crash report readable.

A third way it rots is not silent but dangerous: the symbolizer TRUSTS the
manifest. It reads an asset name out of it and makes that a path under the
download cache, and reads a URL out of it and fetches that. A manifest arrives as
a downloaded CI artifact, so neither value is this script's own, and a name
carrying ``../`` would put attacker-chosen bytes on a writable host file. The
last group of tests runs the real script against hostile manifests.

Offline: the static checks read the workflow YAML and the script source, and the
execution checks all exit before the script reaches the network.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "build-desktop.yml"
EMITTER = ROOT / "scripts" / "emit-symbols-manifest.mjs"
SYMBOLIZER = ROOT / "scripts" / "symbolize-crash.sh"

MANIFEST_PATH = "website/electron/dist/symbols-manifest.json"


def _build_desktop_steps() -> list[dict]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return list(doc["jobs"]["build-desktop"]["steps"])


def _index_of(steps: list[dict], predicate) -> int:
    for index, step in enumerate(steps):
        if predicate(step):
            return index
    return -1


def test_manifest_is_emitted_after_the_build() -> None:
    """The resolved Electron version only exists once the build has installed it.

    Emitting earlier would read a stale ``node_modules/electron`` (or none), and
    a manifest naming the wrong version is worse than no manifest: it sends
    someone to download symbols that will confidently mis-symbolize.
    """
    steps = _build_desktop_steps()
    build = _index_of(steps, lambda s: s.get("name") == "Build desktop app")
    emit = _index_of(steps, lambda s: "emit-symbols-manifest.mjs" in str(s.get("run", "")))

    assert build != -1, "build-desktop lost its 'Build desktop app' step"
    assert emit != -1, (
        "no step runs scripts/emit-symbols-manifest.mjs, so the built artifacts "
        "record no Electron version and a crash from them cannot be symbolized"
    )
    assert emit > build, (
        "the symbols manifest must be emitted AFTER the build: the resolved "
        "Electron version comes from the installed node_modules/electron"
    )


def test_manifest_is_uploaded_with_the_artifacts() -> None:
    """Written but not uploaded is the same as not written."""
    steps = _build_desktop_steps()
    upload = _index_of(
        steps,
        lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact"),
    )
    assert upload != -1, "build-desktop lost its upload step"

    emit = _index_of(steps, lambda s: "emit-symbols-manifest.mjs" in str(s.get("run", "")))
    assert emit < upload, "the manifest must be written before the upload reads it"

    paths = str(steps[upload]["with"]["path"]).split()
    assert MANIFEST_PATH in paths, (
        f"{MANIFEST_PATH} is missing from the upload globs, so every build "
        "writes it and then throws it away"
    )


def test_the_symbolizer_ships_alongside_the_manifest() -> None:
    """A manifest nobody can act on is a decoration.

    The manifest's own ``symbolize`` field names the consumer, so that path has
    to exist and be runnable.
    """
    assert EMITTER.exists(), f"missing {EMITTER.relative_to(ROOT)}"
    assert SYMBOLIZER.exists(), f"missing {SYMBOLIZER.relative_to(ROOT)}"
    assert SYMBOLIZER.stat().st_mode & 0o111, f"{SYMBOLIZER.relative_to(ROOT)} is not executable"

    emitter_source = EMITTER.read_text(encoding="utf-8")
    assert (
        '"scripts/symbolize-crash.sh"' in emitter_source
    ), "the manifest's symbolize field must name a script that exists"


def test_the_emitter_reads_the_resolved_version_not_the_range() -> None:
    """The whole point: never the ``^43.x`` range from package.json.

    A range does not identify a binary. This is a source assertion rather than
    an execution one because running the emitter needs an installed Electron,
    which a bare checkout does not have.
    """
    source = EMITTER.read_text(encoding="utf-8")
    assert (
        'node_modules", "electron", "package.json"' in source
    ), "the emitter must read the RESOLVED version from the installed Electron"


def test_both_symbol_formats_are_recorded_for_macos() -> None:
    """The two archives are not interchangeable inputs.

    ``atos`` reads Mach-O DWARF out of a dSYM to symbolize a ``.ips`` report;
    ``minidump_stackwalk`` reads Breakpad ``.sym`` text to walk a Crashpad
    ``.dmp``. ``crash-collector.js`` surfaces both artifact kinds, so a manifest
    listing only one leaves half the crashes unreadable.
    """
    source = EMITTER.read_text(encoding="utf-8")
    assert "-dsym.tar.xz" in source, "no dSYM asset: a .ips report cannot be symbolized"
    assert "-symbols.zip" in source, "no Breakpad asset: a .dmp cannot be walked"

    symbolizer = SYMBOLIZER.read_text(encoding="utf-8")
    assert "-dsym.tar.xz" in symbolizer and "-symbols.zip" in symbolizer
    assert "dwarfdump --uuid" in symbolizer, (
        "the symbolizer must cross-check the dSYM UUID against the report's "
        "framework image -- a mismatched dSYM prints plausible, WRONG frames "
        "rather than failing, and that silent failure is the whole hazard"
    )


# --- The manifest is untrusted input ---------------------------------------
#
# These run the real script. It needs bash (for the script) and node (to parse
# the manifest), and exits at the validation gate well before any download, so
# there is no network dependency -- but there IS a toolchain one, hence the skip.

VERSION = "43.2.0"
OFFICIAL = f"https://github.com/electron/electron/releases/download/v{VERSION}"

requires_shell_and_node = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("node") is None,
    reason="the symbolizer is a bash script that parses its manifest with node",
)


def _manifest(tmp_path: Path, name: str, url: str) -> Path:
    """A one-asset darwin manifest in the shape the emitter produces."""
    path = tmp_path / "symbols-manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "appVersion": "0.0.0-test",
                "platform": "darwin",
                "arches": ["arm64"],
                "electron": {"version": VERSION},
                "assets": [
                    {"arch": "arm64", "kind": "breakpad", "name": name, "url": url}
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _symbolize(tmp_path: Path, manifest: Path) -> subprocess.CompletedProcess[str]:
    artifact = tmp_path / "crash.dmp"
    artifact.write_bytes(b"")  # never parsed: the gate is upstream of the walker
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    return subprocess.run(
        [
            "bash",
            str(SYMBOLIZER),
            str(artifact),
            "--manifest",
            str(manifest),
            "--arch",
            "arm64",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
             "HOME": str(tmp_path),
             "KIROCREW_SYMBOL_CACHE": str(cache)},
    )


@requires_shell_and_node
def test_a_manifest_asset_name_cannot_escape_the_symbol_cache(tmp_path: Path) -> None:
    """``$CACHE/$ASSET`` is a path, and the manifest is a downloaded file.

    The asset name becomes the download target and then the extraction source, so
    a name containing ``../`` writes attacker-chosen bytes to an attacker-chosen
    place. Refused outright rather than trimmed to its basename: a repaired path
    is still a manifest that lied about what this build published.
    """
    manifest = _manifest(
        tmp_path,
        "../../../../tmp/pwned-symbols.zip",
        f"{OFFICIAL}/../../../../tmp/pwned-symbols.zip",
    )
    result = _symbolize(tmp_path, manifest)

    assert result.returncode != 0, "a traversing asset name was accepted"
    assert "refusing asset name" in result.stderr
    assert not (tmp_path / "pwned-symbols.zip").exists()
    assert not (tmp_path / "pwned-symbols.zip.part").exists()


@requires_shell_and_node
def test_a_manifest_url_must_be_electrons_own_release(tmp_path: Path) -> None:
    """An honest-looking name with a chosen URL is the same attack, one step later.

    The cache filename is harmless here; the bytes are not. Symbols come from
    electron/electron's releases and nowhere else, so the URL is compared for
    equality against the one the name implies.
    """
    name = f"electron-v{VERSION}-darwin-arm64-symbols.zip"
    manifest = _manifest(tmp_path, name, f"https://example.invalid/{name}")
    result = _symbolize(tmp_path, manifest)

    assert result.returncode != 0, "an off-origin symbol URL was accepted"
    assert "refusing download URL" in result.stderr
    assert "example.invalid" in result.stderr, "the refusal should show what it read"


@requires_shell_and_node
def test_an_implausible_electron_version_is_refused(tmp_path: Path) -> None:
    """The version is interpolated into the URL, so it is checked too.

    It reaches the script from three places -- the crash report, the manifest, and
    ``--electron`` -- and none of them is this script's own.
    """
    name = f"electron-v{VERSION}-darwin-arm64-symbols.zip"
    manifest = _manifest(tmp_path, name, f"{OFFICIAL}/{name}")
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(f'"{VERSION}"', '"../../x"', 1),
        encoding="utf-8",
    )
    result = _symbolize(tmp_path, manifest)

    assert result.returncode != 0, "a traversing Electron version was accepted"
    assert "implausible Electron version" in result.stderr


@requires_shell_and_node
def test_the_manifest_the_emitter_actually_writes_passes_the_gate(tmp_path: Path) -> None:
    """The gate has to be lossless for honest input, or it just breaks the tool.

    Exact matching is only safe because ``assetsFor`` derives every name and URL
    from (platform, arch, version) by one formula. This asserts the emitter's own
    output clears the check -- pre-seeding the extracted directory so the run
    stops at the missing stackwalker rather than downloading 128 MB.
    """
    name = f"electron-v{VERSION}-darwin-arm64-symbols.zip"
    manifest = _manifest(tmp_path, name, f"{OFFICIAL}/{name}")
    (tmp_path / "cache" / name[: -len(".zip")]).mkdir(parents=True)

    result = _symbolize(tmp_path, manifest)

    combined = result.stdout + result.stderr
    assert "refusing" not in combined, f"the gate rejected honest input:\n{combined}"
    assert "implausible" not in combined
    assert f"Asset: {name}" in result.stdout
    assert "(cached)" in result.stdout, "the gate ran before the cache lookup"
