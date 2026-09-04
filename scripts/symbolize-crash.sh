#!/usr/bin/env bash
# Turn a Kiro Crew crash artifact into readable frames.
#
# The problem this closes: a macOS `.ips` report from a shipped build has
# `asi: null` and every frame symbol is a NEAREST-NEIGHBOUR GUESS, because the
# Electron Framework in a release build is stripped. Read literally, such a
# report implicates whatever exported symbol happens to sit below the crash
# address — which is how one main-process crash got filed against a component
# that never appeared in the actual call chain. Symbolizing is not a nicety
# here; unsymbolized, the stack is actively misleading.
#
# What was missing was never really the symbols. Electron publishes them with
# every release and keeps them forever, and a `.ips` even names the exact build
# it needs (`usedImages[].CFBundleShortVersionString` plus a Mach-O `uuid`).
# What was missing was the RECIPE: that these archives exist, which of the two
# formats matches which artifact, that `.ips` frame addresses are image-relative
# and have to be rebased before atos sees them, and that a dSYM from the wrong
# build fails SILENTLY — printing plausible, wrong frames rather than an error.
# This script is that recipe, and the UUID check below is what makes the silent
# failure loud.
#
#   .ips report   -> dSYM (Mach-O DWARF, ~1.4-1.7 GB) -> atos
#   .dmp minidump -> Breakpad .sym (~128-146 MB)      -> minidump_stackwalk
#
# Usage:
#   symbolize-crash.sh <crash-artifact> [--manifest <symbols-manifest.json>]
#                                       [--electron <version>] [--arch arm64|x64]
#
# A `.ips` needs no version argument: the report names its own. A `.dmp` does,
# because a minidump identifies modules by debug ID rather than by semver — pass
# `--manifest` (CI archives one beside each build's artifacts, see
# scripts/emit-symbols-manifest.mjs) or `--electron` if you know the version.
#
# Downloads are cached, because these run 128 MB to 1.7 GB per arch:
#   KIROCREW_SYMBOL_CACHE   default ${XDG_CACHE_HOME:-~/.cache}/kirocrew/electron-symbols
set -euo pipefail

ARTIFACT=""
MANIFEST=""
ELECTRON_VERSION=""
ARCH=""
REPORT_UUID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest)  MANIFEST="${2:?--manifest needs a path}"; shift 2 ;;
    --electron)  ELECTRON_VERSION="${2:?--electron needs a version}"; shift 2 ;;
    --arch)      ARCH="${2:?--arch needs arm64 or x64}"; shift 2 ;;
    -h|--help)   sed -n '2,34p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0 ;;
    -*)          echo "ERROR: unknown option '$1'" >&2; exit 2 ;;
    *)
      if [ -n "$ARTIFACT" ]; then
        echo "ERROR: one crash artifact at a time (got '$ARTIFACT' and '$1')" >&2
        exit 2
      fi
      ARTIFACT="$1"; shift ;;
  esac
done

if [ -z "$ARTIFACT" ]; then
  echo "usage: symbolize-crash.sh <crash-artifact> [--manifest <file>] [--electron <version>] [--arch arm64|x64]" >&2
  exit 2
fi
if [ ! -f "$ARTIFACT" ]; then
  echo "ERROR: no such crash artifact: $ARTIFACT" >&2
  exit 1
fi

# Picked by extension rather than asked for: the artifact already says which it
# is, and the two formats are not interchangeable inputs.
case "$ARTIFACT" in
  *.ips)  KIND="ips" ;;
  *.dmp)  KIND="dmp" ;;
  *)
    echo "ERROR: unrecognized artifact '$ARTIFACT' (expected a .ips report or a .dmp minidump)" >&2
    exit 1 ;;
esac

CACHE="${KIROCREW_SYMBOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kirocrew/electron-symbols}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Which Electron build, and which slice ----------------------------------
#
# Never the locally installed Electron: that is whatever this workspace happens
# to have resolved, and has nothing to do with the build that crashed.

if [ "$KIND" = "ips" ] && [ -z "$ELECTRON_VERSION" ]; then
  # The report's own record of its framework image. Preferred over the manifest
  # because it describes THIS crash rather than a build that may not be the one
  # the reporter was running.
  read -r REPORT_VERSION REPORT_UUID REPORT_ARCH <<EOF || true
$(node -e '
const fs = require("fs");
const text = fs.readFileSync(process.argv[1], "utf8").split("\n");
const payload = JSON.parse(text.slice(1).join("\n"));
const image = (payload.usedImages || [])
  .find(i => /Electron Framework/.test(`${i.name || ""} ${i.path || ""}`));
if (!image) process.exit(0);
process.stdout.write([
  image.CFBundleShortVersionString || "",
  image.uuid || "",
  image.arch || "",
].join(" "));
' "$ARTIFACT")
EOF
  if [ -n "${REPORT_VERSION:-}" ]; then
    ELECTRON_VERSION="$REPORT_VERSION"
    # The report also names the slice the crashed process was running, which
    # beats guessing from this host: a universal app can crash in either.
    if [ -z "$ARCH" ]; then
      case "${REPORT_ARCH:-}" in
        arm64*) ARCH="arm64" ;;
        x86_64) ARCH="x64" ;;
      esac
    fi
    echo "Report names Electron $ELECTRON_VERSION (framework uuid ${REPORT_UUID:-unknown})"
  fi
fi

if [ -z "$ELECTRON_VERSION" ]; then
  if [ -z "$MANIFEST" ]; then
    # CI uploads the manifest beside the build's artifacts, so a downloaded run
    # directory usually already holds one.
    for candidate in \
      "$(dirname "$ARTIFACT")/symbols-manifest.json" \
      "website/electron/dist/symbols-manifest.json"; do
      if [ -f "$candidate" ]; then MANIFEST="$candidate"; break; fi
    done
  fi
  if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then
    echo "ERROR: no Electron version to symbolize against." >&2
    echo "       A .dmp identifies its modules by debug ID, not by version, so the" >&2
    echo "       version has to come from the build: pass --manifest with the" >&2
    echo "       symbols-manifest.json from that build's CI artifact, or --electron" >&2
    echo "       if you know it. Guessing is not an option — the wrong symbols do" >&2
    echo "       not fail loudly, they print plausible, wrong frames." >&2
    exit 1
  fi
  ELECTRON_VERSION="$(node -e '
    const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    process.stdout.write(String((m.electron && m.electron.version) || ""));
  ' "$MANIFEST")"
  if [ -z "$ELECTRON_VERSION" ]; then
    echo "ERROR: $MANIFEST has no electron.version" >&2
    exit 1
  fi
  echo "Manifest: $MANIFEST (electron $ELECTRON_VERSION)"
fi

if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    arm64|aarch64) ARCH="arm64" ;;
    *)             ARCH="x64" ;;
  esac
  echo "Arch: $ARCH (from this host; pass --arch for a report from the other slice)"
fi

# Which asset, from the manifest when there is one.
#
# This used to build the name with `darwin` hardcoded, which was silently wrong
# for exactly the case the manifest exists to serve: a Linux build records a
# Breakpad entry, and reconstructing the name here asked for
# `…-darwin-x64-symbols.zip` instead. Breakpad trees are keyed by debug ID, so
# the mismatch does not error — `minidump_stackwalk` just finds no symbols and
# the report reads as "no symbols cover these frames", which is the wrong
# conclusion. The manifest already carries the right `name` and `url` per
# (kind, arch); read them instead of re-deriving them.
if [ "$KIND" = "ips" ]; then WANT_KIND="dsym"; else WANT_KIND="breakpad"; fi

ASSET=""
URL=""
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
  # Name then URL, both newline-terminated, or no output when nothing matches.
  # `|| true` because the second `read` reports EOF on an empty match, which is a
  # normal outcome handled just below, not a failure `set -e` should abort on.
  { read -r ASSET; read -r URL; } <<EOF || true
$(node -e '
  const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  const hit = (m.assets || []).find(
    (a) => a.kind === process.argv[2] && a.arch === process.argv[3]);
  if (hit) process.stdout.write(`${hit.name}\n${hit.url}\n`);
' "$MANIFEST" "$WANT_KIND" "$ARCH")
EOF
  if [ -z "$ASSET" ] || [ -z "$URL" ]; then
    # Fail loudly rather than falling back to a guess. The manifest lists what
    # this build actually has; if it has no matching entry, the answer is that
    # these symbols were not published for that slice, not that we should try a
    # plausible name.
    PLATFORM="$(node -e '
      const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(m.platform || "?"));
    ' "$MANIFEST")"
    echo "ERROR: $MANIFEST lists no $WANT_KIND asset for arch $ARCH." >&2
    echo "       That manifest is for platform '$PLATFORM'; its assets are:" >&2
    node -e '
      const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      for (const a of m.assets || []) process.stdout.write(`         ${a.kind} ${a.arch} ${a.name}\n`);
    ' "$MANIFEST" >&2
    echo "       Pass --arch for the other slice, or use the manifest from the" >&2
    echo "       build that produced this report." >&2
    exit 1
  fi
  echo "Asset: $ASSET (from manifest, kind=$WANT_KIND arch=$ARCH)"
else
  # No manifest — only reachable via an explicit --electron, where the caller has
  # asserted the version. Derive the platform from this host rather than assuming
  # macOS, so a Linux operator gets a Linux asset name.
  case "$(uname -s)" in
    Darwin) PLATFORM="darwin" ;;
    Linux)  PLATFORM="linux" ;;
    *)      PLATFORM="win32" ;;
  esac
  if [ "$KIND" = "ips" ] && [ "$PLATFORM" != "darwin" ]; then
    echo "ERROR: a .ips report is a macOS artifact, but this host is $PLATFORM." >&2
    echo "       Pass --manifest from the macOS build that produced it." >&2
    exit 1
  fi
  if [ "$WANT_KIND" = "dsym" ]; then
    ASSET="electron-v${ELECTRON_VERSION}-${PLATFORM}-${ARCH}-dsym.tar.xz"
  else
    ASSET="electron-v${ELECTRON_VERSION}-${PLATFORM}-${ARCH}-symbols.zip"
  fi
  URL="https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/${ASSET}"
  echo "Asset: $ASSET (no manifest; platform $PLATFORM from this host)"
fi

# --- The asset name and URL are untrusted input ------------------------------
#
# Both branches above produce $ASSET, which becomes a FILESYSTEM PATH two lines
# down (`$CACHE/$ASSET`, written by curl and then by mv), and $URL, which is
# fetched. Neither value is this script's own: the manifest branch reads them out
# of a JSON file that arrived as a CI artifact download, and the no-manifest
# branch interpolates --electron and --arch straight from argv. A name of
# `../../../../etc/something` puts the download outside the cache and lets a
# chosen URL's bytes land on a writable host file; the extraction step then
# unpacks an attacker-chosen archive from there.
#
# So both are checked against what the honest emitter can produce, and the check
# is EXACT rather than sanitizing. A repaired path is still a manifest that lied,
# and there is no legitimate caller whose value needs repairing:
# scripts/emit-symbols-manifest.mjs derives every `name` and `url` from
# (platform, arch, version) by one formula, so exact matching loses nothing.
case "$ELECTRON_VERSION" in
  # Electron's own release versions, and nothing that could reshape the URL.
  *[!0-9A-Za-z.+-]*|"")
    echo "ERROR: implausible Electron version '$ELECTRON_VERSION'." >&2
    echo "       Expected a release version like 43.2.0. This came from the" >&2
    echo "       crash report, the manifest, or --electron; whichever it was is" >&2
    echo "       not describing a real Electron release." >&2
    exit 1 ;;
esac

ASSET_OK=0
case "$ASSET" in
  # A path separator, in a value that is about to be one path COMPONENT.
  */*|*'\'*) ;;
  electron-v*-symbols.zip) ASSET_OK=1 ;;
  electron-v*-dsym.tar.xz) ASSET_OK=1 ;;
esac
if [ "$ASSET_OK" -ne 1 ]; then
  echo "ERROR: refusing asset name '$ASSET'." >&2
  echo "       A symbol asset is a BARE FILENAME of the form" >&2
  echo "       electron-v<version>-<platform>-<arch>-symbols.zip (or -dsym.tar.xz)." >&2
  echo "       This is not one, so either it carries a path separator — which would" >&2
  echo "       place the download outside $CACHE — or it names an archive shape" >&2
  echo "       this script cannot extract. Either way it is rejected rather than" >&2
  echo "       trimmed into something plausible." >&2
  if [ -n "$MANIFEST" ]; then
    echo "       Source: $MANIFEST — that manifest is not one this build wrote." >&2
  fi
  exit 1
fi

EXPECT_URL="https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/${ASSET}"
if [ "$URL" != "$EXPECT_URL" ]; then
  echo "ERROR: refusing download URL for $ASSET." >&2
  echo "       expected: $EXPECT_URL" >&2
  echo "       manifest: $URL" >&2
  echo "       Symbols come from electron/electron's own releases and nowhere" >&2
  echo "       else. A manifest pointing elsewhere is either stale or forged;" >&2
  echo "       either way these are not the symbols for this build." >&2
  exit 1
fi

# --- Fetch, once ------------------------------------------------------------
mkdir -p "$CACHE"
DOWNLOAD="$CACHE/$ASSET"
EXTRACTED="$CACHE/${ASSET%.tar.xz}"
EXTRACTED="${EXTRACTED%.zip}"

if [ -d "$EXTRACTED" ]; then
  echo "Symbols: $EXTRACTED (cached)"
else
  if [ ! -f "$DOWNLOAD" ]; then
    # Announce the size FIRST. A dSYM is well over a gigabyte, and a tool should
    # say that before it starts rather than after.
    if command -v gh >/dev/null 2>&1; then
      SIZE="$(gh api "repos/electron/electron/releases/tags/v${ELECTRON_VERSION}" \
        --jq ".assets[] | select(.name == \"${ASSET}\") | .size" 2>/dev/null || true)"
    else
      SIZE=""
    fi
    if [ -n "${SIZE:-}" ]; then
      echo "Downloading $ASSET ($(( SIZE / 1024 / 1024 )) MB)…"
    else
      echo "Downloading $ASSET…"
    fi
    # Write to a temp name and move on success only: a truncated archive would
    # extract to MISSING symbols rather than to an error.
    curl -fL --progress-bar -o "$DOWNLOAD.part" "$URL"
    mv "$DOWNLOAD.part" "$DOWNLOAD"
  fi
  echo "Extracting into $EXTRACTED…"
  mkdir -p "$EXTRACTED"
  case "$ASSET" in
    *.tar.xz) tar -xJf "$DOWNLOAD" -C "$EXTRACTED" ;;
    *.zip)    unzip -q "$DOWNLOAD" -d "$EXTRACTED" ;;
  esac
fi

# --- Crashpad minidump ------------------------------------------------------
if [ "$KIND" = "dmp" ]; then
  # No UUID cross-check needed on this path: the Breakpad tree is keyed BY debug
  # ID, so a mismatched download yields "no symbols" rather than wrong ones.
  if command -v minidump_stackwalk >/dev/null 2>&1; then
    STACKWALK="minidump_stackwalk"
  elif command -v minidump-stackwalk >/dev/null 2>&1; then
    STACKWALK="minidump-stackwalk"
  else
    echo "ERROR: no minidump stackwalker found. Install one with:" >&2
    echo "       brew install rust-minidump      # provides minidump-stackwalk" >&2
    echo "       (then re-run; the symbols stay cached in $CACHE)" >&2
    exit 1
  fi
  echo
  exec "$STACKWALK" "$ARTIFACT" "$EXTRACTED"
fi

# --- macOS .ips report ------------------------------------------------------
if ! command -v atos >/dev/null 2>&1; then
  echo "ERROR: atos not found (it ships with the Xcode command line tools):" >&2
  echo "       xcode-select --install" >&2
  exit 1
fi

DWARF="$(find "$EXTRACTED" -type f \
  -path "*Electron Framework.dSYM/Contents/Resources/DWARF/*" -print -quit)"
if [ -z "$DWARF" ]; then
  echo "ERROR: no Electron Framework DWARF binary under $EXTRACTED" >&2
  echo "       The archive layout may have changed; list it and look for the .dSYM:" >&2
  echo "       find '$EXTRACTED' -maxdepth 3 -name '*.dSYM'" >&2
  exit 1
fi
echo "DWARF: $DWARF"

# The check that makes a wrong dSYM loud. Without it, symbolizing against a
# neighbouring Electron release succeeds and prints a stack that looks right and
# is not — the exact failure mode this whole script exists to end. Skipped only
# when the report carried no uuid (a hand-edited or truncated report).
if [ -n "$REPORT_UUID" ] && command -v dwarfdump >/dev/null 2>&1; then
  DSYM_UUIDS="$(dwarfdump --uuid "$DWARF" 2>/dev/null || true)"
  # Compared case-insensitively without dashes: the .ips spells it lowercase
  # with dashes, dwarfdump uppercase with dashes.
  NORM_REPORT="$(printf '%s' "$REPORT_UUID" | tr -d '-' | tr '[:upper:]' '[:lower:]')"
  NORM_DSYM="$(printf '%s' "$DSYM_UUIDS" | tr -d '-' | tr '[:upper:]' '[:lower:]')"
  case "$NORM_DSYM" in
    *"$NORM_REPORT"*) echo "UUID: matches the report's framework image ✓" ;;
    *)
      echo "ERROR: dSYM UUID does not match the crash report's framework image." >&2
      echo "       report: $REPORT_UUID" >&2
      echo "       dSYM:   $DSYM_UUIDS" >&2
      echo "       Symbolizing anyway would print plausible, WRONG frames. If the" >&2
      echo "       report came from a different slice, pass --arch; if from a" >&2
      echo "       different build, pass --electron <that version>." >&2
      exit 1 ;;
  esac
fi
echo

# Frames from images we hold no symbols for are printed as-is rather than
# dropped: knowing a frame was in the app's own binary, or in a system library,
# is itself part of reading the report. Only the Electron Framework group goes to
# atos, which takes exactly one -l load address per run.
node -e '
const fs = require("fs");
const [reportPath, argsPath] = process.argv.slice(1);
// A .ips is JSON-lines: a small header object on line 1, the payload after it.
const text = fs.readFileSync(reportPath, "utf8").split("\n");
const payload = JSON.parse(text.slice(1).join("\n"));
const images = payload.usedImages || [];

const groups = new Map();
for (const [tIndex, thread] of (payload.threads || []).entries()) {
  for (const [fIndex, frame] of (thread.frames || []).entries()) {
    const image = images[frame.imageIndex];
    if (!image) continue;
    if (!groups.has(frame.imageIndex)) groups.set(frame.imageIndex, { image, frames: [] });
    // The report stores an offset INTO the image, so every address has to be
    // rebased onto that image load address before it means anything.
    groups.get(frame.imageIndex).frames.push({
      slot: `${tIndex}.${fIndex}`,
      address: "0x" + (BigInt(image.base) + BigInt(frame.imageOffset)).toString(16),
    });
  }
}

console.log(`Faulting thread: ${payload.faultingThread}`);
if (payload.exception) console.log(`Exception: ${JSON.stringify(payload.exception)}`);
console.log("");

let electron = null;
for (const [index, group] of groups) {
  const name = group.image.name || "(anonymous)";
  console.log(`# image ${index}: ${name}  base=${group.image.base}`);
  if (group.image.path) console.log(`#   ${group.image.path}`);
  console.log(`#   thread.frame ${group.frames.map(f => f.slot).join(" ")}`);
  console.log(group.frames.map(f => f.address).join(" "));
  console.log("");
  if (/Electron Framework/.test(`${name} ${group.image.path || ""}`)) electron = group;
}

// Two lines, or an empty file when this report has no framework frames at all.
// The caller tests emptiness rather than parsing a sentinel string.
//
// The load address goes out as HEX. A .ips stores `base` as a decimal JSON
// number, and `atos -l` parses its argument as hex unconditionally — so passing
// the decimal digits through silently slides every address out of range and atos
// echoes the inputs back unresolved instead of erroring. That looks exactly like
// "the symbols do not cover these frames", which is the wrong conclusion to
// hand someone reading a crash.
fs.writeFileSync(
  argsPath,
  electron
    ? `0x${BigInt(electron.image.base).toString(16)}\n`
      + `${electron.frames.map(f => f.address).join(" ")}\n`
    : "",
);
' "$ARTIFACT" "$WORK/atos-args"

echo "--- atos (Electron Framework frames) ---"
if [ -s "$WORK/atos-args" ]; then
  { read -r LOAD; read -r ADDRESSES; } < "$WORK/atos-args"
  # shellcheck disable=SC2086  # ADDRESSES is a deliberate list of arguments.
  atos -o "$DWARF" \
    -arch "$([ "$ARCH" = "x64" ] && echo x86_64 || echo arm64)" \
    -l "$LOAD" $ADDRESSES
else
  echo "(no Electron Framework frames in this report)"
fi

echo
echo "Frames from other images are listed above with their rebased addresses."
echo "Symbolize those against their own binaries — the app's own slice lives in"
echo "the .app bundle the report names, and its symbols are NOT in this dSYM."
