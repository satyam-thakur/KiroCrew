"""Each crew's own webview: a dashboard the crew itself decides the contents of.

A crew that runs long — a conductor holding a fleet of workers, a research loop,
anything that works unattended — accumulates state that answers the only
questions an operator actually has: how many workers am I holding, which one is
stuck, what is my next step, is anything waiting on a decision. Its drawer today
shows activity counts, a path list, wake sources and config, none of which
answer those. This module is the store behind a webview in that drawer which
does.

One webview per crew, and the crew fills it
-------------------------------------------
The view is free-form HTML and it is configurable: each crew gets a TEMPLATE,
authored once, and at runtime the crew publishes only the DATA that fills it.
A crew whose name matches an installed template gets that template; a crew with
no template of its own falls back to a generic one that renders any data object.

The split that makes free-form HTML safe
----------------------------------------
Only the data comes from the crew.

The template is HTML a human wrote and reviewed — versioned in the repository,
or dropped on disk by the operator — free to lay out whatever it likes. The
crew never writes it: the template directory is fenced from agent file tools
(see ``security._CREW_SECRET_LEAVES``), so the only way a crew influences its
webview is by publishing a data object through the MCP tool.

That matters because a conductor reads issue bodies, pull-request descriptions
and review comments on a loop with nobody at the keyboard, so a path exists from
a hostile issue body to whatever renders this. Keeping layout out of the crew's
hands means the untrusted half is *data*, and data can be escaped at a single
boundary -- :func:`compose` below -- rather than trusted to be well-formed
markup. The sandboxed frame the drawer renders into stays as defence in depth,
not as the only defence.

Where a panel lives
-------------------
Inside the crew's own member space (``member_dir(slug)/panel.json``), beside the
DM binding and activity log that are already keyed that way. A panel therefore
belongs to the crew rather than to any one of its sessions, and whatever reaps a
member space reaps the panel with it.

Deliberately generic
--------------------
Nothing here knows what a "worker" or a "pull request" is. The store holds an
opaque JSON object and the id of a template to render it with; the conductor is
the first consumer, not the schema.
"""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from kiro_crew.atomic_write import atomic_write
from kiro_crew.config.paths import data_home
from kiro_crew.platform_compat import release_lock, try_acquire_lock
from kiro_crew.security import redact_credentials, redact_exfiltration_urls

SCHEMA_VERSION = 1

#: Operator-authored template overrides. A DIRECTORY OF ITS OWN, outside every
#: crew's member space, for two reasons: a template is reusable across crews, and
#: it is the one part of a panel that must never be agent-writable -- so it is
#: the thing behind the fence, while the published data (which the crew owns
#: anyway) is not.
TEMPLATES_DIRNAME = "panel-templates"

_LOCK_SUFFIX = ".lock"

#: A template id names a file, so it is validated rather than sanitised: a
#: lenient fold would let ``..%2f`` shaped input pick a path outside the
#: template roots. Lowercase, digit, single dashes, no dots -- nothing that can
#: traverse or hide an extension.
TEMPLATE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

DEFAULT_TEMPLATE_ID = "default"

#: The marker a template must carry, replaced by the data island in
#: :func:`compose`. A template without it renders a crew's data nowhere, which is
#: a template bug worth failing loudly on rather than showing a blank webview the
#: operator cannot explain.
DATA_MARKER = "<!--kirocrew:panel-data-->"

_DATA_ELEMENT_ID = "kirocrew-panel-data"

_MAX_TITLE = 200
#: Data, not layout. A panel carries a few dozen rows of state, so this is two
#: orders of magnitude under the 4 MiB the sandbox document channel accepts --
#: the cap exists to keep one wedged crew from filling the data home, not to
#: leave room for markup.
_MAX_DATA_BYTES = 64 * 1024
#: Bounds the recursion in :func:`_check_depth` and, with the byte cap, bounds
#: the work any renderer has to do. Eight is deeper than a stat row, a table of
#: rows, or a list of nested groups needs.
_MAX_DATA_DEPTH = 8
_MAX_RECORD_BYTES = 128 * 1024

_LOCK_TIMEOUT_SECS = 5.0
_LOCK_POLL_SECS = 0.05


class PanelError(ValueError):
    """A publish was refused. ``code`` is the machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------


def shipped_templates_dir() -> Path:
    """The in-repository template directory that ships with the package."""
    return Path(__file__).resolve().parent / "agent_panel_templates"


def override_templates_dir() -> Path:
    """Where an operator drops a template that wins over the shipped one.

    Resolved against the live data home on every call, never captured at import:
    a pod and a test both move the data home after this module is imported, and a
    captured root would read the operator's real home from inside a test.
    """
    return data_home() / TEMPLATES_DIRNAME


#: Mirrors ``members.MEMBERS_DIR_NAME`` and ``members._SLUG_RE`` rather than
#: importing them, and a test pins the two pairs equal so they cannot drift.
#:
#: Mirrored because ``members`` reaches ``artifacts -> hooks -> webhooks ->
#: validation``, which imports ``artifacts`` back. That cycle is LATENT while
#: something else has already imported the chain -- true under the test suite and
#: true during a gateway boot -- and raises ``ImportError`` the moment this store
#: is what triggers the chain, which is any script or tool that reaches a crew's
#: panel first. Deferring the import to call time only moved the failure from
#: import to first use; not importing it is what actually fixes it.
_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\Z")

#: Where the records live: ``<data home>/trust/crew-panels/<slug>.json``.
#:
#: ``trust/`` is already fenced from agent file tools as a whole directory in
#: ``security._CREW_SECRET_LEAVES``, which is what makes the record unforgeable
#: by a crew other than its owner. Spelled as a literal here for the same reason
#: the slug pattern is: ``members`` cannot be imported at this module's scope
#: (see above), and ``members.DM_BINDINGS_DIR_NAME`` sits beside this one under
#: the same root. An anti-drift test pins the trust name against ``members``.
_TRUST_DIRNAME = "trust"
_PANELS_DIRNAME = "crew-panels"
_PANEL_SUFFIX = ".json"


class CrewSlugError(ValueError):
    """Raised when a crew slug is unusable as a directory name."""


def panel_dir() -> Path:
    """The gateway-only directory holding published panel records.

    NOT the crew's own member space, and that is the whole point. The record
    carries an OWNERSHIP claim (``crew``) that ``publish`` reads back to refuse a
    colliding write, and it is the redacted copy of untrusted text. Under
    ``members/<slug>/`` neither property survived contact with a second crew:
    ``members/`` is deliberately unfenced because a crew owns its own published
    data, so nothing stopped one crew writing ``members/<other-crew>/panel.json``
    directly -- forging another crew's state past ownership resolution AND past
    the redactors in one write, and the drawer would render it.

    So it lives under the keystone-gated ``trust/`` subtree, exactly where
    ``members.dm_binding_path`` puts the DM binding and for the same stated
    reason: a record that is an identity authority must not sit on a path the
    agent's file tools can write. One flat ``<slug>.json`` per crew, which is why
    this takes no slug -- every crew's record shares this directory.

    REAPING: nothing in the tree currently deletes a member space, so moving the
    record out of ``members/<slug>/`` takes nothing away today -- and it leaves the
    record in exactly the position ``dm_binding_path``'s output is already in.
    Whoever adds that reaper has to clear BOTH trust-rooted files, so it is stated
    here rather than left to be rediscovered.
    """
    return (data_home() / _TRUST_DIRNAME / _PANELS_DIRNAME).resolve()


def panel_path(slug: str) -> Path:
    """Absolute path to one crew's published panel record, containment-checked.

    The slug is validated and then the resolved path is containment-checked --
    both steps, because validation and use are separated by a call boundary a
    future caller could bypass, and because a symlinked component must not land
    the record outside its trust-rooted directory. Mirrors
    ``members.dm_binding_path``.

    Does NOT create the directory; :func:`publish` does, on demand.
    """
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise CrewSlugError(f"invalid crew slug {slug!r}: must match {_SLUG_RE.pattern}")
    root = panel_dir()
    target = (root / f"{slug}{_PANEL_SUFFIX}").resolve()
    if target.parent != root and root not in target.parents:
        raise CrewSlugError(f"crew slug {slug!r} escapes {root}")
    return target


# --------------------------------------------------------------------------
# templates
# --------------------------------------------------------------------------


def available_templates() -> list[str]:
    """Template ids that resolve, operator overrides included, sorted.

    Best-effort: an unreadable directory yields what the other one has rather
    than failing a read of somebody's webview.
    """
    found: set[str] = set()
    for root in (shipped_templates_dir(), override_templates_dir()):
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.suffix != ".html" or not entry.is_file():
                continue
            if TEMPLATE_ID_RE.match(entry.stem):
                found.add(entry.stem)
    return sorted(found)


def template_for_crew(name: str) -> str:
    """The template id a crew called *name* gets by default.

    A crew whose own name matches an installed template gets that template --
    which is how a bespoke view reaches its crew with no registry, no mapping
    table and no per-crew config: installing ``<crew-name>.html`` is the whole
    act of wiring it up. Everything else falls back to the generic template.
    """
    candidate = (name or "").strip().lower()
    if TEMPLATE_ID_RE.match(candidate) and candidate in available_templates():
        return candidate
    return DEFAULT_TEMPLATE_ID


def resolve_template(template_id: str) -> str:
    """Return the HTML for *template_id*.

    Operator override first, then the shipped template. A template the operator
    dropped on disk is authored by the person who owns the machine, so it
    deliberately wins -- that is the customisation seam.

    Raises :class:`PanelError` for an id that does not validate or does not
    exist, so a typo in a publish call is reported rather than rendering the
    fallback and looking like the template is broken.
    """
    if not TEMPLATE_ID_RE.match(template_id or ""):
        raise PanelError("bad_template_id", f"invalid template id: {template_id!r}")
    for root in (override_templates_dir(), shipped_templates_dir()):
        candidate = root / f"{template_id}.html"
        try:
            # The id is already pinned to a traversal-free pattern; this second
            # check catches a symlink inside the override directory pointing
            # somewhere else entirely.
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root.resolve()):
                continue
            return resolved.read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
    raise PanelError("unknown_template", f"no such template: {template_id!r}")


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------


def _check_depth(value: Any, limit: int) -> None:
    if limit <= 0:
        raise PanelError("data_too_deep", f"data nests deeper than {_MAX_DATA_DEPTH} levels")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, limit - 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, limit - 1)


def _validate_data(data: Any) -> str:
    """Return the canonical JSON for *data*, or raise :class:`PanelError`.

    A panel's data must be a JSON object: a bare scalar or list gives a template
    no names to bind to, and every template in the tree reads named fields.
    """
    if not isinstance(data, dict):
        raise PanelError("data_not_object", "panel data must be a JSON object")
    _check_depth(data, _MAX_DATA_DEPTH)
    try:
        # allow_nan=False: NaN and Infinity are not JSON, and JSON.parse in the
        # frame would throw on them -- refuse at publish rather than render a
        # panel that dies in the browser.
        #
        # NOT sort_keys: field order is presentation. A crew that publishes
        # cycle, then holding, then credits means that order -- templates render
        # a stat strip in key order, so sorting would silently alphabetise
        # somebody's dashboard and give them no way to control it. Insertion
        # order is already deterministic for a given input, which is all the
        # byte-cap measurement below needs.
        blob = json.dumps(data, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PanelError("data_not_serializable", f"panel data is not JSON: {exc}") from exc
    if len(blob.encode("utf-8")) > _MAX_DATA_BYTES:
        raise PanelError("data_too_large", f"panel data exceeds {_MAX_DATA_BYTES} bytes")
    return blob


def _clamp(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


# --------------------------------------------------------------------------
# the escaping boundary
# --------------------------------------------------------------------------

#: Escaped inside the JSON string literals so the serialized data cannot end the
#: script element that carries it, cannot open a tag, and cannot terminate a
#: JavaScript string across a line break. ``</script>`` is the one that matters:
#: without the ``<`` rewrite, data holding that literal closes the island early
#: and everything after it parses as markup.
_JSON_HTML_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def escape_json_for_html(blob: str) -> str:
    """Make a JSON document safe to embed in an HTML script element.

    The output is still valid JSON -- the replacements are JSON's own ``\\u``
    escapes inside string literals, so ``JSON.parse`` returns exactly the
    original values. Only the HTML parser's view changes.
    """
    for raw, escaped in _JSON_HTML_ESCAPES.items():
        blob = blob.replace(raw, escaped)
    return blob


def compose(template_html: str, data_json: str) -> str:
    """Substitute *data_json* into *template_html* at :data:`DATA_MARKER`.

    The data lands as an inert ``application/json`` island rather than being
    interpolated into markup or into executable JavaScript. A template reads it
    with ``JSON.parse`` and renders through DOM text APIs, which is what keeps a
    crew's string from becoming an element.

    Raises :class:`PanelError` when the template carries no marker: rendering
    the template anyway would silently drop every value the crew published.
    """
    if DATA_MARKER not in template_html:
        raise PanelError(
            "template_missing_marker",
            f"template does not contain the {DATA_MARKER} marker",
        )
    island = (
        f'<script type="application/json" id="{_DATA_ELEMENT_ID}">'
        f"{escape_json_for_html(data_json)}</script>"
    )
    # Only the first marker is filled; a template with two would otherwise
    # define the same element id twice and getElementById would pick one
    # arbitrarily.
    return template_html.replace(DATA_MARKER, island, 1)


# --------------------------------------------------------------------------
# read and write
# --------------------------------------------------------------------------


@contextmanager
def _locked(lock_path: Path) -> Iterator[None]:
    """Bounded exclusive lock over one crew's panel, failing closed.

    The lock lives on its own inode so a state write never replaces the file
    another process is holding. Bounded because a publish runs inside a crew's
    turn: waiting forever on a stuck holder would wedge the turn, so after the
    deadline the caller is told to try again on its next cycle.

    Scoped to the SLUG rather than to the records directory: the collision this
    serialises is two crews reaching one slug, so a per-slug lock is exactly as
    correct as a directory-wide one and does not make every crew's publish wait
    behind every other crew's.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECS
        while not try_acquire_lock(fd, exclusive=True):
            if time.monotonic() >= deadline:
                raise OSError("panel lock is held by another process; try again")
            time.sleep(_LOCK_POLL_SECS)
        try:
            yield
        finally:
            release_lock(fd)
    finally:
        os.close(fd)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


class _RAW:
    """A pre-serialized JSON fragment, spliced in by :class:`_RawEncoder`.

    Exists so the stored record can be dumped as a whole while its ``data``
    member keeps the key order the crew published.
    """

    __slots__ = ("json",)

    def __init__(self, json_text: str) -> None:
        self.json = json_text


class _RawEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:  # pragma: no cover - exercised via publish
        if isinstance(o, _RAW):
            # ``json.JSONEncoder`` has no verbatim hook, so the fragment is
            # parsed back rather than string-spliced: splicing would let a
            # malformed fragment corrupt the whole document, and this fragment
            # was produced by json.dumps one step earlier so the round trip is
            # order-preserving and cheap.
            return json.loads(o.json, object_pairs_hook=dict)
        return super().default(o)


def _scrub(text: str) -> str:
    """Apply the shared credential + exfiltration-URL chain to one string.

    Same pair, in the same order, as every other capture-side scrubber in the
    repo (see ``acp/mcp_session_report._clean``): URLs first, then credentials.
    """
    scrubbed, _ = redact_exfiltration_urls(text)
    scrubbed, _ = redact_credentials(scrubbed)
    return scrubbed


def _scrub_published(value: Any) -> Any:
    """Recursively scrub every string a crew published -- KEYS included.

    A panel's data is assembled unattended from issue bodies, review comments and
    command output, so it is untrusted text on a path that ends at the operator's
    dashboard. Redacting at PUBLISH rather than at render is deliberate: it means
    a credential never enters ``panel.json`` at all, so it cannot be read back by
    a later reader, cannot survive in halves across the record's byte ceiling, and
    is not sitting on disk waiting for the next code path that forgets to scrub.

    Keys are scrubbed as well as values because a key is rendered as a heading --
    the template labels every field it shows, so a crew that put a token in a
    field NAME would print it just as surely as one that put it in the value.
    Non-string scalars are returned unchanged: there is nothing in a number or a
    boolean for either redactor to find.
    """
    if isinstance(value, str):
        return _scrub(value)
    if isinstance(value, dict):
        return {_scrub(str(k)): _scrub_published(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_published(v) for v in value]
    return value


def publish(
    slug: str,
    *,
    template: str,
    data: Any,
    title: str = "",
    crew: str = "",
) -> dict[str, Any]:
    """Replace the crew's panel with a new one. Returns the stored record.

    Whole-document replacement rather than a merge: a panel describes the state
    of one cycle, and a partial update would leave last cycle's rows sitting
    beside this cycle's counters with nothing marking which is which.

    The template is resolved and the document composed here, at publish time, so
    a bad template id or a template missing its marker is reported to the crew
    that made the call -- while it can still fix the call -- instead of surfacing
    later as a broken webview with no author present.

    OWNERSHIP IS THE EXACT CREW NAME, not the slug, and it takes TWO things to
    hold -- they are one story, not two half-guards:

    1. The record lives under the gateway-only ``trust/`` root (see
       :func:`panel_dir`), so ``publish`` is the ONLY way a panel is written. In
       the crew's own unfenced member space a colliding crew could skip this
       function entirely and write the file, and any check here would be theatre.
    2. Inside the lock, a stored ``crew`` that differs from the caller's is
       refused. Slugification is lossy -- ``Oncall`` and ``oncall`` reach one slug
       -- so without this either would overwrite the other and the operator would
       read one crew's state under the other's name.

    Following the member layer's existing answer to the same lossiness rather than
    inventing a second convention: ``members.slug_for_name`` documents that it is
    not unique, and ``record_activity`` matches on BOTH the session and the exact
    ``member`` name for exactly this reason.
    """
    if not TEMPLATE_ID_RE.match(template or ""):
        raise PanelError("bad_template_id", f"invalid template id: {template!r}")
    data_json = _validate_data(_scrub_published(data))
    template_html = resolve_template(template)
    # Composed eagerly and thrown away: this is the validation that the pair
    # actually renders. The reader composes again from the stored parts so an
    # edited template takes effect without the crew republishing.
    compose(template_html, data_json)

    crew_name = _clamp(_scrub(crew), _MAX_TITLE)

    record = {
        "schema": SCHEMA_VERSION,
        "template": template,
        "title": _clamp(_scrub(title), _MAX_TITLE),
        "crew": crew_name,
        "data": None,
        "published_at": _now_iso(),
    }
    blob = json.dumps({**record, "data": _RAW(data_json)}, ensure_ascii=False, cls=_RawEncoder)
    if len(blob.encode("utf-8")) > _MAX_RECORD_BYTES:
        raise PanelError("record_too_large", "panel record exceeds its byte ceiling")

    target = panel_path(slug)
    target.parent.mkdir(parents=True, exist_ok=True)
    with _locked(target.with_suffix(_LOCK_SUFFIX)):
        # OWNERSHIP IS CHECKED INSIDE THE LOCK, with the write, because the two
        # are one decision. Read before acquiring it and the check is a TOCTOU
        # race: two crews colliding on one slug both observe "no owner", both
        # pass, and the later write silently overwrites the first -- which is the
        # exact outcome the check exists to prevent, so a check outside the lock
        # is not a weaker guard but no guard at all.
        existing = read(slug)
        if existing is not None:
            owner = str(existing.get("crew") or "")
            # Empty either side is not a mismatch: a record written before
            # ownership was recorded, or a caller that named no crew, has nothing
            # to compare.
            if owner and crew_name and owner != crew_name:
                raise PanelError(
                    "crew_slug_collision",
                    f"panel {slug!r} belongs to crew {owner!r}, not {crew_name!r}; "
                    "rename one of the crews so their names do not collide",
                )
        atomic_write(target, blob + "\n", mode=0o600)
    record["data"] = json.loads(data_json)
    return record


def read(slug: str) -> dict[str, Any] | None:
    """Return the crew's stored record, or ``None`` if it has no panel.

    Best-effort by design: a missing, unreadable, oversized or malformed file
    reads as "no panel published". A reader is rendering somebody's drawer, and
    an unparseable record on disk must show an empty state rather than breaking
    the page.
    """
    try:
        path = panel_path(slug)
        if path.stat().st_size > _MAX_RECORD_BYTES:
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    # ``MemberSlugError`` is a ``ValueError``, so a bad slug is caught here too.
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("data"), dict):
        return None
    if not TEMPLATE_ID_RE.match(str(raw.get("template", ""))):
        return None
    return raw


def render(slug: str) -> str | None:
    """Compose the crew's stored panel into a document, or ``None``.

    Composition happens on read, not once at publish, so an operator editing a
    template sees the change on the next drawer open without waiting for the
    crew to publish another cycle.
    """
    record = read(slug)
    if record is None:
        return None
    try:
        template_html = resolve_template(str(record["template"]))
        data_json = json.dumps(record["data"], ensure_ascii=False, allow_nan=False)
        return compose(template_html, data_json)
    except (PanelError, TypeError, ValueError):
        # A template that was valid at publish and has since been deleted or
        # broken by an edit: show the empty state, not a stack trace.
        return None
