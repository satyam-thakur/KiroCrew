"""Tests for the crew webview store.

The load-bearing ones are the escaping tests: a conductor ingests issue bodies
and review comments unattended, so a published string is untrusted input that
reaches a rendered document. Everything else here is caps, identity and order.
"""

from __future__ import annotations

import json
import os
from fnmatch import fnmatch
from pathlib import Path

import pytest

from kiro_crew import agent_panel

CREW = "fleet-crew"

#: A crew whose name matches a template the OPERATOR installed. The name-match
#: rule is a property of the store, so it is proven against a template this test
#: drops on disk rather than against any shipped consumer's artifact -- which
#: also exercises the override directory, the seam a shipped template bypasses.
BESPOKE = "bespoke-crew"

#: Shaped like a real bespoke template -- markup around the island and a script
#: that renders the published values -- so the element-count and escaping
#: assertions have structure to count. Every value reaches the DOM as text.
_BESPOKE_HTML = f"""\
<div class="panel"><h2 id="t"></h2><ul id="rows"></ul></div>
<style>.panel {{ color: var(--kc-fg); }}</style>
{agent_panel.DATA_MARKER}
<script>
  var node = document.getElementById('{agent_panel._DATA_ELEMENT_ID}');
  var d = {{}};
  try {{ d = JSON.parse(node.textContent || '{{}}'); }} catch (e) {{ d = {{}}; }}
  document.getElementById('t').textContent = String(d.title || '');
  var rows = document.getElementById('rows');
  (d.workers || []).forEach(function (w) {{
    var li = document.createElement('li');
    li.textContent = String(w.scope) + ' ' + String(w.note);
    rows.appendChild(li);
  }});
</script>
"""


def _install_template(template_id: str, body: str) -> Path:
    """Install *body* as a template an operator dropped on disk.

    Idempotent, so a parametrized case may call it for a template it does not
    use. The data home is per-test, so nothing here escapes the test.
    """
    over = agent_panel.override_templates_dir()
    over.mkdir(parents=True, exist_ok=True)
    path = over / f"{template_id}.html"
    path.write_text(body, encoding="utf-8")
    return path


def _shipped_template_ids() -> list[str]:
    """Every template the package ships, read from the directory itself.

    Derived rather than listed so the rules below (marker, no markup from data,
    body fragment) apply to a template added later without anyone remembering to
    extend a literal. ``shipped_templates_dir()`` is package-relative, so this is
    stable at collection time.
    """
    return sorted(p.stem for p in agent_panel.shipped_templates_dir().glob("*.html"))


SHIPPED = _shipped_template_ids()


def _publish(**over):
    kwargs = {
        "template": "default",
        "data": {"cycle": 47, "holding": 5},
        "title": "fleet",
        "crew": CREW,
    }
    kwargs.update(over)
    return agent_panel.publish(CREW, **kwargs)


# ---------------------------------------------------------------- round trip


def test_publish_then_read_roundtrips():
    written = _publish()
    assert written["schema"] == agent_panel.SCHEMA_VERSION
    got = agent_panel.read(CREW)
    assert got is not None
    assert got["template"] == "default"
    assert got["title"] == "fleet"
    assert got["crew"] == CREW
    assert got["data"] == {"cycle": 47, "holding": 5}
    assert got["published_at"]


def test_the_panel_lives_under_the_gateway_only_trust_root():
    """Not beside the crew's other state, and that is deliberate.

    The record is an ownership authority and a redacted copy of untrusted text, so
    it sits where agent file tools cannot reach it -- the same trust root
    ``members.dm_binding_path`` uses for the DM binding, and for the same reason.
    """
    _publish()
    path = agent_panel.panel_path(CREW)
    assert path.parent == agent_panel.panel_dir()
    assert path.is_file()


def test_read_is_none_for_a_crew_that_never_published():
    assert agent_panel.read("some-other-crew") is None


def test_two_crews_do_not_share_a_panel():
    _publish(data={"mine": 1})
    agent_panel.publish("research-lab", template="default", data={"theirs": 2})
    assert agent_panel.read(CREW)["data"] == {"mine": 1}
    assert agent_panel.read("research-lab")["data"] == {"theirs": 2}


def test_publish_replaces_rather_than_merges():
    _publish(data={"cycle": 1, "stale": "gone"})
    _publish(data={"cycle": 2})
    assert agent_panel.read(CREW)["data"] == {"cycle": 2}


@pytest.mark.parametrize("bad", ["", "a/b", "a\\b", "..", "has space", "Upper.Case"])
def test_a_path_hostile_crew_slug_is_refused(bad):
    with pytest.raises(agent_panel.CrewSlugError):
        agent_panel.panel_path(bad)


# ------------------------------------------------- which template a crew gets


def test_a_crew_named_after_a_template_gets_that_template():
    """How a bespoke view reaches its crew with no registry and no mapping.

    Installing ``<crew-name>.html`` is the entire act of wiring it up.
    """
    _install_template(BESPOKE, _BESPOKE_HTML)
    assert agent_panel.template_for_crew(BESPOKE) == BESPOKE


def test_a_crew_with_no_template_of_its_own_falls_back_to_the_generic_one():
    assert agent_panel.template_for_crew("research-lab") == agent_panel.DEFAULT_TEMPLATE_ID
    assert agent_panel.template_for_crew("") == agent_panel.DEFAULT_TEMPLATE_ID


def test_a_crew_name_that_could_traverse_never_selects_a_template():
    for hostile in ("../../etc/passwd", "..", "default.html"):
        assert agent_panel.template_for_crew(hostile) == agent_panel.DEFAULT_TEMPLATE_ID


# ------------------------------------------------- redaction before storage


#: Shapes both scanners actually recognise, verified against the redactors
#: themselves rather than guessed. ``SECRET`` is a credential literal;
#: ``EXFIL`` is an OAuth authorize URL carrying a state/code_challenge pair,
#: which is the shape ``redact_exfiltration_urls`` flags -- a plain
#: suspicious-looking host is NOT flagged, and a test built on one would have
#: passed vacuously while proving nothing.
SECRET = "AKIAIOSFODNN7EXAMPLE"
EXFIL = (
    "https://api.notion.com/v1/oauth/authorize?client_id=client123"
    "&response_type=code&state=s3cr3tstate0123456789abcdef0123456789"
    "&code_challenge=chal0123456789abcdef0123456789abcdef01234"
    "&code_challenge_method=S256"
)


def test_a_credential_in_published_data_never_reaches_the_record():
    """A panel is assembled unattended from issue bodies and command output.

    Redacted at PUBLISH, not at render, so the credential is not on disk at all:
    it cannot be read back by a later reader, cannot survive in halves across the
    record's byte ceiling, and is not waiting for the next reader that forgets.
    """
    _publish(data={"note": f"token {SECRET} leaked"})
    stored = agent_panel.read(CREW)
    assert stored is not None
    assert SECRET not in json.dumps(stored)


def test_an_exfiltration_url_in_published_data_never_reaches_the_record():
    _publish(data={"note": f"posting to {EXFIL}"})
    assert EXFIL not in json.dumps(agent_panel.read(CREW))


def test_the_title_is_redacted_too():
    _publish(title=f"cycle 47 {SECRET}")
    assert SECRET not in json.dumps(agent_panel.read(CREW))


def test_redaction_reaches_nested_values_and_keys():
    """A KEY is rendered as a heading, so a token in a field NAME would print
    just as surely as one in a value."""
    _publish(
        data={
            "rows": [{"detail": f"see {SECRET}"}],
            "nested": {"inner": {"deep": f"{EXFIL} here"}},
            f"key-{SECRET}": "value",
        }
    )
    blob = json.dumps(agent_panel.read(CREW))
    assert SECRET not in blob
    assert EXFIL not in blob


def test_redaction_does_not_disturb_ordinary_values():
    """The scrubber must not rewrite text that carries no secret, or every panel
    would read as though something had been withheld."""
    _publish(data={"cycle": 47, "phase": "await ci", "ok": True, "nil": None})
    assert agent_panel.read(CREW)["data"] == {
        "cycle": 47,
        "phase": "await ci",
        "ok": True,
        "nil": None,
    }


def test_the_rendered_document_carries_no_credential():
    """End to end: the composed document is what actually reaches the operator."""
    _publish(data={"note": f"token {SECRET}"})
    doc = agent_panel.render(CREW)
    assert doc is not None
    assert SECRET not in doc


# ------------------------------------------- ownership is the exact crew name


def test_a_colliding_crew_name_cannot_overwrite_another_crews_panel():
    """``Oncall`` and ``oncall`` slugify to ONE slug, so one panel.json.

    Without this check either crew would silently overwrite the other and the
    operator would read one crew's state under the other's name. Ownership is the
    exact name, following the member layer's existing answer to the same
    lossiness (``record_activity`` matches on session AND the exact member name).
    """
    agent_panel.publish(CREW, template="default", data={"mine": 1}, crew="Oncall")
    with pytest.raises(agent_panel.PanelError) as exc:
        agent_panel.publish(CREW, template="default", data={"theirs": 2}, crew="oncall")
    assert exc.value.code == "crew_slug_collision"
    # The first crew's panel is untouched, which is the property that matters.
    assert agent_panel.read(CREW)["data"] == {"mine": 1}


def test_the_owning_crew_can_still_republish():
    agent_panel.publish(CREW, template="default", data={"cycle": 1}, crew="Oncall")
    agent_panel.publish(CREW, template="default", data={"cycle": 2}, crew="Oncall")
    assert agent_panel.read(CREW)["data"] == {"cycle": 2}


def test_an_unowned_record_is_not_treated_as_a_collision():
    """A record written before ownership was recorded has nothing to compare."""
    agent_panel.publish(CREW, template="default", data={"cycle": 1}, crew="")
    agent_panel.publish(CREW, template="default", data={"cycle": 2}, crew="Oncall")
    assert agent_panel.read(CREW)["data"] == {"cycle": 2}


# ---------------------------------------------------------------- data caps


def test_data_must_be_an_object():
    for bad in ([1, 2], "text", 7, None):
        with pytest.raises(agent_panel.PanelError) as exc:
            _publish(data=bad)
        assert exc.value.code == "data_not_object"


def test_data_over_the_byte_cap_is_refused():
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(data={"k": "x" * (agent_panel._MAX_DATA_BYTES + 10)})
    assert exc.value.code == "data_too_large"


def test_deeply_nested_data_is_refused():
    node: dict = {}
    cursor = node
    for _ in range(agent_panel._MAX_DATA_DEPTH + 3):
        child: dict = {}
        cursor["n"] = child
        cursor = child
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(data=node)
    assert exc.value.code == "data_too_deep"


def test_non_serializable_data_is_refused():
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(data={"when": object()})
    assert exc.value.code == "data_not_serializable"


def test_nan_is_refused():
    # JSON.parse in the frame would throw on NaN, so it is refused at publish
    # rather than rendering a webview that dies in the browser.
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(data={"ratio": float("nan")})
    assert exc.value.code == "data_not_serializable"


def test_title_is_clamped():
    assert len(_publish(title="t" * 5000)["title"]) == agent_panel._MAX_TITLE


# ---------------------------------------------------------------- templates


@pytest.mark.parametrize(
    "hostile",
    ["../../../../etc/passwd", "..", "de fault", "Default", "default.html", "", "-lead"],
)
def test_a_hostile_template_id_is_refused(hostile):
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(template=hostile)
    assert exc.value.code == "bad_template_id"


def test_an_unknown_template_is_refused():
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(template="no-such-template")
    assert exc.value.code == "unknown_template"


@pytest.mark.parametrize("template_id", SHIPPED)
def test_every_shipped_template_resolves_and_carries_the_marker(template_id):
    assert agent_panel.DATA_MARKER in agent_panel.resolve_template(template_id)


def test_the_shipped_set_is_not_empty():
    """Guards the three rules parametrized over :data:`SHIPPED`.

    An empty glob would make each of them collect zero cases and report green
    while asserting nothing, so the set itself is pinned.
    """
    assert agent_panel.DEFAULT_TEMPLATE_ID in SHIPPED


def test_an_installed_template_joins_the_available_set():
    """What makes the name-match rule reachable: listing is directory-driven, so
    an operator adds a template by dropping a file in and nothing else."""
    assert BESPOKE not in agent_panel.available_templates()
    _install_template(BESPOKE, _BESPOKE_HTML)
    assert {agent_panel.DEFAULT_TEMPLATE_ID, BESPOKE} <= set(agent_panel.available_templates())


def test_an_operator_override_wins_over_the_shipped_template():
    over = agent_panel.override_templates_dir()
    over.mkdir(parents=True, exist_ok=True)
    (over / "default.html").write_text("MINE" + agent_panel.DATA_MARKER, encoding="utf-8")
    assert agent_panel.resolve_template("default").startswith("MINE")


def test_a_template_without_the_marker_is_refused():
    over = agent_panel.override_templates_dir()
    over.mkdir(parents=True, exist_ok=True)
    (over / "markerless.html").write_text("<p>no marker</p>", encoding="utf-8")
    with pytest.raises(agent_panel.PanelError) as exc:
        _publish(template="markerless")
    assert exc.value.code == "template_missing_marker"


def test_only_the_first_marker_is_filled():
    out = agent_panel.compose(agent_panel.DATA_MARKER + "|" + agent_panel.DATA_MARKER, "{}")
    assert out.count('id="kirocrew-panel-data"') == 1


# ------------------------------------------------------- the escaping boundary


HOSTILE = '</script><img src=x onerror="alert(1)"><script>'


def _island(doc: str) -> str:
    """The raw text inside the data island, as the HTML parser would see it.

    Slicing to the FIRST ``</script>`` is the point: if published data could
    close the element early, this returns truncated JSON and the parse below
    fails -- which is exactly the regression the test is guarding.
    """
    after = doc.split(f'id="{agent_panel._DATA_ELEMENT_ID}">', 1)[1]
    return after.split("</script>", 1)[0]


def test_published_data_cannot_close_the_script_island():
    """The one that matters: a hostile issue body reaching a rendered webview."""
    _publish(data={"note": HOSTILE})
    doc = agent_panel.render(CREW)
    assert doc is not None
    island = _island(doc)
    assert json.loads(island) == {"note": HOSTILE}, "the payload was truncated"
    for ch in ("<", ">", "&"):
        assert ch not in island
    assert "\\u003c" in island


@pytest.mark.parametrize("template_id", [agent_panel.DEFAULT_TEMPLATE_ID, BESPOKE])
def test_a_hostile_payload_injects_no_element(template_id):
    """Asserted by COUNTING elements, not by looking for attribute names.

    An escaped payload legitimately still contains the text ``onerror=`` inside a
    JSON string, which is harmless because there is no tag around it. What would
    be a real defect is the element count changing.

    Run against the generic template and against an operator-installed one: the
    guarantee comes from ``compose``, so it must not depend on which template
    happens to be in play.
    """
    _install_template(BESPOKE, _BESPOKE_HTML)
    baseline = agent_panel.compose(agent_panel.resolve_template(template_id), "{}")
    _publish(
        template=template_id,
        data={"title": HOSTILE, "workers": [{"scope": HOSTILE, "note": HOSTILE}]},
    )
    doc = agent_panel.render(CREW)
    assert doc is not None
    for tag in ("<script", "</script>", "<img", "<div", "<style", "<"):
        assert doc.count(tag) == baseline.count(tag), f"data changed the count of {tag!r}"


def test_escaping_preserves_the_value_exactly():
    data = {"note": HOSTILE, "unicode": "caf\u00e9 \u2028 \u2029", "n": 1.5}
    escaped = agent_panel.escape_json_for_html(json.dumps(data, ensure_ascii=False))
    assert json.loads(escaped) == data


@pytest.mark.parametrize("template_id", SHIPPED)
def test_no_shipped_template_builds_markup_from_data(template_id):
    """Every value must reach the DOM through ``textContent``.

    Asserted on the source because it is a rule about how a template is written,
    not about one payload. Parametrized over the shipped set rather than over a
    template this file wrote, which would only prove the fixture is clean.
    """
    html = agent_panel.resolve_template(template_id)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in html, f"{template_id} reaches the DOM through {sink}"


@pytest.mark.parametrize("template_id", SHIPPED)
def test_every_shipped_template_is_a_body_fragment(template_id):
    """A whole document would be mangled: the drawer parses this as a fragment
    and wraps it with the strict CSP and the theme variables."""
    html = agent_panel.resolve_template(template_id).lower()
    for tag in ("<html", "<head", "<body", "<!doctype"):
        assert tag not in html, f"{template_id} is a document, not a fragment"


# ------------------------------------------------------------- field order


ORDERED = ["cycle", "holding", "merged", "credits", "aardvark"]


def test_publish_preserves_the_published_field_order():
    """Field order is presentation, not an implementation detail.

    A template renders a stat strip in key order, so serializing with sorted keys
    silently alphabetises the operator's dashboard and leaves the crew no way to
    control it. Caught by looking at a real render: the tiles came out CREDITS,
    CYCLE, HOLDING, MERGED where the crew published cycle first. ``aardvark`` is
    last on purpose -- it sorts first, so a regression cannot pass by accident.
    """
    _publish(data={k: 1 for k in ORDERED})
    assert list(agent_panel.read(CREW)["data"].keys()) == ORDERED


def test_nested_field_order_is_preserved_too():
    _publish(data={"stats": {k: 1 for k in ORDERED}})
    assert list(agent_panel.read(CREW)["data"]["stats"].keys()) == ORDERED


def test_the_rendered_island_carries_the_published_order():
    _publish(data={k: 1 for k in ORDERED})
    doc = agent_panel.render(CREW)
    assert doc is not None
    island = _island(doc)
    positions = [island.index(f'"{k}"') for k in ORDERED]
    assert positions == sorted(positions), "the island reordered the fields"


# ---------------------------------------------------------------- robustness


def test_read_is_none_for_a_malformed_record():
    _publish()
    agent_panel.panel_path(CREW).write_text("{not json", encoding="utf-8")
    assert agent_panel.read(CREW) is None, "a broken record must show an empty state"


def test_read_is_none_when_the_record_lost_its_data_object():
    _publish()
    agent_panel.panel_path(CREW).write_text(
        json.dumps({"template": "default", "data": "nope"}), encoding="utf-8"
    )
    assert agent_panel.read(CREW) is None


def test_read_is_none_when_the_stored_template_id_is_hostile():
    _publish()
    agent_panel.panel_path(CREW).write_text(
        json.dumps({"template": "../../etc/passwd", "data": {}}), encoding="utf-8"
    )
    assert agent_panel.read(CREW) is None


def test_render_is_none_when_the_template_disappears():
    over = agent_panel.override_templates_dir()
    over.mkdir(parents=True, exist_ok=True)
    (over / "temporary.html").write_text(agent_panel.DATA_MARKER, encoding="utf-8")
    _publish(template="temporary")
    (over / "temporary.html").unlink()
    assert agent_panel.render(CREW) is None


def test_render_reflects_a_template_edited_after_publishing():
    """Composition happens on read so an operator editing a template sees it on
    the next drawer open instead of waiting for another crew cycle."""
    _publish()
    over = agent_panel.override_templates_dir()
    over.mkdir(parents=True, exist_ok=True)
    (over / "default.html").write_text("EDITED" + agent_panel.DATA_MARKER, encoding="utf-8")
    doc = agent_panel.render(CREW)
    assert doc is not None and doc.startswith("EDITED")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_record_is_written_owner_only():
    _publish()
    assert agent_panel.panel_path(CREW).stat().st_mode & 0o077 == 0


# ------------------------------------------------------------ what ships

REPO_ROOT = Path(__file__).resolve().parents[1]


def _declared_package_data() -> list[str]:
    """The ``kiro_crew`` globs from setup.cfg's ``[options.package_data]``."""
    import configparser

    cfg = configparser.ConfigParser()
    cfg.read(REPO_ROOT / "setup.cfg", encoding="utf-8")
    raw = cfg.get("options.package_data", "kiro_crew", fallback="")
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_every_shipped_template_is_covered_by_the_declared_package_data():
    """A shipped template that pip does not copy makes the feature 400 everywhere.

    ``resolve_template`` reads the package-relative directory, which EXISTS in a
    source checkout and in the test suite -- so the whole feature can be green
    locally while ``panel_publish`` returns ``unknown_template`` on every
    pip/PyPI/DMG install, because the templates were never copied into
    site-packages. Nothing else in the suite can see that: every other test reads
    the same source tree that hides it.

    Asserted per FILE against the declared globs rather than by looking for one
    known line, so adding ``pipeline-conductor.html`` without extending the
    declaration fails here instead of shipping a dead feature.
    """
    declared = _declared_package_data()
    shipped = sorted(agent_panel.shipped_templates_dir().glob("*.html"))
    assert shipped, "no shipped templates found -- this test would be vacuous"
    pkg = REPO_ROOT / "src" / "kiro_crew"
    for path in shipped:
        rel = path.relative_to(pkg).as_posix()
        assert any(fnmatch(rel, glob) for glob in declared), (
            f"{rel} ships in the repo but no [options.package_data] glob covers it, "
            "so pip will not copy it into site-packages"
        )


def test_the_sdist_manifest_also_ships_the_templates():
    """setup.cfg alone is not enough: ``python -m build`` builds the wheel FROM
    the sdist, and the sdist takes its contents from MANIFEST.in."""
    manifest = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "agent_panel_templates" in manifest, (
        "MANIFEST.in does not ship the template directory, so the sdist -- and "
        "therefore the published wheel built from it -- would omit it"
    )


# ---------------------------------------------------------------- the fence


def test_the_template_directory_is_fenced_from_agent_file_tools():
    """A crew must not be able to write its own template.

    The whole value of splitting template from data is that layout is authored by
    a human and only data comes from the crew. An agent file tool that could drop
    a .html into the template directory would collapse that distinction and hand
    a hostile issue body a way to author markup directly.
    """
    from kiro_crew import security

    assert agent_panel.TEMPLATES_DIRNAME in security._CREW_SECRET_LEAVES


def test_the_record_is_fenced_from_agent_file_tools_too():
    """The RECORD, not just the template. This is the cross-crew forgery guard.

    ``members/`` is deliberately unfenced -- a crew owns its own published data --
    and that reasoning holds for a crew's OWN panel and fails for everyone else's:
    under ``members/<slug>/`` nothing stopped one crew writing
    ``members/<other-crew>/panel.json`` directly, forging another crew's state
    past ownership resolution AND past the redactors in a single write, with the
    drawer rendering the result.
    """
    from kiro_crew import security

    assert agent_panel._TRUST_DIRNAME in security._CREW_SECRET_LEAVES
    # And the path really is under it, so the fence above actually covers it.
    assert agent_panel._TRUST_DIRNAME in agent_panel.panel_path(CREW).parts


def test_the_record_no_longer_lives_in_the_unfenced_member_space():
    """Pinned as a NEGATIVE so a future tidy-up cannot move it back."""
    from kiro_crew import members as members_mod

    assert members_mod.MEMBERS_DIR_NAME not in agent_panel.panel_path(CREW).parts


def test_a_hostile_slug_cannot_escape_the_records_directory():
    for bad in ("", "a/b", "a\\b", "..", "has space", "Upper.Case", "../../etc/passwd"):
        with pytest.raises(agent_panel.CrewSlugError):
            agent_panel.panel_path(bad)


def test_the_ownership_check_happens_under_the_lock():
    """The TOCTOU guard, asserted on the SOURCE because a race is not reproducible.

    ``read`` before the lock is not a weaker check, it is no check: two crews
    colliding on one slug both observe "no owner", both pass, and the later write
    silently overwrites the first -- the exact outcome the check exists to
    prevent. Asserting on order-in-source is crude but it is the property, and a
    timing test would pass on a machine that happened not to interleave.
    """
    import inspect

    src = inspect.getsource(agent_panel.publish)
    lock_at = src.index("with _locked(")
    read_at = src.index("existing = read(slug)")
    assert read_at > lock_at, (
        "the ownership read happens BEFORE the lock is taken, which makes the "
        "collision check a TOCTOU race rather than a guard"
    )


# ------------------------------------------------------------- the import cycle


def test_the_mirrored_member_layout_matches_members():
    """The store derives its paths itself; this is the anti-drift pin.

    Both names it mirrors are pinned, not just the slug pattern: the records sit
    beside ``members.dm_binding_path``'s output under one trust root, so a rename
    of that root on the ``members`` side must not leave this store writing to a
    directory nothing fences.
    """
    from kiro_crew import members as members_mod

    assert agent_panel._SLUG_RE.pattern == members_mod._SLUG_RE.pattern
    # ``members`` spells the trust root inline in ``dm_binding_path``; the shared
    # constant is the directory name under it, so compare against the real path.
    assert agent_panel._TRUST_DIRNAME in members_mod.dm_binding_path("probe-crew").parts


def test_the_store_works_as_an_entry_point(tmp_path):
    """``members`` must not be imported at this module's scope.

    It pulls in ``artifacts`` -> ``hooks`` -> ``webhooks`` -> ``validation``,
    which imports ``artifacts`` back. The cycle is LATENT whenever something
    else has already imported that chain -- which the test suite always has --
    so a module-scope import reads as green here and raises ``ImportError`` the
    moment this module is the first ``kiro_crew`` import in a process. Run in a
    subprocess for exactly that reason: importing it in-process proves nothing.
    """
    import subprocess
    import sys
    from pathlib import Path

    src = str(Path(__file__).resolve().parents[1] / "src")
    # Reaches a PATH, not just the import: a lazy module-scope import would pass
    # an import-only probe and still fail here, which is how the first attempt at
    # this fix read as green.
    probe = (
        "from kiro_crew import agent_panel;"
        " print(agent_panel.panel_path('fleet-crew'));"
        " print(agent_panel.SCHEMA_VERSION)"
    )
    # The child gets a HOME OF ITS OWN, and the env is built by copying rather
    # than replacing. A bare ``env={"PYTHONPATH": ..., "PATH": ...}`` drops
    # ``KIROCREW_HOME``, so ``panel_dir`` resolved ``data_home()`` to the
    # OPERATOR's real directory and the probe created it -- a test writing
    # outside its sandbox, on the machine of whoever ran the suite. ``cwd`` is
    # moved under ``tmp_path`` too, so anything the child resolves relatively
    # also lands in the sandbox.
    home = tmp_path / "child-home"
    home.mkdir()
    env = dict(os.environ)
    env["PYTHONPATH"] = src
    env["KIROCREW_HOME"] = str(home)
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        # Pinned rather than left to the locale: without it the child's output
        # decodes with the Windows ANSI code page, and this probe compares the
        # decoded path against `tmp_path`.
        encoding="utf-8",
        timeout=120,
        env=env,
        cwd=str(tmp_path),
    )
    assert out.returncode == 0, out.stderr[-1500:]
    resolved, schema = out.stdout.strip().splitlines()
    assert schema == str(agent_panel.SCHEMA_VERSION)
    # The path the child resolved must sit under the sandbox home. This is the
    # assertion that keeps the env from silently re-escaping: it fails if a
    # future edit drops ``KIROCREW_HOME`` again, instead of quietly creating a
    # directory in the operator's home the way the first version did.
    assert Path(resolved).is_relative_to(home.resolve()), resolved
