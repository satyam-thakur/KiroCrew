"""The gateway stops serving an app that another process tore down (#7926).

``kirocrew app disable`` and ``kirocrew app uninstall`` run in a different OS
process from the gateway. They write ``installed.json`` and report success, but
``RouteRegistry`` is an in-memory table in the gateway, so the app's routes keep
dispatching until something in THAT process removes the registration. These
tests drive a real aiohttp app through a real ``RouteRegistry`` and assert the
route is genuinely gone -- ``get_registered_apps`` no longer lists the app, and
the request 404s -- not merely hidden behind a check.

Every leak test asserts BOTH directions: the route answers 200 before the sweep
(so the test would fail on a base commit for the right reason) and 404 after.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew.apps import hooks_integration
from kiro_crew.apps.manager import APP_MANIFEST_FILENAME, enable_app, install_app

ROUTES_MODULE = """\
from aiohttp import web

from kiro_crew.apps.route_registry import AppRoute


async def _probe(request, ctx):
    return web.json_response({"served": True})


def register(ctx):
    return [AppRoute(method="GET", path="/probe", handler=_probe)]
"""


def _make_hooks_app_source(tmp_path: Path, name: str) -> Path:
    """An app whose only backend surface is a ``hooks.routes`` module."""
    src = tmp_path / "source" / name
    (src / "backend").mkdir(parents=True)
    (src / APP_MANIFEST_FILENAME).write_text(
        json.dumps(
            {
                "name": name,
                "version": "1.0.0",
                "displayName": name,
                "description": "route teardown probe",
                "author": "tester",
                "backend": {"hooks": {"routes": "backend.routes:register"}},
            },
            indent=2,
        )
    )
    (src / "backend" / "routes.py").write_text(ROUTES_MODULE)
    return src


@pytest.fixture()
def sweep_env(tmp_path, monkeypatch):
    """A temp KIROCREW_HOME with the hooks system initialized on a real aiohttp app."""
    home = tmp_path / "kirocrew-home"
    home.mkdir()
    monkeypatch.setenv("KIROCREW_HOME", str(home))
    monkeypatch.setattr("kiro_crew.apps.execution.third_party_execution_allowed", lambda: True)
    monkeypatch.setattr(hooks_integration, "_route_registry", None)
    monkeypatch.setattr(hooks_integration, "_lifecycle_dispatcher", None)
    monkeypatch.setattr(hooks_integration, "_teardown_sweep_task", None)

    aio = web.Application()
    hooks_integration.init_hooks_system(aio)
    return {"home": home, "aio": aio, "tmp_path": tmp_path}


async def _install_enable_and_register(env: dict[str, Any], name: str) -> None:
    """Bring an app up exactly as the gateway does: metadata, then hook wiring."""
    from kiro_crew.apps.manager import get_app

    src = _make_hooks_app_source(env["tmp_path"], name)
    result = install_app(str(src))
    assert result.ok, result.error
    result = enable_app(name)
    assert result.ok, result.error
    await hooks_integration.on_app_enable(name, get_app(name))
    assert name in hooks_integration.get_route_registry().get_registered_apps()


async def _probe_route(client: TestClient, name: str) -> int:
    resp = await client.get(f"/api/apps/{name}/probe")
    await resp.release()
    return resp.status


def _write_enabled_flag(home: Path, name: str, *, enabled: bool) -> None:
    """Flip ``installed.json`` the way the CLI's ``disable_app`` does."""
    meta_path = home / "apps" / name / "installed.json"
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    data["enabled"] = enabled
    meta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _remove_installed_metadata(home: Path, name: str) -> None:
    """Leave the state a CLI ``uninstall`` leaves: no metadata file at all."""
    (home / "apps" / name / "installed.json").unlink()


class TestTornDownAppStopsBeingServed:
    """Both CLI verbs, and the still-installed app must be untouched."""

    @pytest.mark.asyncio
    async def test_disabled_out_of_process_app_route_is_removed(self, sweep_env):
        await _install_enable_and_register(sweep_env, "leak-probe")
        registry = hooks_integration.get_route_registry()

        client = TestClient(TestServer(sweep_env["aio"]))
        await client.start_server()
        try:
            # POSITIVE CONTROL: without the sweep this is the whole bug -- the
            # metadata says disabled and the route still answers.
            _write_enabled_flag(sweep_env["home"], "leak-probe", enabled=False)
            assert await _probe_route(client, "leak-probe") == 200
            assert "leak-probe" in registry.get_registered_apps()

            torn_down = await hooks_integration.reconcile_torn_down_apps()

            assert torn_down == ["leak-probe"]
            # REMOVED, not hidden: the table itself no longer carries the app.
            assert "leak-probe" not in registry.get_registered_apps()
            assert await _probe_route(client, "leak-probe") == 404
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_uninstalled_out_of_process_app_route_is_removed(self, sweep_env):
        """An absent metadata file is a definite not-installed, not an unknown."""
        await _install_enable_and_register(sweep_env, "leak-probe")
        registry = hooks_integration.get_route_registry()

        client = TestClient(TestServer(sweep_env["aio"]))
        await client.start_server()
        try:
            _remove_installed_metadata(sweep_env["home"], "leak-probe")
            assert await _probe_route(client, "leak-probe") == 200

            torn_down = await hooks_integration.reconcile_torn_down_apps()

            assert torn_down == ["leak-probe"]
            assert "leak-probe" not in registry.get_registered_apps()
            assert await _probe_route(client, "leak-probe") == 404
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_sweep_does_not_touch_a_still_enabled_app(self, sweep_env):
        """The inverse assertion: teardown must not over-reach past its target."""
        await _install_enable_and_register(sweep_env, "leak-probe")
        await _install_enable_and_register(sweep_env, "keeper-app")
        registry = hooks_integration.get_route_registry()

        client = TestClient(TestServer(sweep_env["aio"]))
        await client.start_server()
        try:
            _write_enabled_flag(sweep_env["home"], "leak-probe", enabled=False)

            torn_down = await hooks_integration.reconcile_torn_down_apps()

            assert torn_down == ["leak-probe"]
            assert registry.get_registered_apps() == ["keeper-app"]
            assert await _probe_route(client, "keeper-app") == 200
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_sweep_unloads_the_app_modules(self, sweep_env):
        """Deregistration must take ``sys.modules`` with it, or the code stays live."""
        import sys

        await _install_enable_and_register(sweep_env, "leak-probe")
        assert any(k.startswith("_kirocrew_app_leak-probe") for k in sys.modules)

        _write_enabled_flag(sweep_env["home"], "leak-probe", enabled=False)
        await hooks_integration.reconcile_torn_down_apps()

        assert not any(k.startswith("_kirocrew_app_leak-probe") for k in sys.modules)

    @pytest.mark.asyncio
    async def test_repeated_sweeps_report_the_teardown_once(self, sweep_env):
        """Nothing is left registered, so a second sweep has nothing to report."""
        await _install_enable_and_register(sweep_env, "leak-probe")
        _write_enabled_flag(sweep_env["home"], "leak-probe", enabled=False)

        assert await hooks_integration.reconcile_torn_down_apps() == ["leak-probe"]
        assert await hooks_integration.reconcile_torn_down_apps() == []


class TestSweepRefusesToActOnAnUnknownState:
    """``app_enabled_state`` is tri-state; only a CONFIRMED False may tear down."""

    @pytest.mark.asyncio
    async def test_unreadable_metadata_leaves_the_registration_standing(self, sweep_env):
        """A transient read fault must not take a live app's routes offline."""
        await _install_enable_and_register(sweep_env, "leak-probe")
        registry = hooks_integration.get_route_registry()

        client = TestClient(TestServer(sweep_env["aio"]))
        await client.start_server()
        try:
            # None, not False: the app may well still be enabled and the file
            # merely unreadable this instant.
            (sweep_env["home"] / "apps" / "leak-probe" / "installed.json").write_text(
                "{ not json", encoding="utf-8"
            )

            assert await hooks_integration.reconcile_torn_down_apps() == []
            assert "leak-probe" in registry.get_registered_apps()
            assert await _probe_route(client, "leak-probe") == 200
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_sweep_with_no_registry_is_a_no_op(self, sweep_env, monkeypatch):
        """Called before ``init_hooks_system``, the sweep must not raise."""
        monkeypatch.setattr(hooks_integration, "_route_registry", None)
        assert await hooks_integration.reconcile_torn_down_apps() == []


class TestSweepSurvivesItsOwnFailures:
    """The exposure lasts until something deregisters, so the loop must not die."""

    @pytest.mark.asyncio
    async def test_a_failing_app_teardown_does_not_stop_the_sweep(self, sweep_env, monkeypatch):
        await _install_enable_and_register(sweep_env, "aaa-fails")
        await _install_enable_and_register(sweep_env, "zzz-succeeds")
        registry = hooks_integration.get_route_registry()
        _write_enabled_flag(sweep_env["home"], "aaa-fails", enabled=False)
        _write_enabled_flag(sweep_env["home"], "zzz-succeeds", enabled=False)

        real_disable = hooks_integration.on_app_disable

        async def _explode_for_one(name, info, **kwargs):
            if name == "aaa-fails":
                raise RuntimeError("teardown blew up")
            return await real_disable(name, info, **kwargs)

        monkeypatch.setattr(hooks_integration, "on_app_disable", _explode_for_one)

        torn_down = await hooks_integration.reconcile_torn_down_apps()

        assert torn_down == ["zzz-succeeds"]
        assert "aaa-fails" in registry.get_registered_apps()

    @pytest.mark.asyncio
    async def test_an_incomplete_teardown_is_not_reported_as_torn_down(
        self, sweep_env, monkeypatch
    ):
        """``on_app_disable`` returns early when a detached startup hook will not stop."""
        await _install_enable_and_register(sweep_env, "leak-probe")
        registry = hooks_integration.get_route_registry()
        _write_enabled_flag(sweep_env["home"], "leak-probe", enabled=False)

        async def _returns_without_deregistering(name, info, **kwargs):
            return {"startup_cleanup": "failed"}

        monkeypatch.setattr(hooks_integration, "on_app_disable", _returns_without_deregistering)

        assert await hooks_integration.reconcile_torn_down_apps() == []
        assert "leak-probe" in registry.get_registered_apps()

    @pytest.mark.asyncio
    async def test_loop_keeps_running_after_a_failed_sweep(self, sweep_env, monkeypatch):
        calls: list[int] = []
        done = asyncio.Event()

        async def _fail_then_succeed() -> list[str]:
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("sweep blew up")
            done.set()
            return []

        monkeypatch.setattr(hooks_integration, "_TEARDOWN_SWEEP_INTERVAL", 0.01)
        monkeypatch.setattr(hooks_integration, "reconcile_torn_down_apps", _fail_then_succeed)

        hooks_integration.start_teardown_sweep()
        try:
            await asyncio.wait_for(done.wait(), timeout=5)
        finally:
            await hooks_integration.stop_teardown_sweep()

        assert len(calls) >= 2


class TestSweepLifecycle:
    """Arming and cancelling, so an in-process restart leaks no task."""

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self, sweep_env):
        hooks_integration.start_teardown_sweep()
        first = hooks_integration._teardown_sweep_task
        hooks_integration.start_teardown_sweep()
        try:
            assert hooks_integration._teardown_sweep_task is first
        finally:
            await hooks_integration.stop_teardown_sweep()

    @pytest.mark.asyncio
    async def test_stop_cancels_and_clears_the_task(self, sweep_env):
        hooks_integration.start_teardown_sweep()
        task = hooks_integration._teardown_sweep_task
        assert task is not None

        await hooks_integration.stop_teardown_sweep()

        assert task.cancelled()
        assert hooks_integration._teardown_sweep_task is None

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_no_op(self, sweep_env):
        await hooks_integration.stop_teardown_sweep()
        assert hooks_integration._teardown_sweep_task is None
