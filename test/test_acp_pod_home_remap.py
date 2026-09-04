"""``acp.client._apply_pod_home_remap`` -- HOME remap for a pod-spawned kiro-cli
child, applied identically at both ACP spawn sites (``AcpClient._spawn`` and
``AcpRuntime._spawn_admitted``).

Regression context: ``pod.runtime.build_pod_env`` deliberately keeps the pod
GATEWAY's own ``HOME`` unchanged (isolating ``KIROCREW_HOME``/``KIRO_HOME``
only), so a pod-spawned kiro-cli child inherited that same real ``$HOME`` and
wrote its MCP OAuth grant artifacts there -- a REAL, durable, machine-level
credential that survived ``pod down``. This function is the fix's second half:
``mcp_grant.kiro_oauth_cache_dir()`` (pinned in ``test_mcp_grant.py``) makes
the pod's OWN reads resolve the pod's tree; this makes kiro-cli's OWN WRITES
land there too, by remapping the spawned child's ``HOME``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kiro_crew.acp.client import _apply_pod_home_remap


def _base_pod_env(tmp_path: Path) -> dict[str, str]:
    """A KIROCREW_POD=1 env with KIROCREW_OS_HOME set, as build_pod_env emits."""
    return {
        "HOME": str(tmp_path / "real-home"),
        "PATH": "/usr/bin",
        "KIROCREW_POD": "1",
        "KIROCREW_OS_HOME": str(tmp_path / "pod-os-home"),
    }


class TestAppliesOnlyInsideAPodForKiroCli:
    def test_remaps_home_for_a_pod_kiro_cli_spawn(self, tmp_path: Path) -> None:
        env = _base_pod_env(tmp_path)
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["HOME"] == str(tmp_path / "pod-os-home")
        assert out is env  # mutates in place, per the docstring's contract

    def test_userprofile_moves_with_home(self, tmp_path: Path) -> None:
        """Windows spelling of the same concept — the two must never disagree."""
        env = _base_pod_env(tmp_path)
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["USERPROFILE"] == out["HOME"] == str(tmp_path / "pod-os-home")

    def test_noop_outside_a_pod(self, tmp_path: Path) -> None:
        """No KIROCREW_POD marker -- an ordinary, non-pod ACP spawn on the
        operator's own machine must never have its HOME touched."""
        env = _base_pod_env(tmp_path)
        del env["KIROCREW_POD"]
        real_home = env["HOME"]
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["HOME"] == real_home
        assert "USERPROFILE" not in out

    def test_noop_for_a_non_kiro_harness_inside_a_pod(self, tmp_path: Path) -> None:
        """A Claude/KAS child inside a pod is a different harness with its own
        credential store; it must not be told a Kiro-specific env story."""
        env = _base_pod_env(tmp_path)
        real_home = env["HOME"]
        out = _apply_pod_home_remap(env, pod_home_remap=False)
        assert out["HOME"] == real_home
        assert "USERPROFILE" not in out

    def test_noop_when_the_pod_marker_is_set_with_no_os_home(self, tmp_path: Path) -> None:
        """A malformed pod env (marker without the directory to point at) must
        leave HOME as-is rather than remapping to an empty string -- breaking
        every filesystem-dependent tool in the spawned child would be strictly
        worse than the status quo it degrades to."""
        env = _base_pod_env(tmp_path)
        del env["KIROCREW_OS_HOME"]
        real_home = env["HOME"]
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["HOME"] == real_home

    @pytest.mark.parametrize("marker", ["false", "0", "no", "off", "", "true", "2", " 1"])
    def test_only_the_exact_marker_value_one_remaps(self, tmp_path: Path, marker: str) -> None:
        """Every non-empty string is truthy in Python, so a truthiness test on
        KIROCREW_POD remapped HOME for a child whose marker explicitly said it
        was NOT in a pod. Only the value build_pod_env actually writes ("1")
        may move a credential store."""
        env = _base_pod_env(tmp_path)
        env["KIROCREW_POD"] = marker
        real_home = env["HOME"]
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["HOME"] == real_home, f"marker {marker!r} must not remap HOME"
        assert "AWS_CONFIG_FILE" not in out


class TestTheCapabilitySetIsItsOwnDecision:
    """The remap is gated on ACP_BACKENDS_POD_HOME_REMAP, never on the
    internal-sandbox set: "carries its own OS sandbox" and "relocating HOME
    moves its credential store" are different questions, and conflating them
    would hand a harness added for sandbox reasons credential-relocation
    semantics it never opted into (harness-parity H6)."""

    def test_the_set_exists_and_is_a_subset_of_known_backends(self) -> None:
        from kiro_crew.acp_backends import (
            ACP_BACKENDS_KNOWN,
            ACP_BACKENDS_POD_HOME_REMAP,
        )

        assert ACP_BACKENDS_POD_HOME_REMAP <= ACP_BACKENDS_KNOWN

    def test_membership_is_positive_and_kiro_only(self) -> None:
        from kiro_crew.acp_backends import (
            ACP_BACKEND_CLAUDE,
            ACP_BACKEND_KAS,
            ACP_BACKEND_KIRO,
            ACP_BACKENDS_POD_HOME_REMAP,
        )

        assert ACP_BACKEND_KIRO in ACP_BACKENDS_POD_HOME_REMAP
        assert ACP_BACKEND_CLAUDE not in ACP_BACKENDS_POD_HOME_REMAP
        assert ACP_BACKEND_KAS not in ACP_BACKENDS_POD_HOME_REMAP

    def test_neither_spawn_site_gates_the_remap_on_the_sandbox_set(self) -> None:
        """The regression: reusing ACP_BACKENDS_INTERNAL_SANDBOX for this gate
        is the conflation, so neither call site may name it for the remap."""
        import inspect

        from kiro_crew.acp import client as client_mod
        from kiro_crew.acp import runtime as runtime_mod

        for source in (
            inspect.getsource(client_mod.AcpClient._spawn),
            inspect.getsource(runtime_mod.AcpRuntime._spawn_admitted),
        ):
            remap_call = source.split("_apply_pod_home_remap(")[1].split(")")[0]
            assert "ACP_BACKENDS_POD_HOME_REMAP" in remap_call
            assert "ACP_BACKENDS_INTERNAL_SANDBOX" not in remap_call


class TestAwsCredentialFilesArePinnedToTheRealHome:
    """Requirement: AWS env credentials keep working for pod agent turns even
    though HOME now points at the pod's (mostly empty) os-home tree."""

    def test_pins_aws_config_file_to_the_real_home(self, tmp_path: Path) -> None:
        env = _base_pod_env(tmp_path)
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["AWS_CONFIG_FILE"] == str(tmp_path / "real-home" / ".aws" / "config")

    def test_pins_aws_shared_credentials_file_to_the_real_home(self, tmp_path: Path) -> None:
        env = _base_pod_env(tmp_path)
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["AWS_SHARED_CREDENTIALS_FILE"] == str(
            tmp_path / "real-home" / ".aws" / "credentials"
        )

    def test_never_overwrites_an_operator_set_aws_config_file(self, tmp_path: Path) -> None:
        """An operator who already pointed AWS_CONFIG_FILE somewhere specific
        must keep pointing there — only the DEFAULT resolution is corrected."""
        env = _base_pod_env(tmp_path)
        env["AWS_CONFIG_FILE"] = "/custom/aws-config"
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["AWS_CONFIG_FILE"] == "/custom/aws-config"

    def test_never_overwrites_an_operator_set_credentials_file(self, tmp_path: Path) -> None:
        env = _base_pod_env(tmp_path)
        env["AWS_SHARED_CREDENTIALS_FILE"] = "/custom/aws-creds"
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert out["AWS_SHARED_CREDENTIALS_FILE"] == "/custom/aws-creds"

    def test_pins_derive_from_the_pre_remap_home_not_the_new_one(self, tmp_path: Path) -> None:
        """The AWS files must resolve against the REAL home, not the pod's
        os-home -- pinning them AFTER HOME is overwritten would point AWS
        credential resolution at the pod's empty tree."""
        env = _base_pod_env(tmp_path)
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert str(tmp_path / "pod-os-home") not in out["AWS_CONFIG_FILE"]
        assert str(tmp_path / "pod-os-home") not in out["AWS_SHARED_CREDENTIALS_FILE"]

    def test_no_aws_pins_outside_a_pod(self, tmp_path: Path) -> None:
        """Nothing to correct when HOME was never remapped."""
        env = _base_pod_env(tmp_path)
        del env["KIROCREW_POD"]
        out = _apply_pod_home_remap(env, pod_home_remap=True)
        assert "AWS_CONFIG_FILE" not in out
        assert "AWS_SHARED_CREDENTIALS_FILE" not in out


class TestBothSpawnTransportsApplyItIdentically:
    """AcpClient and AcpRuntime must reach the same function with the same
    harness-parity-correct classification -- never a hand-rolled copy that
    could drift between the two transports."""

    def test_acp_client_spawn_calls_the_shared_helper(self) -> None:
        import inspect

        from kiro_crew.acp import client as client_mod

        source = inspect.getsource(client_mod.AcpClient._spawn)
        assert "_apply_pod_home_remap(" in source
        assert "ACP_BACKENDS_POD_HOME_REMAP" in source

    def test_acp_runtime_spawn_calls_the_same_shared_helper(self) -> None:
        import inspect

        from kiro_crew.acp import runtime as runtime_mod

        source = inspect.getsource(runtime_mod.AcpRuntime._spawn_admitted)
        assert "_apply_pod_home_remap(" in source
        assert "ACP_BACKENDS_POD_HOME_REMAP" in source

    def test_runtime_imports_the_client_defined_function_rather_than_a_copy(self) -> None:
        """Import identity, not merely name equality — a copy-pasted function
        of the same name would pass a naive check while drifting silently."""
        from kiro_crew.acp import client as client_mod
        from kiro_crew.acp import runtime as runtime_mod

        assert runtime_mod._apply_pod_home_remap is client_mod._apply_pod_home_remap
