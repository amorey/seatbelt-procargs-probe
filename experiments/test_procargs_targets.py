"""Their kern.procargs2 probe, against targets other than pytest itself.

Not part of agent-sandbox.nix. The upstream workflow copies this file into
its tests/integration/ at run time, so it runs in their harness with their
fixture, launcher and probe.lua; only the target pid changes. It records what
each read returned and asserts nothing about it.
"""

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from harness.build import BuildSandbox
from harness.launch import Launch

pytestmark = pytest.mark.darwin


def _their_probe() -> str:
    path = Path(__file__).with_name("test_sysctl.py")
    spec = importlib.util.spec_from_file_location("their_test_sysctl", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PROBE


# These start the launcher themselves, reading their own pid, so the target is
# an ancestor of the sandbox the way pytest is in their test.
SH_ANCESTOR = '"$0" --norc --noprofile -c "luajit probe.lua $$"; :'
PY_ANCESTOR = """
import os, subprocess, sys
result = subprocess.run(
    [sys.argv[1], "--norc", "--noprofile", "-c", f"luajit probe.lua {os.getpid()}"],
    stdin=subprocess.DEVNULL, capture_output=True, text=True,
)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
sys.exit(result.returncode)
"""

TARGETS = [
    "pytest-self",
    "pytest-parent",
    "sh-child",
    "python-child",
    "sh-ancestor",
    "python-ancestor",
]


def _comm(pid: int) -> str:
    out = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True)
    return out.stdout.strip() or "?"


@pytest.mark.parametrize("target", TARGETS)
def test_procargs_target(
    target: str,
    build_sandbox: BuildSandbox,
    launch: Launch,
    tmp_path: Path,
    fake_home: Path,
    sessions_root: Path,
) -> None:
    binary = build_sandbox("sysctl-narrowed-sandbox")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "probe.lua").write_text(_their_probe())
    # The environment their launch_sandbox gives the launcher.
    env = {
        **os.environ,
        "PWD": str(workspace),
        "HOME": str(fake_home),
        "AGENT_SANDBOX_SESSIONS_ROOT": str(sessions_root),
    }

    child = None
    try:
        if target in ("sh-ancestor", "python-ancestor"):
            argv = (
                ["/bin/sh", "-c", SH_ANCESTOR, str(binary)]
                if target == "sh-ancestor"
                else [sys.executable, "-c", PY_ANCESTOR, str(binary)]
            )
            what = argv[0]
            result = subprocess.run(
                argv, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                capture_output=True, text=True,
            )
        else:
            if target == "pytest-self":
                pid = os.getpid()
            elif target == "pytest-parent":
                pid = os.getppid()
            else:
                argv = (
                    ["/bin/sh", "-c", "/bin/sleep 600; :"]
                    if target == "sh-child"
                    else [sys.executable, "-c", "import time; time.sleep(600)"]
                )
                # Its own process group, so the sleep under sh dies with it.
                child = subprocess.Popen(argv, start_new_session=True)
                time.sleep(0.5)
                pid = child.pid
            what = _comm(pid)
            result = launch(binary, f"luajit probe.lua {pid}", cwd=workspace)
    finally:
        if child is not None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()

    # probe.lua prints errnos for kern.proc.all, kern.procargs, kern.procargs2.
    line = f"| {target} | `{what}` | `{result.stdout.strip()}` |"
    print(f"\nRESULT {line}")
    if path := os.environ.get("PROCARGS_RESULTS"):
        with open(path, "a") as f:
            f.write(line + "\n")
    assert result.returncode == 0, result.stderr
