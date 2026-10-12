# seatbelt-procargs-probe

On macOS, `sysctl({CTL_KERN, KERN_PROCARGS2, pid})` returns another process's
arguments and, before macOS 27, its environment. This repo measures whether a
process inside a Seatbelt sandbox (`sandbox-exec`) can still read it under the
two profile rules discussed in
[anthropics/sandbox-runtime#160](https://github.com/anthropics/sandbox-runtime/issues/160#issuecomment-6119661528),
against targets that differ in only one way at a time.

It is a measurement. It fixes nothing and asserts nothing about what the
results should be.

## Run it

```sh
./run.sh
```

It needs only the Xcode Command Line Tools. It builds `probe.c`, prints the OS
version, architecture, SIP status and code-signing details, then one table.
Before measuring, it checks that each profile is enforced by trying a file
write that `(deny default)` must block. The exit status is non-zero only if
the harness itself broke, including a profile that was not enforced.

## What it measures

Each target carries a fresh argument marker in its argv and a fresh
environment marker in `PROCARGS_TEST_SECRET`. A cell says which of the two
the probe found, or the errno and which `sysctl` call (`@size` or `@data`)
was refused.

| Target | Apple binary | Relation to the sandboxed probe |
|---|---|---|
| `sh-unrelated` | yes (`/bin/sh`) | unrelated, started outside the sandbox |
| `probe-unrelated` | no (`probe sleep`) | unrelated, started outside the sandbox |
| `sh-ancestor` | yes (`/bin/sh`) | parent of the sandboxed probe |
| `probe-ancestor` | no (`probe launch`) | parent of the sandboxed probe |

| Condition | Profile |
|---|---|
| `unsandboxed` | none |
| `control.sb` | deny-default, just enough to run, `kern.procargs2` open |
| `deny.sb` | `control.sb` + `(deny process-info* (target others))` + `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))` |
| `deny-regex.sb` | `deny.sb` with the sysctl deny also matching `^kern\.proc\.` |

## Their test

`.github/workflows/upstream.yml` checks out
[archie-judd/agent-sandbox.nix](https://github.com/archie-judd/agent-sandbox.nix)
at v5.5.1 and runs its `tests/integration/test_sysctl.py`, unmodified. It then
reruns `run.sh` with the profile that test generated as an extra
`upstream.sb` column (via `EXTRA_PROFILE` and `PROBE_DIR`, see `run.sh`).

`experiments/launch-matrix.sh` then splits the reader from the launch: our C
probe and their `probe.lua` under LuaJIT, each run unsandboxed, under
`deny-regex.sb`, under their profile directly, under their profile as a child
of a shell inside the sandbox, and through their launcher.

`experiments/test_procargs_targets.py` is copied into their test directory at
run time and reruns their probe, through their harness, against other
targets: pytest itself, its parent, a `/bin/sh` and a Python started by
pytest, and a `/bin/sh` and a Python that are ancestors of the sandbox.

## Sessions

`experiments/session-matrix.sh` starts the sandboxed reader in the caller's
session, in a new process group, and in a new session (`probe detach`), under
each profile plus `deny-info.sb` and `deny-sysctl.sb` (one of the two rules
each), against targets inside and outside the reader's session.

`experiments/rejoin.sh` starts the sandbox in a new process group or a new
session, and has the code inside it try to move back into the target's
process group (`probe join`, which calls `setpgid()`) before reading.

## Results

From commit `e167e94`, runs
[probe 38282769638](https://github.com/amorey/seatbelt-procargs-probe/actions/runs/38282769638)
and
[upstream 38282769745](https://github.com/amorey/seatbelt-procargs-probe/actions/runs/38282769745).
Every runner in a workflow produced the same table, so each table appears
once. SIP is reported disabled on every runner.

| runner | macOS | build | arch |
|---|---|---|---|
| macos-15 | 15.7.9 | 24G830 | arm64 |
| macos-15-intel | 15.7.9 | 24G830 | x86_64 |
| macos-26 | 26.6.2 | 25G83 | arm64 |
| macos-26-intel | 26.6.1 | 25G76 | x86_64 |
| xcode-27 | 27.0.1 | 26A434 | arm64 |

### `run.sh` (all five runners)

| target | apple binary | relation | unsandboxed | control.sb | deny.sb | deny-regex.sb |
|---|---|---|---|---|---|---|
| sh-unrelated | yes | unrelated | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| probe-unrelated | no | unrelated | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| sh-ancestor | yes | ancestor | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| probe-ancestor | no | ancestor | read (args, env) | read (args, env) | read (args, env) | read (args, env) |

### `session-matrix.sh` (all five runners)

| target | reader started in | unsandboxed | control.sb | deny-info.sb | deny-sysctl.sb | deny.sb | deny-regex.sb |
|---|---|---|---|---|---|---|---|
| same-session | this session | read | read | read | read | read | read |
| same-session | new process group | read | read | read | read | EPERM @size | EPERM @size |
| same-session | new session | read | read | read | read | EPERM @size | EPERM @size |
| ancestor | this session | read | read | read | read | read | read |
| ancestor | new process group | read | read | read | read | EPERM @size | EPERM @size |
| ancestor | new session | read | read | read | read | EPERM @size | EPERM @size |
| own-session | this session | read | read | read | read | EPERM @size | EPERM @size |
| own-session | new process group | read | read | read | read | EPERM @size | EPERM @size |
| own-session | new session | read | read | read | read | EPERM @size | EPERM @size |

### agent-sandbox.nix v5.5.1 (macos-26 and xcode-27)

Their `test_sysctl.py`: passed on both.

`run.sh` with the profile their test generated as `upstream.sb`:

| target | apple binary | relation | unsandboxed | control.sb | deny.sb | deny-regex.sb | upstream.sb |
|---|---|---|---|---|---|---|---|
| sh-unrelated | yes | unrelated | read (args, env) | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| probe-unrelated | no | unrelated | read (args, env) | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| sh-ancestor | yes | ancestor | read (args, env) | read (args, env) | read (args, env) | read (args, env) | read (args, env) |
| probe-ancestor | no | ancestor | read (args, env) | read (args, env) | read (args, env) | read (args, env) | read (args, env) |

`launch-matrix.sh`. For `lua`, "all" is the errnos for `kern.proc.all`,
`kern.procargs` and `kern.procargs2`, where 0 is a read and 1 is EPERM:

| reader | target | unsandboxed | deny-regex.sb | their profile, direct | their profile, child of sh | their launcher |
|---|---|---|---|---|---|---|
| c | unrelated | read | read | read | read | read |
| c | ancestor | read | read | read | read | read |
| lua | unrelated | read (all: 0 0 0) | read (all: 1 0 0) | read (all: 1 0 0) | read (all: 1 0 0) | read (all: 1 0 0) |
| lua | ancestor | read (all: 0 0 0) | read (all: 1 0 0) | read (all: 1 0 0) | read (all: 1 0 0) | read (all: 1 0 0) |

`test_procargs_targets.py`, their probe through their harness. Their harness
starts the launcher with `start_new_session=True`; the two `-ancestor` targets
start it themselves, without a new session:

| target | process | probe.lua output |
|---|---|---|
| pytest-self | Nix `python3.14` | `1 1 1` |
| pytest-parent | `/bin/bash` | `1 1 1` |
| sh-child | `/bin/sh` | `1 1 1` |
| python-child | Nix `python3.14` | `1 1 1` |
| sh-ancestor | `/bin/sh` | `1 0 0` |
| python-ancestor | Nix `python3.14` | `1 0 0` |
