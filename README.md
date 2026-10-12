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

## Results

_Not yet run. One table per runner goes here, copied from the CI job
summaries._
