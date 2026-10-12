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
The exit status is non-zero only if the harness itself broke.

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

## Results

_Not yet run. One table per runner goes here, copied from the CI job
summaries._
