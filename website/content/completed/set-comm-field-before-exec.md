---
title: "Set `comm` field before `exec()`"
weight: 30
status: completed
categories:
  - processes
commit: "543841d18060"
---

[x] Set `comm` field before `exec()`

There should be a way to control the process' `comm` field if
started via `fexecve()`/`execveat()`.

Right now, when `fexecve()`/`execveat()` is used, the `comm` field
(i.e. `/proc/self/comm`) contains a name derived of the numeric fd,
which breaks `ps -C …` and various other tools.  In particular when
the fd was opened with `O_CLOEXEC`, the number of the fd in the old
process is completely meaningless.

The goal is add a way to tell `fexecve()`/`execveat()` what Name to use.

Since `comm` is under user control anyway (via `PR_SET_NAME`), it
should be safe to also make it somehow configurable at fexecve()
time.

See https://github.com/systemd/systemd/commit/35a926777e124ae8c2ac3cf46f44248b5e147294,
https://github.com/systemd/systemd/commit/8939eeae528ef9b9ad2a21995279b76d382d5c81.

**🙇 `543841d18060 ("exec: fix up /proc/pid/comm in the execveat(AT_EMPTY_PATH) case")` 🙇**

**Use-Case:** In systemd we generally would prefer using `fexecve()`
to safely and race-freely invoke processes, but the fact that `comm`
is useless after invoking a process that way makes the call
unfortunately hard to use for systemd.
