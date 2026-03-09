---
title: "API to determine the parent process ID of a pidfd"
weight: 20
status: completed
categories:
  - pidfd
  - processes
commit: "cdda1f26e74b"
---

[x] API to determine the parent process ID of a pidfd

An API to determine the parent process ID (ppid) of a pidfd would be
good.

This information is relevant to code dealing with pidfds, since if
the ppid of a pidfd matches the process own pid it can call
`waitid()` on the process, if it doesn't it cannot and such a call
would fail. It would be very useful if this could be determined
easily before even calling that syscall.

**🙇 `cdda1f26e74b ("pidfd: add ioctl to retrieve pid info")` 🙇**

**Use-Case:** systemd manages a multitude of processes, most of which
are its own children, but many which are not. It would be great if
we could easily determine whether it is worth waiting for
`SIGCHLD`/`waitid()` on them or whether waiting for `POLLIN` on
them is the only way to get exit notification.
