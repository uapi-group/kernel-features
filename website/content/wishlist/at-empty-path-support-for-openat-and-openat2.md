---
title: "`AT_EMPTY_PATH` support for `openat()` and `openat2()`"
weight: 420
status: wishlist
categories:
  - processes
---

To get an operable version of an `O_PATH` file descriptors, it is
possible to use `openat(fd, ".", O_DIRECTORY)` for directories, but
other files currently require going through
`open("/proc/<pid>/fd/<nr>")` which depends on a functioning `procfs`.

FreeBSD already has `O_EMPTY_PATH` for `openat`, while `fstatat` and
similar functions have `AT_EMPTY_PATH`.

**Use-Case:** When dealing with `O_PATH` file descriptors, allow
re-opening an operable version without the need of `procfs`.
