---
title: "A timeout for the `flock()` syscall"
weight: 150
status: wishlist
categories:
  - block-devices
  - processes
---

A timeout for the `flock()` syscall. Faking the time-out in userspace
is nasty: most code does it with `alarm()` (or equivalent APIs), but
that's racy since on a heavily loaded system the timeout might trigger
before the `flock()` call is entered, in particular if short time-outs
shall be used. More accurate is to do the locking in a short-lived
child processed, but that's difficult already in C, and almost
impossible in languages that do not allow `fork()` without `execve()`.

**Use-Case:** as mentioned above systemd-udev allows synchronizing
block device probing via flock(). Often userspace wants to wait
for that, but without risking to hang forever.
