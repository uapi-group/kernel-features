---
title: "`CLONE_PIDFD_AUTOKILL` semantics for PID 1"
weight: 20
status: wishlist
categories:
  - cgroups
  - pidfd
  - processes
---

Allow obtaining a `CLONE_PIDFD_AUTOKILL` pidfd for PID 1. Currently
PID 1 cannot hand off an autokill pidfd for itself. Allowing this would
make it possible to create system-death-traps where the lifetime of
PID 1 is tied to another process. PID 1 creates a `CLONE_PIDFD_AUTOKILL`
pidfd for itself, hands it off to another task, and closes its own copy.
If that other task exits, PID 1 is taken down.

**Use-Case:** Tie the lifetime of PID 1 to a critical process such as a
software TPM or other security-sensitive daemon. This ensures the system
is brought down if the critical process dies, rather than continuing to
run in a potentially compromised state.

**Considerations:** When PID 1 is spawned there is no mechanism to start
it with a pidfd right away. There are two possible approaches:

1. Place a pidfd at file descriptor position 3 in PID 1's file descriptor
   table before `exec()`, similar to how the coredump usermodehelper works.
   After `exec()` PID 1 knows that it already has an autokill pidfd for
   itself opened at fd 3.

2. Allow opening an autokill pidfd via `pidfd_open()`. This would require
   mutual exclusion with `CLONE_PIDFD_AUTOKILL`: if an autokill pidfd
   already exists from `clone3()` then no new autokill pidfd can be
   created via `pidfd_open()`. This guarantees clean semantics.

Permission checking would have to be strict. It should probably only be
allowed for the current thread-group leader on itself.
