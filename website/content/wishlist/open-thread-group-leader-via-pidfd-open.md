---
title: "Open thread-group leader via `pidfd_open()`"
weight: 380
status: wishlist
categories:
  - pidfd
---

Extend `pidfd_open()` to allow opening the thread-group leader based on the
PID of an individual thread. Currently we do support:

1. `pidfd_open(1234, 0)` on a thread-group leader PID
2. `pidfd_open(1234, PIDFD_THREAD)` on a thread

Add an option to go from individual thread to thread-group leader.

**Use-Case:** Allow for a race free way to go from individual thread
to thread-group leader pidfd.
