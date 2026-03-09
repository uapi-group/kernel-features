---
title: "Extend `io_uring` with classic synchronous system calls"
weight: 240
status: wishlist
categories:
  - io-uring
  - mounts
  - namespaces
---

The `io_uring` subsystem is open to adding classic existing synchronous
system calls (e.g. `setns()` or `mount()` or other) to `io_uring`.
They also said they would support adding new functionality into
`io_uring` that is not exposed through system calls yet.
