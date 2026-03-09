---
title: "Support detached mounts with `pivot_root()`"
weight: 30
status: in-progress
categories:
  - filesystems
  - mounts
---

The new rootfs must currently refer to an attached mount. This restriction
seems unnecessary. We should allow the new rootfs to refer to a detached
mount.

This will allow a service- or container manager to create a new rootfs as
a detached, private mount that isn't exposed anywhere in the filesystem and
then `pivot_root()` into it.

Since `pivot_root()` only takes path arguments the new rootfs would need to
be passed via `/proc/<pid>/fd/<nr>`. In the long run we should add a new
`pivot_root()` syscall operating on file descriptors instead of paths.
