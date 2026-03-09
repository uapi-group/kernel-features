---
title: "Create mount namespace with custom rootfs via `open_tree()` and `fsmount()`"
weight: 40
status: in-progress
categories:
  - mounts
  - namespaces
  - processes
---

Add `OPEN_TREE_NAMESPACE` flag to `open_tree()` and `FSMOUNT_NAMESPACE` flag
to `fsmount()` that create a new mount namespace with the specified mount tree
as the rootfs mounted on top of a copy of the real rootfs. These return a
namespace file descriptor instead of a mount file descriptor.

This allows `OPEN_TREE_NAMESPACE` to function as a combined
`unshare(CLONE_NEWNS)` and `pivot_root()`.

When creating containers the setup usually involves using `CLONE_NEWNS` via
`clone3()` or `unshare()`. This copies the caller's complete mount namespace.
The runtime will also assemble a new rootfs and then use `pivot_root()` to
switch the old mount tree with the new rootfs. Afterward it will recursively
unmount the old mount tree thereby getting rid of all mounts.

Copying all of these mounts only to get rid of them later is wasteful. With a
large mount table and a system where thousands of containers are spawned in
parallel this quickly becomes a bottleneck increasing contention on the
semaphore.

**Use-Case:** Container runtimes can create an extremely minimal rootfs
directly:

```c
fd_mntns = open_tree(-EBADF, "/var/lib/containers/wootwoot", OPEN_TREE_NAMESPACE);
```

This creates a mount namespace where "wootwoot" has become the rootfs. The
caller can `setns()` into this new mount namespace and assemble additional
mounts without copying and destroying the entire parent mount table.
