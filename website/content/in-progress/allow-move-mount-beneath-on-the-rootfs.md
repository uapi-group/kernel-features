---
title: "Allow `MOVE_MOUNT_BENEATH` on the rootfs"
weight: 60
status: in-progress
categories:
  - filesystems
  - mounts
  - namespaces
  - processes
---

Allow `MOVE_MOUNT_BENEATH` to target the caller's rootfs, enabling
root-switching without `pivot_root(2)`. The traditional approach to
switching the rootfs involves `pivot_root(2)` or a `chroot_fs_refs()`-based
mechanism that atomically updates `fs->root` for all tasks sharing the
same `fs_struct`. This has consequences for `fork()`, `unshare(CLONE_FS)`,
and `setns()`.

Instead, decompose root-switching into individually atomic, locally-scoped
steps:

```c
fd_tree = open_tree(-EBADF, "/newroot",
                    OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
fchdir(fd_tree);
move_mount(fd_tree, "", AT_FDCWD, "/",
           MOVE_MOUNT_BENEATH | MOVE_MOUNT_F_EMPTY_PATH);
chroot(".");
umount2(".", MNT_DETACH);
```

Since each step only modifies the caller's own state, the
`fork()`/`unshare()`/`setns()` races are eliminated by design.

To make this work, `MNT_LOCKED` is transferred from the top mount to the
mount beneath. The new mount takes over the job of protecting the parent
mount from being revealed. This also makes it possible to safely modify
an inherited mount table after `unshare(CLONE_NEWUSER | CLONE_NEWNS)`:

```sh
mount --beneath -t tmpfs tmpfs /proc
umount -l /proc
```

**Use-Case:** Containers created with `unshare(CLONE_NEWUSER | CLONE_NEWNS)`
can reshuffle an inherited mount table safely. `MOVE_MOUNT_BENEATH` on the
rootfs makes it possible to switch out the rootfs without the costly
`pivot_root(2)` and without cross-namespace vulnerabilities.
