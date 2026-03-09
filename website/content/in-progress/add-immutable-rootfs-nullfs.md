---
title: "Add immutable rootfs (`nullfs`)"
weight: 50
status: in-progress
categories:
  - filesystems
  - mounts
  - namespaces
  - processes
  - security
---

Currently `pivot_root()` doesn't work on the real rootfs because it
cannot be unmounted. Userspace has to do a recursive removal of the
initramfs contents manually before continuing the boot.

Add an immutable rootfs called `nullfs` that serves as the parent mount
for anything that is actually useful such as the tmpfs or ramfs for
initramfs unpacking or the rootfs itself. The kernel mounts a
tmpfs/ramfs on top of it, unpacks the initramfs and fires up userspace
which mounts the rootfs and can then simply do:

```c
chdir(rootfs);
pivot_root(".", ".");
umount2(".", MNT_DETACH);
```

This also means that the rootfs mount in unprivileged namespaces doesn't
need to become `MNT_LOCKED` anymore as it's guaranteed that the
immutable rootfs remains permanently empty so there cannot be anything
revealed by unmounting the covering mount.

**Use-Case:** Simplifies the boot process by enabling `pivot_root()` to
work directly on the real rootfs. Removes the need for traditional
`switch_root` workarounds. In the future this also allows us to create
completely empty mount namespaces without risking to leak anything.
