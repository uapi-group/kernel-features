---
title: "A system call to query information about a mount"
weight: 120
status: completed
categories:
  - block-devices
  - mounts
  - namespaces
commit: "46eae99ef733"
---

[x] Implement a mount-specific companion to `statx()` that puts at least the
following information into `struct mount_info`:

**🙇 `46eae99ef73302f9fb3dddcd67c374b3dffe8fd6 ("add statmount(2) syscall")` 🙇**

* mount flags: `MOUNT_ATTR_RDONLY`, ...
* time flags: `MOUNT_ATTR_RELATIME`, ...
  Could probably be combined with mount flags.
* propagation setting: `MS_SHARED)`, ...
* peer group
* mnt id of the mount
* mnt id of the mount's parent
* owning userns

There's a bit more advanced stuff systemd would really want but which
I think is misplaced in a mountinfo system call including:
* list of primary and auxiliary block device major/minor
* diskseq value of those device nodes (This is a new block device feature
  we added that allows preventing device recycling issues when e.g.
  removing usb devices very quickly and is needed for udev.)
* uuid/fsid
* feature flags (`O_TMPFILE`, `RENAME_EXCHANGE` supported etc.)

**Use-Case:** low-level userspace tools have to interact with advanced
mount information constantly. This is currently costly and brittel because
they have to go and parse `/proc/<pid>/mountinfo`.
