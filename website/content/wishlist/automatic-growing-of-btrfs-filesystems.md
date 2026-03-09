---
title: "Automatic growing of `btrfs` filesystems"
weight: 360
status: wishlist
categories:
  - block-devices
  - filesystems
---

An *auto-grow* feature in `btrfs` would be excellent.

If such a mode is enabled, `btrfs` would automatically grow a file
system up to the size of its backing block devices. Example: btrfs
is created with 200M in size on a block device 2G in size. Once the
file system is filled up fully, `btrfs` would automatically grow the
file system as need in the increments it needs, up to the 2G that
the backing block device is in size.

**Use-Case:** This would allow creating minimal, compact file
systems: just create them small on a sparse block device, and copy
files into it, as needed, create subvolumes and whatever else is
desired. As long as only files are created and written (but not
modified) the resulting fs should be automatically minimal in size.
This would specifically be useful in `systemd-homed`, which
maintains per-user `btrfs` file systems backed by block
devices. Currently, `homed` grows the file systems manually on login
and then shrinks them again on logout, but this is less than ideal,
since btrfs places files all over the backing store, and thus the
shrinking will generate a lot of nonsensical IO that could be
reduced if the file system was always kept minimal in size anyway.
