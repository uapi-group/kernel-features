---
title: "Query mount information via file descriptor with `statmount()`"
weight: 70
status: in-progress
categories:
  - mounts
  - namespaces
---

Extend `struct mnt_id_req` to accept a file descriptor and introduce
`STATMOUNT_BY_FD` flag. When a valid fd is provided and `STATMOUNT_BY_FD`
is set, `statmount()` returns mount info about the mount the fd is on.

This works even for "unmounted" mounts (mounts that have been unmounted using
`umount2(mnt, MNT_DETACH)`), if you have access to a file descriptor on that
mount. These unmounted mounts will have no mountpoint and no valid mount
namespace, so `STATMOUNT_MNT_POINT` and `STATMOUNT_MNT_NS_ID` are unset in
`statmount.mask` for such mounts.

**Use-Case:** Query mount information directly from a file descriptor without
needing the mount ID, which is particularly useful for detached or unmounted
mounts.
