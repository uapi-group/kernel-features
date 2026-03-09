---
title: "Mount a subdirectory instead of the top-level directory"
weight: 80
status: completed
categories:
  - filesystems
  - mounts
  - namespaces
commit: "c5c12f871a30"
---

[x] Mount a subdirectory instead of the top-level directory

Ability to mount a subdirectory of a regular file system instead of
the top-level directory. E.e. for a file system `/dev/sda1` which
contains a sub-directory `/foobar` mount `/foobar` without having
to mount its parent directory first. Consider something like this:

```
mount -t ext4 /dev/sda1 somedir/ -o subdir=/foobar
```

(This is of course already possible via some mount namespacing
shenanigans, but this requires namespacing to be available, and is
not precisely obvious to implement. Explicit kernel support at mount
time would be much preferable.)

**🙇 `c5c12f871a30 ("fs: create detached mounts from detached mounts")` 🙇**

**Use-Case:** `systemd-homed` currently mounts a sub-directory of
the per-user LUKS volume as the user's home directory (and not the
root directory of the per-user LUKS volume's file system!), and in
order to implement this invisibly from the host side requires a
complex mount namespace exercise.
