---
title: "inotify() events for BSD file locks"
weight: 30
status: wishlist
categories:
  - block-devices
  - filesystems
---

BSD file locks (i.e. `flock()`, as opposed to POSIX `F_SETLK` and
friends are inode-focussed, hence would be great if one could get
asynchronous notification when they are released via inotify.

**Use-Case:** udevd probes block devices whenever they pop up to
create /dev/disk/by-label/* and similar symlinks. Formatting tools
can temporarily block this behaviour by taking a BSD file lock on
the block device (as per https://systemd.io/BLOCK_DEVICE_LOCKING),
in order to make sure udevd doesn't probe file systems/partition
tables that are only partially initialized. Currently, udevd uses
inotify `IN_CLOSE_WRITE` notifications to detect whenever
applications close a block device after writing to it, and
automatically reprobes the device. This works reasonably OK given
that block devices are usually closed at the same time as their
BSD file lock is released, and vice versa. However, this is not
fully correct: what udevd actually should be watching is the locks
being released, not the devices being closed.
