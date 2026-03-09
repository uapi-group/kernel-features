---
title: "Race-free mounting of block devices"
weight: 300
status: wishlist
categories:
  - block-devices
  - filesystems
  - mounts
---

Introduce a new struct to `fsconfig()` as an alternative to the
`source` property. The struct contains at least a pointer to a path,
possibly a device minor and major, and a diskseq number. The VFS can
expose a helper that filesystems can call and use the diskseq number
to verify that the block device they are intending to mount is indeed
the one they want to mount.

**Use-Case:** Race-free mounting of block devices.
