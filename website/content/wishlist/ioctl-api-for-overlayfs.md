---
title: "`ioctl()` API for `overlayfs`"
weight: 350
status: wishlist
categories:
  - block-devices
  - filesystems
---

`overlayfs` should have an `ioctl()`-based API (or similar) for
querying information of the backing file systems/block devices

**Use-Case:** In systemd in various areas we automatically find the
block device backing the root file system and other file systems
(Example: `systemd-gpt-auto-generator` or `bootctl` wull try to find
auxiliary file systems of the OS image by looking in the GPT
partition table the root file system is located in). While this
logic is good enough to find the backing block devices of some more
complex storage such as dm-crypt, dm-verity or btrfs, once
`overlayfs` is used as backing for the root file system this logic
does not work anymore. It would be great if there was an API to
simply query `overlayfs` for the superblock information
(i.e. `.st_dev`) of the backing layers.
