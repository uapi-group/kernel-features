---
title: "Ability to reopen a `struct block_device`"
weight: 310
status: wishlist
categories:
  - filesystems
  - mounts
---

Add ability to reopen a `struct block_device`. This would allow using
`blkdev_get_by_path()`/`blkdev_get_{part,whole}()` to claim a device
with `BLK_OPEN_READ` and later on reopen with
`BLK_OPEN_READ | BLK_OPEN_WRITE`. This in turn would opening block
devices at `fsconfig(FS_CONFIG_SET_*)` time and then at `fill_super()`
time we would be able to reopen in case the `!(fc->sb_flags & SB_RDONLY)`.
Overall this has the effect that we're able to open devices early
giving the user early errors when they set mount options rather than
very late when the superblock is created.
