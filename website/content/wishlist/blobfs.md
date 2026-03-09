---
title: "blobfs"
weight: 260
status: wishlist
categories:
  - filesystems
---

[`blobfs`](https://fuchsia.dev/fuchsia-src/concepts/filesystems/blobfs)
for Linux. i.e. a minimalistic file system, that can store
authenticated (Verity) data files, that can be written once, and
not be modified after that, and provide stable handles (i.e. is
content-addressable) to them.

**Use-Case:** This would deliver just about enough to place
trusted OS resources (binaries, kernels, initrds, fs trees, other
resources) in them, without having to trust the medium and IO
underneath. Should be simple enough to even implement in a boot
loader and similar, without making things vulnerable to rogue file
system image attacks. The OS and its payloads (apps, containers,
…) could then be composed from these resources, through means like
overlayfs, namespacing and more.
