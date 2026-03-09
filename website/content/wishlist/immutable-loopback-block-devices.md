---
title: "Immutable loopback block devices"
weight: 140
status: wishlist
categories:
  - block-devices
  - filesystems
  - mounts
---

Truly immutable loopback block devices. Right now setting up a
loopback block device in read-only mode, backed by a read-only
file (stored on a regular read/write file system), and then
mounting it with `ext4` also in `MS_RDONLY`mode *will* result in
changes to the file, quite unexpectedly 🤯. Ideally, if a loopback
block device is set up in read-only mode this should guarantee
that the backing file remains unmodified by it.

**Use-Case:** disk image build tools that want to reproducibly and
verifiable build images must be able to rely that mounting them in
read-only mode does not alter the images in any way. In particular
when working in computer forensics one must be able to rely that
file systems that are analyzed remain unmodified by the analysis.
