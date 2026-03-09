---
title: "Specification of a keyring for dm-verity volume verification"
weight: 320
status: wishlist
categories:
  - block-devices
---

When activating a dm-verity volume allow specifying keyring to
validate root hash signature against.

**Use-Case:** In systemd, we'd like to authenticate Portable Service
images, system extension images, configuration images, container
images with different keys, as they typically originate from
different sources and it should not be possible to generate a
system extension with a key pair that is supposed to be good for
container images only.
