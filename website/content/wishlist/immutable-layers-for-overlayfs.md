---
title: "Immutable layers for `overlayfs`"
weight: 340
status: wishlist
categories:
  - filesystems
---

`overlayfs` should permit *immutable* layers, i.e. layers whose
non-directory inodes may not be overriden in an upper writable
layer.

**Use-Case:** This would be useful when implementing `/etc/` as a
stack of overlayfs layers, each shipping configuration for a
different facet of the system, with a writable layer on the top for
local modifications. In such a scenario it would be useful to allow
the user to change any configuration it likes, except of the files
and other inodes shipped in the lower layers.
