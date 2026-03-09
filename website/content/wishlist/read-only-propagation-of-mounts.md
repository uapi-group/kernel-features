---
title: "Read-only propagation of mounts"
weight: 90
status: wishlist
categories:
  - mounts
  - namespaces
---

A way to mark mounts that receive mount propagation events from
elsewhere so that these propagated mounts are established
read-only implicitly. Right now, if a mount receives a mount
propagation event it will have the exact same `MS_RDONLY`,
`MS_NODEV`, … flags as it has where it originated. It would be
very useful if an `MS_RDONLY` could be ORed into the mount flags
automatically whenever propagated elsewhere.

**Use-Case:** various mount namespace based sandboxes
(e.g. `systemd`'s `ProtectSystem=` option) mark large parts of the
host file hierarchy read-only via mounting it
`MS_RDONLY|MS_BIND|MS_REMOUNT`, but generally intend to leave the
file hierarchy besides that the way it is, and that includes they
typically still want to be able to receive mount events to
directories such as `/mnt/` and `/media/` in these sandboxed
environments. Right now, any such propagation then happens in
writable mode, even if the file hierarchy otherwise is almost
entirely read-only. To close this gap it would be great if such
propagated mounts could implicitly gain `MS_RDONLY` as they are
propagated.
