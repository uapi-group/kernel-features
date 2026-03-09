---
title: "Map different uids/gids to the same uids/gids?"
weight: 250
status: wishlist
categories:
  - filesystems
  - mounts
---

Explore the idea of mapping different uids/gids to the same uids/gids, i.e.
65534:1000:1 50000:1000:1. This will only work if the mount is read-only as
the kernel wouldn't know what uid/gid would need to be put to disk
otherwise (65534? 50000? the first one that is mapped?).

**Use-Case:** Delegate multiple {g,u}ids to the same user. Merging
ownership similar to how overlayfs merges files. Bindfs
(https://bindfs.org/docs/bindfs.1.html#sect3) allows this concept too.
