---
title: "Unmounting of obstructed mounts"
weight: 90
status: completed
categories:
  - filesystems
  - mounts
commit: "6ac392815628"
---

[x] ability to unmount obstructed mounts. (this means: you have a stack
of mounts on the very same inode, and you want to remove a mount in
the middle. right now, you can only remove the topmost mount.)

**🙇 instead of the ability to unmount obstructured mounts we gained
the ability to mount beneath an existing mount, with mostly
equivalent outcome. `6ac392815628f317fcfdca1a39df00b9cc4ebc8b
("fs: allow to mount beneath top mount")` 🙇**

**use-case:** this is useful for replacing mounts atomically, for
example for upgrading versioned disk images: first an old version
of the image is mounted. then a new version is mounted over the
existing mount point, and then the lower mount point is
removed. One such software would be `systemd-sysext`.
