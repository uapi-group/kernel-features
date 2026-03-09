---
title: "Mount notifications without rescanning of `/proc/self/mountinfo`"
weight: 70
status: completed
categories:
  - mounts
commit: "0f46d81f2bce"
---

[x] Mount notifications without rescanning of `/proc/self/mountinfo`

Mount notifications that do not require continuous rescanning of
`/proc/self/mountinfo`. Currently, if a program wants to track
mounts established on the system it can receive `poll()`able
events via a file descriptor to `/proc/self/mountinfo`. When
receiving them it needs to rescan the file from the top and
compare it with the previous scan. This is both slow and
racy. It's slow on systems with a large number of mounts as the
cost for re-scanning the table has to be paid for every change to
the mount table. It's racy because quickly added and removed
mounts might not be noticed.

**🙇 `0f46d81f2bce ("fanotify: notify on mount attach and detach")` 🙇**

**Use-Case:** `systemd` tracks the mount table to integrate the mounts
into it own dependency management.
