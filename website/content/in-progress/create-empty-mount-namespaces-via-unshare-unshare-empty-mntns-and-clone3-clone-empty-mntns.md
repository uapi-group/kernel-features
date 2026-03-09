---
title: "Create empty mount namespaces via `unshare(UNSHARE_EMPTY_MNTNS)` and `clone3(CLONE_EMPTY_MNTNS)`"
weight: 10
status: in-progress
categories:
  - filesystems
  - mounts
  - namespaces
  - processes
---

Now that we have support for `nullfs` it is trivial to allow the
creation of completely empty mount namespaces, i.e., mount namespaces
that only have the `nullfs` mount located at it's root.

**Use-Case:** This allows to isolate tasks in completely empty mount
namespaces. It also allows the caller to avoid copying its current mount
table which is useless in the majority of container workload cases.
