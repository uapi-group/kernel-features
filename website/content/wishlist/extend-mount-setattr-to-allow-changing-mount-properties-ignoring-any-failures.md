---
title: "Extend `mount_setattr()` to allow changing mount properties ignoring any failures"
weight: 160
status: wishlist
categories:
  - mounts
---

**Use-Case:** workloads that know that there are mounts in a mount tree
whose attributes cannot be changed by the caller don't want
`mount_settattr()` to fail on the first mount it failed to convert. Give
them a flag to request changes ignoring failures.
