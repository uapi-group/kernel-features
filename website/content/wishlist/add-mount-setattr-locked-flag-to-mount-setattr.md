---
title: "Add `MOUNT_SETATTR_LOCKED` flag to `mount_setattr()`"
weight: 190
status: wishlist
categories:
  - mounts
  - namespaces
  - processes
  - security
---

Add a new `MOUNT_SETATTR_LOCKED` flag to `mount_setattr(..., ..., MOUNT_SETATTR_LOCKED, ..., ...)`.
The `MOUNT_SETATTR_LOCKED` flag allow a `ns_capable(mntns->user_ns,
CAP_SYS_ADMIN)` caller to lock all mount properties. The mount properties
cannot be changed anymore.

**Use-Case:** allowing processes to lock mount properties even for
privileged processes. Locking mount properties would currently involve
having to have the mount namespace of the container be owned by an ancestor
user namespace. But this doesn't just lock a single mount or mount subtree
it locks all mounts in the mount namespace, i.e., the mount table cannot be
altered.
