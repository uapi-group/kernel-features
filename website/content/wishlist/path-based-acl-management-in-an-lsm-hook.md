---
title: "Path-based ACL management in an LSM hook"
weight: 330
status: wishlist
categories:
  - filesystems
  - mounts
  - security
---

The LSM module API should have the ability to do path-based (not
just inode-based) ACL management.

**Use-Case:** This would be useful in BPF-LSM modules such as
systemd's `mntfsd` which allows unprivileged file system mounts in
some cases, and which would like to restrict ACL handling based on
the superblock involved.
