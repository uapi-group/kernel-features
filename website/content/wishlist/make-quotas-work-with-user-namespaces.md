---
title: "Make quotas work with user namespaces"
weight: 180
status: wishlist
categories:
  - mounts
  - namespaces
  - security
---

The quota codepaths in the kernel currently broken and inconsistent
and most interesting operations are guarded behind
`capable(CAP_SYS_ADMIN)`, i.e., require `CAP_SYS_ADMIN` in the initial
user namespace. We should rework these codepaths to work with user
namespaces and then see whether we can make them work with idmapped
mounts.

**Use-Case:** using quotas correctly in containers.
