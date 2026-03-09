---
title: "Require a user namespace to have an idmapping when attached"
weight: 60
status: completed
categories:
  - mounts
  - namespaces
commit: "dacfd001eaf2"
---

[x] Require a user namespace to have an idmapping when attached

Enforce that the user namespace about to be attached to a mount must
have an idmapping written.

**🙇 `dacfd001eaf2 ("fs/mnt_idmapping.c: Return -EINVAL when no map is written")` 🙇**

**Use-Case:** Tighten the semantics.
