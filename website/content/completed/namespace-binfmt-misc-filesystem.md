---
title: "Namespace `binfmt_misc` filesystem"
weight: 160
status: completed
categories:
  - filesystems
  - mounts
  - namespaces
commit: "21ca59b365c0"
---

[x] Make the `binfmt_misc` filesystem namespaced.

**🙇 `21ca59b365c0 ("binfmt_misc: enable sandboxed mounts")` 🙇**

**Use-Case:** Allow containers and sandboxes to register their own binfmt
handlers.
