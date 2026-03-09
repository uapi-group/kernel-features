---
title: "Additional identifiers for pidfds in `statx()`"
weight: 150
status: completed
categories:
  - pidfd
  - processes
commit: "cb12fd8e0dab"
---

[x] Make `statx()` on a pidfd return additional recognizable identifiers
in `.stx_ino`.

**🙇 `cb12fd8e0dabb9a1c8aef55a6a41e2c255fcdf4b pidfd: add pidfs` 🙇**

It would be fantastic if issuing statx() on any pidfd would return some
reasonably stable 64bit identifier for the process in `.stx_ino`. This would
be perfect to identify processes pinned by a pidfd, and compare them.
