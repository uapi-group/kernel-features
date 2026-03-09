---
title: "Upgrade masks in `openat2()`"
weight: 170
status: wishlist
categories:
  - security
---

Add upgrade masks to `openat2()`. Extend `struct open_how` to allow
restrict re-opening of file descriptors.

**Use-Case:** block services or containers from re-opening/upgrading an
`O_PATH` file descriptor through e.g. `/proc/<pid>/fd/<nr` as `O_WRONLY`.
