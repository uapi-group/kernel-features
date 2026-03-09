---
title: "`AT_EMPTY_PATH` support for `unlinkat()`"
weight: 290
status: wishlist
categories:
  - processes
---

**Use-Case:** When dealing with files/directories, allow passing
around only a file descriptor without having to keep the path around
to be able to unlink the file/directory.
