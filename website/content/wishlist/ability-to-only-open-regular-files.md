---
title: "Ability to only open regular files"
weight: 60
status: wishlist
categories:
  - mounts
---

`O_REGULAR` (inspired by the existing `O_DIRECTORY` flag for
`open()`), which opens a file only if it is of type `S_IFREG`.

**Use-Case:** this would be very useful to write secure programs
that want to avoid being tricked into opening device nodes with
special semantics while thinking they operate on regular
files. This is particularly relevant as many device nodes (or even
FIFOs) come with blocking I/O (or even blocking `open()`!) by
default, which is not expected from regular files backed by "fast"
disk I/O. Consider implementation of a naive web browser which is
pointed to `file://dev/zero`, not expecting an endless amount of
data to read.
