---
title: "xattrs for pidfd"
weight: 10
status: wishlist
categories:
  - filesystems
  - pidfd
---

Since pidfds have been moved to a separate pidfs filesystem it is easy
to add support for xattrs on pidfds. That could be valuable to store
meta information along the pidfd. Storing an xattr should probably make
the pidfd automatically persistent, i.e., the reference for the dentry
is only put once the task is reaped.

**Use-Case:** Store meta information alongside pidfds.
