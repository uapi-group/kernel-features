---
title: "Extend `setns()` to allow attaching to all new namespaces of a process"
weight: 200
status: wishlist
categories:
  - namespaces
  - pidfd
  - processes
---

Add an extension to `setns()` to allow attaching to all namespaces of
a process `SETNS_PIDFD_ALL` different from the caller's namespaces.
Currently specifying e.g., `CLONE_NEWUSER` fails if the caller is in the
same user namespace as the target process. This is very inconvenient.

**Use-Case:** Make it trivial to attach to all namespaces of a process
without having to figure out whether the caller is already in the same
namespace or not.
