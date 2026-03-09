---
title: "Namespace ioctl to translate a PID between PID namespaces"
weight: 10
status: completed
categories:
  - namespaces
  - processes
commit: "ca567df74a28"
---

[x] Namespace ioctl to translate a PID between PID namespaces

**🙇 `ca567df74a28a9fb368c6b2d93e864113f73f5c2 ("nsfs: add pid translation ioctls")` 🙇**

**Use-Case:** This makes it possible to e.g., figure out what a given PID in
a PID namespace corresponds to in the caller's PID namespace. For example, to
figure out what the PID of PID 1 inside of a given PID namespace is.
