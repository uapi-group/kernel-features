---
title: "Per-cgroup limit for coredump sizes"
weight: 220
status: wishlist
categories:
  - cgroups
  - processes
---

A per-cgroup knob for coredump sizes. Currently coredump size
control is strictly per process, and primarily under control of
the processes themselves. It would be good if we had a per-cgroup
knob instead, that is under control of the service manager.

**Use-Case:** coredumps can be heavy to generate. For different
usecases it would be good to be able to opt-in or opt-out
dynamically from coredumps for specific services, at runtime
without restarting them.
