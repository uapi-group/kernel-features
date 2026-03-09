---
title: "Add process by PIDFD to a cgroup"
weight: 370
status: wishlist
categories:
  - cgroups
  - pidfd
  - processes
  - sockets
---

At the moment the canonical way to add a process to a cgroup is by
echoing its PID into the `cgroup.procs` attribute in the target
cgroupfs directory of the cgroup. This is safe as long as the
process doing so just forked off the process it wants to migrate and
hence can control that it hasn't been reaped yet, and hence
guarantees the PID is valid. This is racy however if "foreign"
processes shall be moved into the cgroup.

**Use-Case:** In systemd, all user sessions are wrapped in scope
units which are backed by a cgroup. The session processes moved into
the scope unit are typically "foreign" processes, i.e. not children
of the service manager, hence doing the movement is subject to races
in case the process dies and its PID is quickly recycled. (This
assumes systemd can acquire a pidfd of the foreign process without
races, for example via `SCM_PIDFD` and `SO_PEERPIDFD` or similar.)
