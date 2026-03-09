---
title: "Auxiliary socket message describing the sender's cgroup"
weight: 40
status: wishlist
categories:
  - cgroups
  - sockets
---

`SCM_CGROUPID` or a similar auxiliary socket message, that allows
receivers to figure out which cgroup a sender is part of.

**Use-Case:** `systemd-journald` picks up cgroup information from
logging clients, in order to augment log records and allow
filtering via this meta-information. In particular it derives
service identity from that (so that requests such as "Show me all
log messages of service X!" can be answered). This is currently
racy, since it uses `SCM_CREDS`' `.pid` field for this, which it then
used to load `/proc/$PID/cgroup`. In particular for programs that
log and immediately exit, the cgroup information frequently cannot
be acquired anymore by `systemd-journald`.
