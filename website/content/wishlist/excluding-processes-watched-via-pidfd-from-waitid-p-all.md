---
title: "Excluding processes watched via `pidfd` from `waitid(P_ALL, …)`"
weight: 110
status: wishlist
categories:
  - pidfd
  - processes
---

**Use-Case:** various programs use `waitid(P_ALL, …)` to collect exit
information of exited child processes. In particular PID 1 and
processes using `PR_SET_CHILD_SUBREAPER` use this as they may
collect unexpected children that have been reparented from dying
sub-processes, and that need to be reaped in order to clean up the
PID space. Currently, these programs cannot easily mix waiting for
specific sub-processes via `pidfd` with waiting for the other
*unexpected* children via `waitid(P_ALL, …)` since the latter also
reaps (and thus invalidates) the pidfd-tracked
children. Specifically, the `systemd` service manager would like
to use `pidfd`s to remove PID recycling security issues, but
currently cannot as it also needs to generically wait for such
unexpected children.
