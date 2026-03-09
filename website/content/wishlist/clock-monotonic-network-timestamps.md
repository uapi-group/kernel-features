---
title: "`CLOCK_MONOTONIC` network timestamps"
weight: 130
status: wishlist
categories:
  - sockets
---

Currently network timestamps are exclusively in `CLOCK_REALTIME`, even
though for many (most?) a monotonic clock would be much preferable, as
calculations become easier when one doesn't have to think about clock
jumps and similar.

**Use-Case:** `systemd-journald` collects implicit timestamps via
`AF_UNIX` time-stamping, in `CLOCK_REALTIME`, even though for its
internal logic only monotonic timestamps are used, as log records
are searched via bisection in ordered tables, that require
strictly increasing timestamps. In particular during boot (where
`CLOCK_REALTIME` is often not available, stable or subject to
corrections) it would be good to have reliable, monotonic
timestamps on all log records.
