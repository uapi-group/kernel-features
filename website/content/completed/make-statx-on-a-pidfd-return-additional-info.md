---
title: "Make statx() on a pidfd return additional info"
weight: 40
status: completed
categories:
  - pidfd
  - processes
commit: "cb12fd8e0dab"
---

Make statx() on a pidfd return additional recognizable identifiers in
`.stx_btime`.

**🙇 `cb12fd8e0dabb9a1c8aef55a6a41e2c255fcdf4b pidfd: add pidfs` 🙇**

It would be fantastic if issuing statx() on any pidfd would return
the start time of the process in `.stx_btime` even after the process
died.

These fields should in particular be queriable *after* the process
already exited and has been reaped, i.e. after its PID has already
been recycled.

**Use-Case:** In systemd we maintain lists of processes in a hash
table. Right now, the key is the PID, but this is less than ideal
because of PID recycling. By being able to use the `.stx_btime`
and/or `.stx_ino` fields instead would be perfect to safely
identify, track and compare process even after they ceased to exist.
