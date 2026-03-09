---
title: "`SCM_PIDFD` auxiliary socket message"
weight: 100
status: completed
categories:
  - pidfd
  - processes
  - sockets
commit: "5e2ff6704a27"
---

[x] `SCM_PIDFD` or similar auxiliary socket message, that is a modern
version of the `SCM_CREDS` message's `.pid` field, and provides a
`pidfd` file descriptor to the originating peer process.

**🙇 `5e2ff6704a275be00 ("scm: add SO_PASSPIDFD and SCM_PIDFD)")` 🙇**

**Use-Case:** security infrastructure (such as PolicyKit) can safely
reference clients this way without fearing PID
recycling. `systemd-journald` can acquire peer metadata this way in
a less racy fashion, in particular safe against PID recycling.
