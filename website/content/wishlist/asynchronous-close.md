---
title: "Asynchronous `close()`"
weight: 120
status: wishlist
categories:
  - mounts
  - processes
  - sockets
---

An asynchronous or forced `close()`, that guarantees that
userspace doesn't have to risk blocking for longer periods of time
when trying to get rid of unwanted file descriptors, possibly
received via `recvmsg()` + `SCM_RIGHTS` (see above). Currently,
`close()` of various file descriptors (for example those referring
to slow storage, e.g. non-responding NFS servers and such) might
take arbitrary amounts of time, potentially into the minute range
and more. This makes it risky accepting file descriptors on
publicly accessible `AF_UNIX` sockets, the way like IPC brokers
(e.g. D-Bus) do it: if a rogue client keeps sending file
descriptors that because unexpected must be closed immediately it
might cause the receiving process to effectively crawl, when it is
busy closing them all. A special form of `close()` that simply
detaches a file descriptor from the file descriptor table without
blocking on IO in any form would be great to close this issue.

**Use-Case:** any program that receives file descriptors via `AF_UNIX`
from untrusted clients would benefit from this. e.g. D-Bus
brokers.
