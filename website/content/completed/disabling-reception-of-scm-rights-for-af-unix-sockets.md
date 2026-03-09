---
title: "Disabling reception of `SCM_RIGHTS` for `AF_UNIX` sockets"
weight: 180
status: completed
categories:
  - processes
  - sockets
commit: "77cbe1a6d873"
---

[x] Ability to turn off `SCM_RIGHTS` reception for `AF_UNIX`
sockets.

**🙇 `77cbe1a6d8730a07f99f9263c2d5f2304cf5e830 ("af_unix: Introduce SO_PASSRIGHTS")` 🙇**

Right now reception of file descriptors is always on when
a process makes the mistake of invoking `recvmsg()` on such a
socket. This is problematic since `SCM_RIGHTS` installs file
descriptors in the recipient process' file descriptor
table. Getting rid of these file descriptors is not necessarily
easy, as they could refer to "slow-to-close" files (think: dirty
file descriptor referring to a file on an unresponsive NFS server,
or some device file descriptor), that might cause the recipient to
block for a longer time when it tries to them. Programs reading
from an `AF_UNIX` socket currently have three options:

1. Never use `recvmsg()`, and stick to `read()`, `recv()` and
   similar which do not install file descriptors in the recipients
   file descriptor table.

2. Ignore the problem, and simply `close()` the received file descriptors
   it didn't expect, thus possibly locking up for a longer time.

3. Fork off a thread that invokes `close()`, which mitigates the
   risk of blocking, but still means a sender can cause resource
   exhaustion in a recipient by flooding it with file descriptors,
   as for each of them a thread needs to be spawned and a file
   descriptor is taken while it is in the process of being closed.

(Another option of course is to never talk `AF_UNIX` to peers that
are not trusted to not send unexpected file descriptors.)

A simple knob that allows turning off `SCM_RIGHTS` right reception
would be useful to close this weakness, and would allow
`recvmsg()` to be called without risking file descriptors to be
installed in the file descriptor table, and thus risking a
blocking `close()` or a form of potential resource exhaustion.

**Use-Case:** any program that uses `AF_UNIX` sockets and uses (or
would like to use) `recvmsg()` on it (which is useful to acquire
other metadata). Example: logging daemons that want to collect
timestamp or `SCM_CREDS` auxiliary data, or the D-Bus message
broker and suchlike.
