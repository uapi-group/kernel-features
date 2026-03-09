---
title: "Useful handling of LSM denials on SCM_RIGHTS"
weight: 390
status: wishlist
categories:
  - security
  - sockets
---

Right now if some LSM such as SELinux denies an `AF_UNIX` socket peer
to receive an `SCM_RIGHTS` fd the `SCM_RIGHTS` fd array will be cut
short at that point, and `MSG_CTRUNC` is set on return of
`recvmsg()`. This is highly problematic behaviour, because it leaves
the receiver wondering what happened. As per man page `MSG_CTRUNC` is
supposed to indicate that the control buffer was sized too short, but
suddenly a permission error might result in the exact same flag being
set. Moreover, the receiver has no chance to determine how many fds
got originally sent and how many were suppressed.

Ideas how to improve things:

1. Maybe introduce a new flag `MSG_RIGHTS_DENIAL` or so which is set
   on `recvmsg()` return, which tells us that fds where dropped from
   the `SCM_RIGHTS` array because of an LSM error. This new flag could
   be set in addition to `CMSG_CTRUNC`, for compatibility.

2. Maybe, define a new flag `MSG_RIGHTS_FILTER` or so which when
   passed to `recvmsg()` will ensure that the `SCM_RIGHTS` fd array is
   always passed through in its full, original size. Entries for which
   an LSM says no are suppressed, and replaced by a special value, for
   example `-EPERM`.

3. It would be good if the relevant man page would at least document
   this pitfall, even if it right now cannot reasonably be handled.

Ideally both ideas would be implemented, but of course, strictly
speaking the 2nd idea makes the 1st idea half-way redundant.

**Use-Case:** Any code that uses `SCM_RIGHTS` generically (D-Bus and
so on) needs this, so that it can reasonably handle SELinux AVC errors
on received messages.
