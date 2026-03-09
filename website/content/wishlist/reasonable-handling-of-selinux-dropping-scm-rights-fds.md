---
title: "Reasonable Handling of SELinux dropping SCM_RIGHTS fds"
weight: 410
status: wishlist
categories:
  - sockets
---

Currently, if SELinux refuses to let some file descriptor through, it
will just drop them from the `SCM_RIGHTS` array. That's a terrible
idea, since applications rely on the precise arrangement of the array
to know which fd is which. By dropping entries silently, these apps
will all break.

Idea how to improve things: leave the elements in the array in place,
but return a marker instead (i.e. negative integer, maybe `-EPERM`) that
tells userspace that there was an fd, but it was not allowed through.

**Use-Case:** Any code that wants to use `SCM_RIGHTS` properly.
