---
title: "Reasonable EOF on SOCK_SEQPACKET"
weight: 400
status: wishlist
categories:
  - sockets
---

Zero size datagrams cannot be distinguished from EOF on
`SOCK_SEQPACKET`. Both will cause `recvmsg()` to return zero.

Idea how to improve things: maybe define a new MSG_XYZ flag for this,
which causes either of the two cases result in some recognizable error
code returned rather than a 0.

**Use-Case:** Any code that wants to use `SOCK_SEQPACKET` and cannot
effort disallowing zero sized datagrams from their protocol.
