---
title: "Filtering on received file descriptors"
weight: 100
status: wishlist
categories:
  - filesystems
  - sockets
---

An alternative to the previous item could be if some form of filtering
could be enforced on the file descriptors suitable for enqueuing on
the `AF_UNIX` socket. i.e. allow filtering by superblock type or
similar, so that policies such as "only `memfd`s are OK to be
received" may be expressed. (BPF?).

**Use-Case:** as above.
