---
title: "Ability to put user xattrs on `S_IFSOCK` socket entrypoint inodes in the file system"
weight: 20
status: in-progress
categories:
  - filesystems
  - mounts
  - namespaces
  - sockets
---

Currently, the kernel only allows extended attributes in the
`user.*` namespace to be attached to directory and regular file
inodes. It would be tremendously useful to allow them to be
associated with socket inodes, too.

**Use-Case:** There are two syslog RFCs in use today: RFC3164 and
RFC5424. `glibc`'s `syslog()` API generates events close to the
former, but there are programs which would like to generate the
latter instead (as it supports structured logging). The two formats
are not backwards compatible: a client sending RFC5424 messages to a
server only understanding RFC3164 will cause an ugly mess. On Linux
there's only a single `/dev/log` AF_UNIX/SOCK_DGRAM socket backing
`syslog()`, which is used in a one-way, fire-and-forget style. This
means that feature negotation is not really possible within the
protocol. Various tools bind mount the socket inode into `chroot()`
and container environments, hence it would be fantastic to associate
supported feature information directly with the inode (and thus
outside of the protocol) to make it easy for clients to determine
which features are spoken on a socket, in a way that survives bind
mounts. Implementation idea would be that syslog daemons
implementing RFC5425 could simply set an xattr `user.rfc5424` to `1`
(or something like that) on the socket inode, and clearly inform
clients in a natural and simple way that they'd be happy to parse
the newer format. Also see:
https://github.com/systemd/systemd/issues/19251 – This idea could
also be extended to other sockets and other protocols: by setting
some extended attribute on a socket inodes, services could advertise
which protocols they support on them. For example D-Bus sockets
could carry `user.dbus` set to `1`, and Varlink sockets
`user.varlink` set to `1` and so on.
