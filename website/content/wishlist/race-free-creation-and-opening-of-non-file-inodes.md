---
title: "Race-free creation and opening of non-file inodes"
weight: 230
status: wishlist
categories:
  - filesystems
  - sockets
---

A way to race-freely create an (non-file) inode and immediately
open it. For regular files we have open(O_CREAT) for creating a
new file inode, and returning a pinning fd to it. This is missing
for other inode types, such as directories, device nodes,
FIFOs. The lack of such functionality means that when populating a
directory tree there's always a race involved: the inodes first
need to be created, and then opened to adjust their
permissions/ownership/labels/timestamps/acls/xattrs/…, but in the
time window between the creation and the opening they might be
replaced by something else. Addressing this race without proper
APIs is possible (by immediately fstat()ing what was opened, to
verify that it has the right inode type), but difficult to get
right. Hence, mkdirat_fd() that creates a directory *and* returns
an O_DIRECTORY fd to it would be great. As would be mknodeat_fd()
that creates a device node, FIFO or (dead) socket and returns an
O_PATH fd to it. And of course symlinkat_fd() that creates a
symlink and returns an O_PATH fd to it.

**Use-Case:** any program that creates/unpacks not just files, but
directories, device nodes, fifos, and wants to ensure that they
safely get the right attributes applied, even if other code might
simultaneously have access to the same directory tree.
