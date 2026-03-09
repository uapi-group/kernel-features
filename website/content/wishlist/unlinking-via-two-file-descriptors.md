---
title: "Unlinking via two file descriptors"
weight: 70
status: wishlist
categories:
  - filesystems
  - processes
---

`unlinkat3(dir_fd, name, inode_fd)`: taking one file descriptor
for the directory to remove a file in, and another one referring
to the inode of the filename to remove. This call should only
succeed if the specified filename still refers to the specified
inode.

**Use-Case:** code that operates on a well-know path that might be
shared by multiple programs that jointly manage it might want to
safely remove a filename under the guarantee it still refers to
the expected inode. As a specific example, consider lock files,
that should be cleaned up only if they still refer to the assumed
owner's instance, but leave the file in place if another process
already took over the filename.
