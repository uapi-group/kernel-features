---
title: "Determining if a mount point belongs to the current user"
weight: 80
status: wishlist
categories:
  - mounts
  - namespaces
  - processes
---

Ability to determine if a mount point belongs to the current user
namespace, in order to check if there's a chance a process can
safely unmount it (as that only works for mounts owned by the same
user namespaces — or one further down the tree, but not any up the
tree). A simple, additional field in `/proc/self/mountinfo`
container the owning user namespace ID would probably already
suffice.

**Use-Case:** the `systemd` system and service manager tries to unmount
all established mounts on shutdown. Inside of container
environments where specific mounts are established by the
container manager (and not the payload itself) this will
ultimately fail if user namespaces are enabled. In order to clean
up the shutdown logic it would be very good to be able to
determine whether a specific mount could even possibly be
unmounted or whether it's not worth the effort to include the
unmount in the system shutdown transaction.
