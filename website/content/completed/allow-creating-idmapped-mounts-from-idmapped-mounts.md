---
title: "Allow creating idmapped mounts from idmapped mounts"
weight: 50
status: completed
categories:
  - filesystems
  - mounts
  - namespaces
  - security
commit: "c4a16820d901"
---

[x] Allow creating idmapped mounts from idmapped mounts

Add a new `OPEN_TREE_CLEAR` flag to `open_tree()` that can only be
used in conjunction with `OPEN_TREE_CLONE`. When specified it will clear
all mount properties from that mount including the mount's idmapping.
Requires the caller to be `ns_capable(mntns->user_ns)`. If idmapped mounts
are encountered the caller must be `ns_capable(sb->user_ns, CAP_SYS_ADMIN)`
in the filesystems user namespace.

Locked mount properties cannot be changed. A mount's idmapping becomes
locked if it propagates across user namespaces.

This is useful to get a new, clear mount and also allows the caller to
create a new detached mount with an idmapping attached to the mount. Iow,
the caller may idmap the mount afterwards.

**🙇 `c4a16820d901 ("fs: add open_tree_attr()")` 🙇**

**Use-Case:** A user may already use an idmapped mount for their home
directory. And once a mount has been idmapped the idmapping cannot be
changed anymore. This allows for simple semantics and allows to avoid
lifetime complexity in order to account for scenarios where concurrent
readers or writers might still use a given user namespace while it is about
to be changed.
But this poses a problem when the user wants to attach an idmapping to
a mount that is already idmapped. The new flag allows to solve this
problem. A sufficiently privileged user such as a container manager can
create a user namespace for the container which expresses the desired
ownership. Then they can create a new detached mount without any prior
mount properties via OPEN_TREE_CLEAR and then attach the idmapping to this
mount.
