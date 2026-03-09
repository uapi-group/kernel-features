---
title: "Idmapped mounts for tmpfs"
weight: 140
status: completed
categories:
  - filesystems
  - mounts
  - namespaces
commit: "7a80e5b8c6fa"
---

[x] Support idmapped mounts for tmpfs

**🙇 `7a80e5b8c6fa ("shmem: support idmapped mounts for tmpfs")` 🙇**

**Use-Case:** Runtimes such as Kubernetes use a lot of `tmpfs` mounts of
individual files or directories to expose information to containers/pods.
Instead of having to change ownership permanently allow them to use an
idmapped mount instead.

@rata and @giuseppe brought this suggestion forward. For Kubernetes it is
sufficient to support idmapped mounts of `tmpfs` instances mounted in the
initial user namespace. However, in the future idmapped
mounts of `tmpfs` instances mounted in user namespaces should be supported.
Other container runtimes want to make use of this. The kernel is able to
support this since at least `5.17`.

Things to remember are that `tmpfs` mounts can serve as lower- or upper
layers in `overlayfs` and care needs to be taken that this remains safe if
idmapped mounts of `tmpfs` instances mounted in user namespaces are
supported.
