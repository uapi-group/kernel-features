---
title: "Device cgroup guard to allow `mknod()` in non-initial userns"
weight: 280
status: wishlist
categories:
  - cgroups
  - filesystems
  - mounts
  - namespaces
  - security
---

If a container manager restricts its unprivileged (user namespaced)
children by a device cgroup, it is not necessary to deny `mknod()`
anymore. Thus, user space applications may map devices on different
locations in the file system by using `mknod()` inside the container.

**Use-Case:** A use case for this, which is applied by users of GyroidOS,
is to run `virsh` for VMs inside an unprivileged container. `virsh` or
libvirt creates device nodes, e.g., `/var/run/libvirt/qemu/11-fgfg.dev/null`
which currently fails in a non-initial userns, even if a cgroup device white
list with the corresponding major, minor of `/dev/null` exists. Thus, in
this case the usual bind mounts or pre populated device nodes under `/dev`
are not sufficient.

An initial group internal RFC exists in
(https://github.com/quitschbo/linux/tree/devcg_guard_rfc).
See commit message for more implementation specific details.
