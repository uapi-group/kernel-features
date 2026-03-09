---
title: "A reliable way to check for PID namespacing"
weight: 190
status: completed
categories:
  - filesystems
  - namespaces
  - processes
---

[x] A reliable (non-heuristic) way to detect from userspace if the
current process is running in a PID namespace that is not the main
PID namespace. PID namespaces are probably the primary type of
namespace that identify a container environment. While many
heuristics exist to determine generically whether one is executed
inside a container, it would be good to have a correct,
well-defined way to determine this.

**🙇 The inode number of the root PID namespace is fixed (0xEFFFFFFC)
and now considered API. It can be used to distinguish the root PID
namespace from all others. 🙇**

**Use-Case:** tools such as `systemd-detect-virt` exist to determine
container execution, but typically resolve to checking for
specific implementations. It would be much nicer and universally
applicable if such a check could be done generically. It would
probably suffice to provide an `ioctl()` call on the `pidns` file
descriptor that reveals this kind of information in some form.
