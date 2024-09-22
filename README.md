# Kernel Features 🤞 🎁 🙏

This is a list of kernel features that would be useful to have. The items on
the list are strictly ideas. It is especially important to not take the items
on this list as being implementation requests. Some of the ideas on this list
are rather rough and unrefined. They serve as entry points for exploring the
associated problem space.

**When implementing ideas on this list or ideas inspired by this list please
point that out explicitly and clearly in the associated patches and Cc
`Christian Brauner <brauner (at) kernel (dot) org`.**

### Mount a subdirectory instead of the top-level directory

Ability to mount a subdirectory of a regular file system instead of
the top-level directory. E.e. for a file system `/dev/sda1` which
contains a sub-directory `/foobar` mount `/foobar` without having
to mount its parent directory first. Consider something like this:

```
mount -t ext4 /dev/sda1 somedir/ -o subdir=/foobar
```

(This is of course already possible via some mount namespacing
shenanigans, but this requires namespacing to be available, and is
not precisely obvious to implement. Explicit kernel support at mount
time would be much preferable.)

**Use-Case:** `systemd-homed` currently mounts a sub-directory of
the per-user LUKS volume as the user's home directory (and not the
root directory of the per-user LUKS volume's file system!), and in
order to implement this invisibly from the host side requires a
complex mount namespace exercise.

### inotify() events for BSD file locks

BSD file locks (i.e. `flock()`, as opposed to POSIX `F_SETLK` and
friends are inode-focussed, hence would be great if one could get
asynchronous notification when they are released via inotify.

**Use-Case:** udevd probes block devices whenever they pop up to
create /dev/disk/by-label/* and similar symlinks. Formatting tools
can temporarily block this behaviour by taking a BSD file lock on
the block device (as per https://systemd.io/BLOCK_DEVICE_LOCKING),
in order to make sure udevd doesn't probe file systems/partition
tables that are only partially initialized. Currently, udevd uses
inotify `IN_CLOSE_WRITE` notifications to detect whenever
applications close a block device after writing to it, and
automatically reprobes the device. This works reasonably OK given
that block devices are usually closed at the same time as their
BSD file lock is released, and vice versa. However, this is not
fully correct: what udevd actually should be watching is the locks
being released, not the devices being closed.

### Auxiliary socket message describing the sender's cgroup

`SCM_CGROUP` or a similar auxiliary socket message, that allows
receivers to figure out which cgroup a sender is part of.

**Use-Case:** `systemd-journald` picks up cgroup information from
logging clients, in order to augment log records and allow
filtering via this meta-information. In particular it derives
service identity from that (so that requests such as "Show me all
log messages of service X!" can be answered). This is currently
racy, since it uses `SCM_CREDS`' `.pid` field for this, which it then
used to load `/proc/$PID/cgroup`. In particular for programs that
log and immediately exit, the cgroup information frequently cannot
be acquired anymore by `systemd-journald`.

### Linking of `O_TMPFILE` files with replacement

Ability to link an `O_TMPFILE` file into a directory while *replacing* an
existing file. (Currently there's only the ability to link it in, if the
file name doesn't exist yet.)

**Use-Case:** there are many programs (e.g. `systemd-hostnamed`
when updating `/etc/hostname`) that atomically want to update a
file, so that either the old or the new version is in place, but
never a partially updated one. The canonical way to do this is by
creating a temporary file with the new contents, and then renaming
it to the filename of the file to update, thus atomically replacing
it. Currently, the temporary file for this must be created with a
random name, `O_TMPFILE` cannot be used, since for these files
atomic-replace is not supported, currently.

### Ability to only open regular files

`O_REGULAR` (inspired by the existing `O_DIRECTORY` flag for
`open()`), which opens a file only if it is of type `S_IFREG`.

**Use-Case:** this would be very useful to write secure programs
that want to avoid being tricked into opening device nodes with
special semantics while thinking they operate on regular
files. This is particularly relevant as many device nodes (or even
FIFOs) come with blocking I/O (or even blocking `open()`!) by
default, which is not expected from regular files backed by "fast"
disk I/O. Consider implementation of a naive web browser which is
pointed to `file://dev/zero`, not expecting an endless amount of
data to read.

### Unlinking via two file descriptors

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

### Determining if a mount point belongs to the current user

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

### Read-only propagation of mounts

A way to mark mounts that receive mount propagation events from
elsewhere so that these propagated mounts are established
read-only implicitly. Right now, if a mount receives a mount
propagation event it will have the exact same `MS_RDONLY`,
`MS_NODEV`, … flags as it has where it originated. It would be
very useful if an `MS_RDONLY` could be ORed into the mount flags
automatically whenever propagated elsewhere.

**Use-Case:** various mount namespace based sandboxes
(e.g. `systemd`'s `ProtectSystem=` option) mark large parts of the
host file hierarchy read-only via mounting it
`MS_RDONLY|MS_BIND|MS_REMOUNT`, but generally intend to leave the
file hierarchy besides that the way it is, and that includes they
typically still want to be able to receive mount events to
directories such as `/mnt/` and `/media/` in these sandboxed
environments. Right now, any such propagation then happens in
writable mode, even if the file hierarchy otherwise is almost
entirely read-only. To close this gap it would be great if such
propagated mounts could implicitly gain `MS_RDONLY` as they are
propagated.

### Disabling reception of `SCM_RIGHTS` for `AF_UNIX` sockets

Ability to turn off `SCM_RIGHTS` reception for `AF_UNIX`
sockets. Right now reception of file descriptors is always on when
a process makes the mistake of invoking `recvmsg()` on such a
socket. This is problematic since `SCM_RIGHTS` installs file
descriptors in the recipient process' file descriptor
table. Getting rid of these file descriptors is not necessarily
easy, as they could refer to "slow-to-close" files (think: dirty
file descriptor referring to a file on an unresponsive NFS server,
or some device file descriptor), that might cause the recipient to
block for a longer time when it tries to them. Programs reading
from an `AF_UNIX` socket currently have three options:

1. Never use `recvmsg()`, and stick to `read()`, `recv()` and
   similar which do not install file descriptors in the recipients
   file descriptor table.

2. Ignore the problem, and simply `close()` the received file descriptors
   it didn't expect, thus possibly locking up for a longer time.

3. Fork off a thread that invokes `close()`, which mitigates the
   risk of blocking, but still means a sender can cause resource
   exhaustion in a recipient by flooding it with file descriptors,
   as for each of them a thread needs to be spawned and a file
   descriptor is taken while it is in the process of being closed.

(Another option of course is to never talk `AF_UNIX` to peers that
are not trusted to not send unexpected file descriptors.)

A simple knob that allows turning off `SCM_RIGHTS` right reception
would be useful to close this weakness, and would allow
`recvmsg()` to be called without risking file descriptors to be
installed in the file descriptor table, and thus risking a
blocking `close()` or a form of potential resource exhaustion.

**Use-Case:** any program that uses `AF_UNIX` sockets and uses (or
would like to use) `recvmsg()` on it (which is useful to acquire
other metadata). Example: logging daemons that want to collect
timestamp or `SCM_CREDS` auxiliary data, or the D-Bus message
broker and suchlike.

### Filtering on received file descriptors

An alternative to the previous item could be if some form of filtering
could be enforced on the file descriptors suitable for enqueuing on
the `AF_UNIX` socket. i.e. allow filtering by superblock type or
similar, so that policies such as "only `memfd`s are OK to be
received" may be expressed. (BPF?).

**Use-Case:** as above.

### A reliable way to check for PID namespacing

A reliable (non-heuristic) way to detect from userspace if the
current process is running in a PID namespace that is not the main
PID namespace. PID namespaces are probably the primary type of
namespace that identify a container environment. While many
heuristics exist to determine generically whether one is executed
inside a container, it would be good to have a correct,
well-defined way to determine this.

**Use-Case:** tools such as `systemd-detect-virt` exist to determine
container execution, but typically resolve to checking for
specific implementations. It would be much nicer and universally
applicable if such a check could be done generically. It would
probably suffice to provide an `ioctl()` call on the `pidns` file
descriptor that reveals this kind of information in some form.

### Excluding processes watched via `pidfd` from `waitid(P_ALL, …)`


**Use-Case:** various programs use `waitid(P_ALL, …)` to collect exit
information of exited child processes. In particular PID 1 and
processes using `PR_SET_CHILD_SUBREAPER` use this as they may
collect unexpected children that have been reparented from dying
sub-processes, and that need to be reaped in order to clean up the
PID space. Currently, these programs cannot easily mix waiting for
specific sub-processes via `pidfd` with waiting for the other
*unexpected* children via `waitid(P_ALL, …)` since the latter also
reaps (and thus invalidates) the pidfd-tracked
children. Specifically, the `systemd` service manager would like
to use `pidfd`s to remove PID recycling security issues, but
currently cannot as it also needs to generically wait for such
unexpected children.

### Mount notifications without rescanning of `/proc/self/mountinfo`

Mount notifications that do not require continuous rescanning of
`/proc/self/mountinfo`. Currently, if a program wants to track
mounts established on the system it can receive `poll()`able
events via a file descriptor to `/proc/self/mountinfo`. When
receiving them it needs to rescan the file from the top and
compare it with the previous scan. This is both slow and
racy. It's slow on systems with a large number of mounts as the
cost for re-scanning the table has to be paid for every change to
the mount table. It's racy because quickly added and removed
mounts might not be noticed.

**Use-Case:** `systemd` tracks the mount table to integrate the mounts
into it own dependency management.

### Asynchronous `close()`

An asynchronous or forced `close()`, that guarantees that
userspace doesn't have to risk blocking for longer periods of time
when trying to get rid of unwanted file descriptors, possibly
received via `recvmsg()` + `SCM_RIGHTS` (see above). Currently,
`close()` of various file descriptors (for example those referring
to slow storage, e.g. non-responding NFS servers and such) might
take arbitrary amounts of time, potentially into the minute range
and more. This makes it risky accepting file descriptors on
publicly accessible `AF_UNIX` sockets, the way like IPC brokers
(e.g. D-Bus) do it: if a rogue client keeps sending file
descriptors that because unexpected must be closed immediately it
might cause the receiving process to effectively crawl, when it is
busy closing them all. A special form of `close()` that simply
detaches a file descriptor from the file descriptor table without
blocking on IO in any form would be great to close this issue.

**Use-Case:** any program that receives file descriptors via `AF_UNIX`
from untrusted clients would benefit from this. e.g. D-Bus
brokers.

### `CLOCK_MONOTONIC` network timestamps

Currently network timestamps are exclusively in `CLOCK_REALTIME`, even
though for many (most?) a monotonic clock would be much preferable, as
calculations become easier when one doesn't have to think about clock
jumps and similar.

**Use-Case:** `systemd-journald` collects implicit timestamps via
`AF_UNIX` time-stamping, in `CLOCK_REALTIME`, even though for its
internal logic only monotonic timestamps are used, as log records
are searched via bisection in ordered tables, that require
strictly increasing timestamps. In particular during boot (where
`CLOCK_REALTIME` is often not available, stable or subject to
corrections) it would be good to have reliable, monotonic
timestamps on all log records.

### Immutable loopback block devices

Truly immutable loopback block devices. Right now setting up a
loopback block device in read-only mode, backed by a read-only
file (stored on a regular read/write file system), and then
mounting it with `ext4` also in `MS_RDONLY`mode *will* result in
changes to the file, quite unexpectedly 🤯. Ideally, if a loopback
block device is set up in read-only mode this should guarantee
that the backing file remains unmodified by it.

**Use-Case:** disk image build tools that want to reproducibly and
verifiable build images must be able to rely that mounting them in
read-only mode does not alter the images in any way. In particular
when working in computer forensics one must be able to rely that
file systems that are analyzed remain unmodified by the analysis.

### A timeout for the `flock()` syscall

A timeout for the `flock()` syscall. Faking the time-out in userspace
is nasty: most code does it with `alarm()` (or equivalent APIs), but
that's racy since on a heavily loaded system the timeout might trigger
before the `flock()` call is entered, in particular if short time-outs
shall be used. More accurate is to do the locking in a short-lived
child processed, but that's difficult already in C, and almost
impossible in languages that do not allow `fork()` without `execve()`.

**Use-Case:** as mentioned above systemd-udev allows synchronizing
block device probing via flock(). Often userspace wants to wait
for that, but without risking to hang forever.

### Extend `mount_setattr()` to allow changing mount properties ignoring any failures 

**Use-Case:** workloads that know that there are mounts in a mount tree
whose attributes cannot be changed by the caller don't want
`mount_settattr()` to fail on the first mount it failed to convert. Give
them a flag to request changes ignoring failures.

### Upgrade masks in `openat2()`

Add upgrade masks to `openat2()`. Extend `struct open_how` to allow
restrict re-opening of file descriptors.

**Use-Case:** block services or containers from re-opening/upgrading an
`O_PATH` file descriptor through e.g. `/proc/<pid>/fd/<nr` as `O_WRONLY`.

### Make quotas work with user namespaces

The quota codepaths in the kernel currently broken and inconsistent
and most interesting operations are guarded behind
`capable(CAP_SYS_ADMIN)`, i.e., require `CAP_SYS_ADMIN` in the initial
user namespace. We should rework these codepaths to work with user
namespaces and then see whether we can make them work with idmapped
mounts.

**Use-Case:** using quotas correctly in containers.

### Add `MOUNT_SETATTR_LOCKED` flag to `mount_setattr()`

Add a new `MOUNT_SETATTR_LOCKED` flag to `mount_setattr(..., ..., MOUNT_SETATTR_LOCKED, ..., ...)`.
The `MOUNT_SETATTR_LOCKED` flag allow a `ns_capable(mntns->user_ns,
CAP_SYS_ADMIN)` caller to lock all mount properties. The mount properties
cannot be changed anymore.

**Use-Case:** allowing processes to lock mount properties even for
privileged processes. Locking mount properties would currently involve
having to have the mount namespace of the container be owned by an ancestor
user namespace. But this doesn't just lock a single mount or mount subtree
it locks all mounts in the mount namespace, i.e., the mount table cannot be
altered.

### Add `OPEN_TREE_CLEAR` flag to `open_tree()`

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

### Require a user namespace to have an idmapping when attached

Enforce that the user namespace about to be attached to a mount must
have an idmapping written.

**Use-Case:** Tighten the semantics.

### Extend `setns()` to allow attaching to all new namespaces of a process

Add an extension to `setns()` to allow attaching to all namespaces of
a process `SETNS_PIDFD_ALL` different from the caller's namespaces.
Currently specifying e.g., `CLONE_NEWUSER` fails if the caller is in the
same user namespace as the target process. This is very inconvenient.

**Use-Case:** Make it trivial to attach to all namespaces of a process
without having to figure out whether the caller is already in the same
namespace or not.

### Security hook for `mount_setattr()`

(kAPI) Add security hook to `mount_setattr()`.

**Use-Case:** Allow LSMs to make decisions about what mount properties to
allow and what to deny.

### Per-cgroup limit for coredump sizes

A per-cgroup knob for coredump sizes. Currently coredump size
control is strictly per process, and primarily under control of
the processes themselves. It would be good if we had a per-cgroup
knob instead, that is under control of the service manager.

**Use-Case:** coredumps can be heavy to generate. For different
usecases it would be good to be able to opt-in or opt-out
dynamically from coredumps for specific services, at runtime
without restarting them.

### Race-free creation and opening of non-file inodes

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

### Extend `io_uring` with classic synchronous system calls

The `io_uring` subsystem is open to adding classic existing synchronous
system calls (e.g. `setns()` or `mount()` or other) to `io_uring`.
They also said they would support adding new functionality into
`io_uring` that is not exposed through system calls yet.

### Map different uids/gids to the same uids/gids?

Explore the idea of mapping different uids/gids to the same uids/gids, i.e.
65534:1000:1 50000:1000:1. This will only work if the mount is read-only as
the kernel wouldn't know what uid/gid would need to be put to disk
otherwise (65534? 50000? the first one that is mapped?).

**Use-Case:** Delegate multiple {g,u}ids to the same user. Merging
ownership similar to how overlayfs merges files. Bindfs
(https://bindfs.org/docs/bindfs.1.html#sect3) allows this concept too.

### blobfs

[`blobfs`](https://fuchsia.dev/fuchsia-src/concepts/filesystems/blobfs)
for Linux. i.e. a minimalistic file system, that can store
authenticated (Verity) data files, that can be written once, and
not be modified after that, and provide stable handles (i.e. is
content-addressable) to them.

**Use-Case:** This would deliver just about enough to place
trusted OS resources (binaries, kernels, initrds, fs trees, other
resources) in them, without having to trust the medium and IO
underneath. Should be simple enough to even implement in a boot
loader and similar, without making things vulnerable to rogue file
system image attacks. The OS and its payloads (apps, containers,
…) could then be composed from these resources, through means like
overlayfs, namespacing and more.

### Namespaced loop and block devices

Namespace-able loop and block devices, usable inside user namespaces.

**Use-Case:** Allow mounting images inside nspawn containers, and using
RootImage= and friends in the systemd user manager.

### Support detached mounts with `pivot_root()`

The new rootfs must currently refer to an attached mount. This restriction
seems unnecessary. We should allow the new rootfs to refer to a detached
mount.

This will allow a service- or container manager to create a new rootfs as
a detached, private mount that isn't exposed anywhere in the filesystem and
then `pivot_root()` into it.

Since `pivot_root()` only takes path arguments the new rootfs would need to
be passed via `/proc/<pid>/fd/<nr>`. In the long run we should add a new
`pivot_root()` syscall operating on file descriptors instead of paths.

### Device cgroup guard to allow `mknod()` in non-initial userns

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

### `AT_EMPTY_PATH` support `for unlinkat()`

**Use-Case:** When dealing with files/directories, allow passing
around only a file descriptor without having to keep the path around
to be able to unlink the file/directory.

### Race-free mounting of block devices

Introduce a new struct to `fsconfig()` as an alternative to the
`source` property. The struct contains at least a pointer to a path,
possibly a device minor and major, and a diskseq number. The VFS can
expose a helper that filesystems can call and use the diskseq number
to verify that the block device they are intending to mount is indeed
the one they want to mount.

**Use-Case:** Race-free mounting of block devices.

### Ability to reopen a `struct block_device`

Add ability to reopen a `struct block_device`. This would allow using
`blkdev_get_by_path()`/`blkdev_get_{part,whole}()` to claim a device
with `BLK_OPEN_READ` and later on reopen with
`BLK_OPEN_READ | BLK_OPEN_WRITE`. This in turn would opening block
devices at `fsconfig(FS_CONFIG_SET_*)` time and then at `fill_super()`
time we would be able to reopen in case the `!(fc->sb_flags & SB_RDONLY)`.
Overall this has the effect that we're able to open devices early
giving the user early errors when they set mount options rather than
very late when the superblock is created.

### Specification of a keyring for dm-verity volume verification

When activating a dm-verity volume allow specifying keyring to
validate root hash signature against.

**Usecase:** In systemd, we'd like to authenticate Portable Service
images, system extension images, configuration images, container
images with different keys, as they typically originate from
different sources and it should not be possible to generate a
system extension with a key pair that is supposed to be good for
container images only.

### Make statx() on a pidfd return additional info

Make statx() on a pidfd return additional recognizable identifiers in
`.stx_btime`.

**🙇 `cb12fd8e0dabb9a1c8aef55a6a41e2c255fcdf4b pidfd: add pidfs` 🙇**

It would be fantastic if issuing statx() on any pidfd would return
the start time of the process in `.stx_btime` even after the process
died.

These fields should in particular be queriable *after* the process
already exited and has been reaped, i.e. after its PID has already
been recycled.

**Usecase:** In systemd we maintain lists of processes in a hash
table. Right now, the key is the PID, but this is less than ideal
because of PID recycling. By being able to use the `.stx_btime`
and/or `.stx_ino` fields instead would be perfect to safely
identify, track and compare process even after they ceased to exist.

### API to determine the parent process ID of a pidfd

An API to determine the parent process ID (ppid) of a pidfd would be
good.

This information is relevant to code dealing with pidfds, since if
the ppid of a pidfd matches the process own pid it can call
`waitid()` on the process, if it doesn't it cannot and such a call
would fail. It would be very useful if this could be determined
easily before even calling that syscall.

**Usecase:** systemd manages a multitude of processes, most of which
are its own children, but many which are not. It would be great if
we could easily determine whether it is worth waiting for
`SIGCHLD`/`waitid()` on them or whether waiting for `POLLIN` on
them is the only way to get exit notification.

### Set `comm` field before `exec()`

There should be a way to control the process' `comm` field if
started via `fexecve()`/`execveat()`.

Right now, when `fexecve()`/`execveat()` is used, the `comm` field
(i.e. `/proc/self/comm`) contains a name derived of the numeric fd,
which breaks `ps -C …` and various other tools.  In particular when
the fd was opened with `O_CLOEXEC`, the number of the fd in the old
process is completely meaningless.

The goal is add a way to tell `fexecve()`/`execveat()` what Name to use.

Since `comm` is under user control anyway (via `PR_SET_NAME`), it
should be safe to also make it somehow configurable at fexecve()
time.

See https://github.com/systemd/systemd/commit/35a926777e124ae8c2ac3cf46f44248b5e147294,
https://github.com/systemd/systemd/commit/8939eeae528ef9b9ad2a21995279b76d382d5c81.

**Usecase:** In systemd we generally would prefer using `fexecve()`
to safely and race-freely invoke processes, but the fact that `comm`
is useless after invoking a process that way makes the call
unfortunately hard to use for systemd.

### Path-based ACL management

The LSM module API should have the ability to do path-based (not
just inode-based) ACL management.

**Usecase:** This would be useful in BPF-LSM modules such as
systemd's `mntfsd` which allows unprivileged file system mounts in
some cases, and which would like to restrict ACL handling based on
the superblock involved.

### Immutable layers for `overlayfs`

`overlayfs` should permit *immutable* layers, i.e. layers whose
non-directory inodes may not be overriden in an upper writable
layer.

**Usecase:** This would be useful when implementing `/etc/` as a
stack of overlayfs layers, each shipping configuration for a
different facet of the system, with a writable layer on the top for
local modifications. In such a scenario it would be useful to allow
the user to change any configuration it likes, except of the files
and other inodes shipped in the lower layers.

### `ioctl()` API for `overlayfs`

`overlayfs` should have an `ioctl()`-based API (or similar) for
querying information of the backing file systems/block devices

**Usecase:** In systemd in various areas we automatically find the
block device backing the root file system and other file systems
(Example: `systemd-gpt-auto-generator` or `bootctl` wull try to find
auxiliary file systems of the OS image by looking in the GPT
partition table the root file system is located in). While this
logic is good enough to find the backing block devices of some more
complex storage such as dm-crypt, dm-verity or btrfs, once
`overlayfs` is used as backing for the root file system this logic
does not work anymore. It would be great if there was an API to
simply query `overlayfs` for the superblock information
(i.e. `.st_dev`) of the backing layers.

#### Automatic growing of `btrfs` filesystems

An *auto-grow* feature in `btrfs` would be excellent.

If such a mode is enabled, `btrfs` would automatically grow a file
system up to the size of its backing block devices. Example: btrfs
is created with 200M in size on a block device 2G in size. Once the
file system is filled up fully, `btrfs` would automatically grow the
file system as need in the increments it needs, up to the 2G that
the backing block device is in size.

**Usecase:** This would allow creating minimal, compact file
systems: just create them small on a sparse block device, and copy
files into it, as needed, create subvolumes and whatever else is
desired. As long as only files are created and written (but not
modified) the resulting fs should be automatically minimal in size.
This would specifically be useful in `systemd-homed`, which
maintains per-user `btrfs` file systems backed by block
devices. Currently, `homed` grows the file systems manually on login
and then shrinks them again on logout, but this is less than ideal,
since btrfs places files all over the backing store, and thus the
shrinking will generate a lot of nonsensical IO that could be
reduced if the file system was always kept minimal in size anyway.

### Add process by PIDFD to a cgroup

At the moment the canonical way to add a process to a cgroup is by
echoing its PID into the `cgroup.procs` attribute in the target
cgroupfs directory of the cgroup. This is safe as long as the
process doing so just forked off the process it wants to migrate and
hence can control that it hasn't been reaped yet, and hence
guarantees the PID is valid. This is racy however if "foreign"
processes shall be moved into the cgroup.

**Usecase:** In systemd, all user sessions are wrapped in scope
units which are backed by a cgroup. The session processes moved into
the scope unit are typically "foreign" processes, i.e. not children
of the service manager, hence doing the movement is subject to races
in case the process dies and its PID is quickly recycled. (This
assumes systemd can acquire a pidfd of the foreign process without
races, for example via `SCM_PIDFD` and `SO_PEERPIDFD` or similar.)

### Ability to put user xattrs on `S_IFSOCK` socket inodes

Currently, the kernel only allows extended attributes in the
`user.*` namespace to be attached to directory and regular file
inodes. It would be tremendously useful to allow them to be
associated with socket inodes, too.

**Usecase:** There are two syslog RFCs in use today: RFC3164 and
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

### Open thread-group leader via `pidfd_open()`

Extend `pidfd_open()` to allow opening the thread-group leader based on the
PID of an individual thread. Currently we do support:

1. `pidfd_open(1234, 0)` on a thread-group leader PID
2. `pidfd_open(1234, PIDFD_THREAD)` on a thread

Add an option to go from individual thread to thread-group leader.

**Use-Case:** Allow for a race free way to go from individual thread
to thread-group leader pidfd.

### Namespace ioctl to translate a PID between PID namespaces

**Use-Case:** This makes it possible to e.g., figure out what a given PID in
a PID namespace corresponds to in the caller's PID namespace. For example, to
figure out what the PID of PID 1 inside of a given PID namespace is.

## Finished Items

### Unmounting of obstructed mounts

[x] ability to unmount obstructed mounts. (this means: you have a stack
of mounts on the very same inode, and you want to remove a mount in
the middle. right now, you can only remove the topmost mount.)

**🙇 instead of the ability to unmount obstructured mounts we gained
the ability to mount beneath an existing mount, with mostly
equivalent outcome. `6ac392815628f317fcfdca1a39df00b9cc4ebc8b
("fs: allow to mount beneath top mount")` 🙇**

**use-case:** this is useful for replacing mounts atomically, for
example for upgrading versioned disk images: first an old version
of the image is mounted. then a new version is mounted over the
existing mount point, and then the lower mount point is
removed. One such software would be `systemd-sysext`.

### `SCM_PIDFD` auxiliary socket message

[x] `SCM_PIDFD` or similar auxiliary socket message, that is a modern
version of the `SCM_CREDS` message's `.pid` field, and provides a
`pidfd` file descriptor to the originating peer process.

**🙇 `5e2ff6704a275be00 ("scm: add SO_PASSPIDFD and SCM_PIDFD)")` 🙇**

**Use-Case:** security infrastructure (such as PolicyKit) can safely
reference clients this way without fearing PID
recycling. `systemd-journald` can acquire peer metadata this way in
a less racy fashion, in particular safe against PID recycling.

### Take `IP_UNICAST_IF` into account for routing decisions

[x] `IP_UNICAST_IF` should be taken into account for routing decisions
at UDP `connect()` time (currently it isn't, only `SO_BINDTOINDEX`
is, but that does so much more than just that, and one often
doesn't want that)

**🙇 `0e4d354762cefd3e16b4cff8988ff276e45effc4 ("net-next: Fix
IP_UNICAST_IF option behavior for connected sockets")` 🙇**

**Use-Case:** DNS resolvers that associate DNS configuration with
specific network interfaces (example: `systemd-resolved`) typically
want to preferably route DNS traffic to the per-interface DNS
server via that interface, but not make further restrictions on the
origins or received replies, and all that without
privileges. `IP_UNICAST_IF` fulfills this role fine for TCP, but
for UDP it is not taken into account for the `connect()` routing
decision.

### A system call to query information about a mount

[x] Implement a mount-specific companion to `statx()` that puts at least the
following information into `struct mount_info`:

**🙇 `46eae99ef73302f9fb3dddcd67c374b3dffe8fd6 ("add statmount(2) syscall")` 🙇**

* mount flags: `MOUNT_ATTR_RDONLY`, ...
* time flags: `MOUNT_ATTR_RELATIME`, ...
  Could probably be combined with mount flags.
* propagation setting: `MS_SHARED)`, ...
* peer group
* mnt id of the mount
* mnt id of the mount's parent
* owning userns

There's a bit more advanced stuff systemd would really want but which
I think is misplaced in a mountinfo system call including:
* list of primary and auxiliary block device major/minor
* diskseq value of those device nodes (This is a new block device feature
  we added that allows preventing device recycling issues when e.g.
  removing usb devices very quickly and is needed for udev.)
* uuid/fsid
* feature flags (`O_TMPFILE`, `RENAME_EXCHANGE` supported etc.)

**Use-Case:** low-level userspace tools have to interact with advanced
mount information constantly. This is currently costly and brittel because
they have to go and parse `/proc/<pid>/mountinfo`.

### Security hook for `create_user_ns()`.

[x] (kAPI) Add security hook to `create_user_ns()`.

**🙇 `7cd4c5c2101c ("security, lsm: Introduce security_create_user_ns()")` 🙇**

**Use-Case:** Allow LSMs to monitor user namespace creation.

### Idmapped mounts for tmpfs

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

### Additional identifiers for pidfds in `statx()`

[x] Make `statx()` on a pidfd return additional recognizable identifiers
in `.stx_ino`.

**🙇 `cb12fd8e0dabb9a1c8aef55a6a41e2c255fcdf4b pidfd: add pidfs` 🙇**

It would be fantastic if issuing statx() on any pidfd would return some
reasonably stable 64bit identifier for the process in `.stx_ino`. This would
be perfect to identify processes pinned by a pidfd, and compare them.

### Namespace `binfmt_misc` filesystem

[x] Make the `binfmt_misc` filesystem namespaced.

**🙇 `21ca59b365c0 ("binfmt_misc: enable sandboxed mounts")` 🙇**

**Use-Case:** Allow containers and sandboxes to register their own binfmt
handlers.

### Support idmapped mounts for `overlayfs`

[x] Support idmapped mounts for `overlayfs`

**🙇 `bc70682a497c ("ovl: support idmapped layers")` 🙇**

**Use-Case:** Allow containers to use `overlayfs` with idmapped mounts.
