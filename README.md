# Kernel Wish List 🤞 🎁 🙏

Here are a bunch of things we'd really like to see added to the Linux
Kernel APIs:

1. Per-user-namespace `overflowuid`.

   **Use-case #1**: Desktop integration for removable storage with
   file systems such as `ext4`: when a USB stick is inserted into a
   desktop with a session of a user "lennart", then this should have
   the effect that all files on the USB stick are owned by "lennart",
   regardless of what ownership is recorded in the file system. This
   currently works well for `vfat`, but does not work for `ext4`,
   `btrfs`, `xfs`, which store their own UIDs on the file system. By
   combining UID mapping mounts and a per-user-namespace `overflowuid`
   we can make this work: the mount is established with a UID map
   without entries, but with its `overflowuid` set to the desktop user's
   UID, so that all files on the disk will be assigned to the
   `overflowuid` and thus the user.

   **Use-case #2**: UID mapping mounts with `systemd-homed`: any files
   inside a LUKS home file system should be assigned to the UID the
   user has assigned locally.

2. Ability to unmount obstructed mounts. (This means: you have a stack
   of mounts on the very same inode, and you want to remove a mount in
   the middle. Right now, you can only remove the topmost mount.)

   **Use-Case:** this is useful for replacing mounts atomically, for
   example for upgrading versioned disk images: first an old version
   of the image is mounted. Then a new version is mounted over the
   existing mount point, and then the lower mount point is
   removed. One such software would be `systemd-sysext`.

3. Ability to mount sub-directories of regular file systems instead of
   the top-level directory. i.e. for a file system `/dev/sda1` which
   contains a sub-directory `/foobar` mount `/foobar` without having
   to mount its parent directory first. Consider something like this:

   ```
   mount -t ext4 /dev/sda1 somedir/ -o subdir=/foobar
   ```

   **Use-Case:** `systemd-homed` currently mounts a sub-directory of
   the per-user LUKS volume as the user's home directory (and not the
   root directory of the per-user LUKS volume's file system!), and in
   order to implement this invisibly from the host side requires a
   complex mount namespace exercise.


4. inotify() events for BSD file locks. BSD file locks
   (i.e. `flock()`, as opposed to POSIX `F_SETLK` and friends are
   inode-focussed, hence would be great if one could get asynchronous
   notification when they are released via inotify.

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

5. `SCM_CGROUP` or a similar auxiliary socket message, that allows
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

6. `SCM_PIDFD` or similar auxiliary socket message, that is a modern
   version of the `SCM_CREDS` message's `.pid` field, and provides a
   `pidfd` file descriptor to the originating peer process.

   **Use-Case:** security infrastructure (such as PolicyKit) can safely
   reference clients this way without fearing PID
   recycling. `systemd-journald` can acquire peer metadata this way in
   a less racy fashion, in particular safe against PID recycling.

7. Ability to link an `O_TMPFILE` file into a directory while *replacing* an
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

8. `O_REGULAR` (inspired by the existing `O_DIRECTORY` flag for
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

9. `IP_UNICAST_IF` should be taken into account for routing decisions
   at UDP `connect()` time (currently it isn't, only `SO_BINDTOINDEX`
   is, but that does so much more than just that, and one often
   doesn't want that)

   **Use-Case:** DNS resolvers that associate DNS configuration with
   specific network interfaces (example: `systemd-resolved`) typically
   want to preferably route DNS traffic to the per-interface DNS
   server via that interface, but not make further restrictions on the
   origins or received replies, and all that without
   privileges. `IP_UNICAST_IF` fulfills this role fine for TCP, but
   for UDP it is not taken into account for the `connect()` routing
   decision.

10. `unlinkat3(dir_fd, name, inode_fd)`: taking one file descriptor
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

11. Ability to determine if a mount point belongs to the current user
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

12. A way to mark mounts that receive mount propagation events from
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

13. Ability to turn off `SCM_RIGHTS` reception for `AF_UNIX`
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

14. Another alternative to this could be if some form of filtering
    could be enforced on the file descriptors suitable for en-queuing
    on the `AF_UNIX` socket. i.e. allow filtering by superblock type
    or similar, so that policies such as "only `memfd`s are OK to be
    received" may be expressed. (BPF?).

    **Use-Case:** a above.

15. A reliable (non-heuristic) way to detect from userspace if the
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

16. A way to exclude `pidfd` watched processes from `waitid(P_ALL, …)`.

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

17. Mount notifications that do not require continuous re-scanning of
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

18. Ability to to do cross-namespace mounts by file
    descriptor. Currently preparing a mount point in one namespace and then
    mounting it via `mount("/proc/self/fd/…", "/somewhere/else", NULL,
    MS_BIND…)` is prohibited by the kernel.

    **Use-Case:** various programs prepare complex mount hierarchies in
    private mount namespaces, that they later want to make appear in
    the host mount namespace fully put together (e.g. `systemd-dissect
    --mount`). This can currently only be implemented via mount
    propagation, which however has effects way beyond the installation
    of the one mount hierarchy that shall be installed.

19. An asynchronous or forced `close()`, that guarantees that
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

20. `CLOCK_MONOTONIC` network timestamps. Currently network timestamps
    are exclusively in `CLOCK_REALTIME`, even though for many (most?)
    a monotonic clock would be much preferable, as calculations become
    easier when one doesn't have to think about clock jumps and
    similar.

    **Use-Case:** `systemd-journald` collects implicit timestamps via
    `AF_UNIX` time-stamping, in `CLOCK_REALTIME`, even though for its
    internal logic only monotonic timestamps are used, as log records
    are searched via bisection in ordered tables, that require
    strictly increasing timestamps. In particular during boot (where
    `CLOCK_REALTIME` is often not available, stable or subject to
    corrections) it would be good to have reliable, monotonic
    timestamps on all log records.

21. Truly immutable loopback block devices. Right now setting up a
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
