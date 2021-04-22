# Kernel Wishlist

Here are a bunch of things we'd really like to see in the kernel

1. Per-user-namespace `overflowuid`.

   Usecase #1: Desktop integration for removable storage with file
   systems such as `ext4`: when a USB stick is inserted into a desktop
   with a session of a user "lennart", then this should have the
   effect that all files on the USB stick are owned by "lennart",
   regardless what is stored in the file system. This currently works
   well for `vfat`, but does not work for `ext4`, `btrfs`, `xfs`,
   which store their own UIDs on the file system. By combining UID
   mapping mounts and a per-user-namespace `overflowuid` we can make
   this work: the mount is established with a UID map without entries,
   but with its overflowuid set to the desktop user's UID, so that all
   files on the disk will be assigned to the `overflowuid` and thus
   the user.

   Usecase #2: UID mapping mounts with `systemd-homed`: any files
   inside a LUKS home file system should be assigned to the UID the
   user has assigned locally.

2. Ability to unmount obstructed mounts. (This means: you have a stack
   of mounts on the very same inode, and you want to remove a mount in
   the middle. Right now, you can only remove the topmost mount.)

   Usecase: this is useful for replacing mounts atomically, for
   example for upgrading versioned disk images: first an old version
   of the image is mounted. Then a new version is mounted over the
   existing mount point, and then the lower mount point is
   removed. One such software would be `systemd-sysext`.

3. Ability to mount subdirectories of regular file systems instead of
   the top-level directry. i.e. for a file system `/dev/sda1` which
   contains a subdir `/foobar` mount `/foobar` without having to mount
   its parent directory first.

   ```
   mount -t ext4 /dev/sda1 somedir/ -o subdir=/foobar
   ```

4. The ability to determine re-uses of devices, in particular block
   devices, so that we can pinpoint a specific use of a device. Linux
   agressively recycles device names, in particular block device
   names. i.e. a USB disk is almost certainly named "sda" when plugged
   in (at lest if there's only one of them). If you unplug it and plug
   in a different one, the device name in the kernel will be the same,
   again `sda`, but we start talking to an entirely different device,
   with with different features, properties and contents.

   This is particularly bad for loopback block devices, which
   applications frequently allocate and release, and which are always
   allocated from `loop0`. In particular when working with partitioned
   images it's important to be able to match up the udev database
   entry for a device, the uevents coming from the kernel and the
   actual device node one can open in a safe way, so that one isn't
   mixing up data from an early use of such a device with a later one.

   Usecase: `systemd-nspawn` has an `--image=` switch which allows
   booting a container directly from a partitioned GPT disk
   image. After attaching the image file to a loopback device, one has
   to wait until the kernel' partition table parser picked up all
   partitions to mount. It currently is racy for userspace to wait for
   this, if the loopback devices are heavily recycled, since it's not
   clear from which device use the uevents originate.

   Proposed patch set: https://lore.kernel.org/linux-block/20210315200242.67355-1-mcroce@linux.microsoft.com/

5. `SCM_CGROUP` or a similar auxiliary socket message, that allows
   receivers to figure out which cgroup a sender is part of.

   Usecase: `systemd-journald` picks up cgroup information from
   logging client, to enhance log records and allow filtering via
   that. In particular it derives service identity from that (so that
   requests such as "Show me all log messages of service X!" can be
   answered). This is currently racy, since it uses SCM_CREDS' `.pid`
   field for this, which it then used to load `/proc/$PID/cgroup`. In
   particular for programs that log and immediately exit, the cgroup
   information freqently cannot be acquired anymore by
   `systemd-journald`.

6. `SCM_PIDFD` or similar auxiliary socket message, that is a modern
   version of the `SCM_CREDS` message's `.pid` field, and provides a
   `pidfd` file descriptor to the originating peer process.

   Usecase: security infrastructure (such as PolicyKit) can safely
   reference clients this way without fearing PID
   recycling. `systemd-journald` can acquire peer metadata this way in
   a less racy fashion, in particular safe against PID recycling.

7. Ability to link an `O_TMPFILE` file into a directory while *replacing* an
   existing file. (Currently there's only the ability to link it in, if the
   file name doesn't exist yet.)

   Usecase: there are many programs (e.g. `systemd-hostnamed` when
   updating /etc/hostname) that atomically want to update a file, so
   that either the old or the new version is in place, but never a
   partially updated one. The canonical way to do this is by creating
   a temporary file with the new contents, and then renaming it to the
   filename of the file to update, thus atomically replacing
   it. Currently, the temporary file for this must be created with a
   random name, `O_TMPFILE` cannot be used, since for these files
   atomic-replace is not supported, currenty.

8. `O_REGULAR` (which corresponds with the existing `O_DIRECTORY` flag
   for `open()`), but open a file only if it is of type `S_IFREG`.

   Usecase: this would be very useful to write secure programs that
   want to avoid being tricked into opening device nodes with special
   semantics while thinking they operate on regular files. This is
   particularly relevant as many device nodes (or even FIFOs) come
   with blocking I/O and `open()`by default, which is not expected
   from disk I/O. Consider implementation of a naive web browser which
   is pointed to `file://dev/zero`, no expecting an endless amount of
   data to read.

9. `IP_UNICAST_IF` should be taken into account for routing decisions at UDP
   connect() time (currently it isn't, only SO_BINDTOINDEX is, but that does so
   much more than just that, and one often doesn't want that)

10. unlinkat(dir_fd, name, inode_fd): one for the dir to remove a file in,
    and one referring to the inode to remove. And make this call succeed only
    if the name still matches the specified inode_fd.

11. Ability to determine if a mount point belongs to the current userns, i.e.
    there's a chance we can unmount it. Or if it belongs to some other
    namespace, and hence we cannot possibly unmount. This would help greatly to
    clean up systemd's shutdown logic, where we shouldn't bother unmounting
    dirs we cannot possibly successfully unmount anyway.

12. A way to mark bind mounts that receive propagation events from elsewhere,
    will get them automatically mounted read-only

13. Ability to turn off SCM_RIGHTS for AF_UNIX sockets

14. Better than 13: ability to restrict SCM_RIGHTS to only memfd() file
    descriptors.

15. reliable (non-heuristic) way to detect from userspace if one is running in
    a pidns that is not the main pidns.

16. A way to exclude pidfd watched processes from P_ALL

17. Sensible notifications for mounts that do not require repeated rescanning
    of all of /proc/self/mountinfo.

18. Ability to to do cross-namespace mounts by fd

19. An asynchronous or forced close(), that guarantees that userspace doesn't
    block when trying ot get rid of unwanted fds, possibly received via
    recvmsg()/SCM_RIGHTS.

20. CLOCK_MONOTONIC network timestamps

21. Truly immutable loopback block devices
