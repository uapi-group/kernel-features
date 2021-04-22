# Kernel Wishlist

Here are a bunch of things we'd really like to see in the kernel

1. per userns overflowuid: usecase is uid mapping mounts/homed — any files
   owned by an unmapped user should be mapped in a specific mount-specific way.

2. ability to unmount obstructed mounts

3. ability to mount subdirectories of regular file systems instead of the
   top-level dir. i.e. for an fs /dev/sda1 which contains a subdir /foobar
   mount /foobar without having to mount its root first.

   mount -t ext4 /dev/sda1 somedir/ -o subdir=/foobar

4. The ability to determine re-uses of devices, in particular block devices, so
   that we can pinpoint a specific use of a device

5. SCM_CGROUP or so, that allows receivers to figure out which cgroup a sender
   is part of

6. SCM_PIDFD that is like SCM_CREDS but returns a pidfd of a peer, instead of a
   ucred

7. ability to link an O_TMPFILE file into a directory while *replacing* an
   existing file. (Currently there's only the ability to link it in, if the
   file name doesn't exist yet)

8. O_REGULAR (which would be like O_DIRECTORY), but open a file only if it is
   of type S_IFREG)

9. IP_UNICAST_IF should be taken into account for routing decisions at UDP
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
