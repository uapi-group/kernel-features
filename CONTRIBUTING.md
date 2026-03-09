# Contributing

Thank you for your interest in the UAPI Group Kernel Feature Wishlist. This
document explains how to propose new features, claim existing ones, or mark
items as completed.

## Proposing a new feature

1. Create a new Markdown file in the appropriate section directory
   under `website/content/`:
   - `wishlist/` for new ideas
   - `in-progress/` for features you are actively working on

2. Use the following front matter template:

   ```yaml
   ---
   title: "Short descriptive title"
   weight: 10
   status: wishlist
   categories:
     - mounts
     - namespaces
   ---
   ```

3. Include a clear description of the feature and a **Use-Case** section
   explaining why this would be valuable.

4. Open a pull request.

## Claiming an item

To indicate you are working on a wishlist item:

1. Move the file from `website/content/wishlist/` to
   `website/content/in-progress/`.
2. Update the `status` field in the front matter to `in-progress`.
3. Open a pull request with your GitHub handle or email address noted.

## Marking an item as completed

When a feature has been merged into the kernel:

1. Move the file from its current location to `website/content/completed/`.
2. Update the `status` field to `completed`.
3. Add a `commit` field to the front matter with the commit SHA.
4. Open a pull request.

## Attribution

**When implementing ideas on this list or ideas inspired by this list,
please point that out explicitly and clearly in the associated patches
and Cc `Christian Brauner <brauner (at) kernel (dot) org>`.**

## Categories

Use one or more of the following categories in front matter:

- `mounts` — mount namespaces, pivot_root, move_mount, statmount
- `pidfd` — pidfd xattrs, CLONE_PIDFD, SCM_PIDFD
- `namespaces` — user namespaces, PID namespaces, mount namespaces
- `filesystems` — nullfs, blobfs, overlayfs, tmpfs, binfmt_misc
- `sockets` — AF_UNIX, SCM_RIGHTS, SCM_PIDFD
- `cgroups` — device cgroups, coredump limits
- `block-devices` — loop devices, dm-verity, diskseq
- `security` — LSM hooks, user namespace restrictions
- `io-uring` — io_uring extensions
- `processes` — pidfd, clone3, waitid, prctl

## Local development

```sh
git clone --recurse-submodules https://github.com/uapi-group/kernel-features.git
cd kernel-features/website
hugo server
```
