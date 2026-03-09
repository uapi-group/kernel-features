---
title: "Linking of `O_TMPFILE` files with replacement"
weight: 50
status: wishlist
categories:
  - filesystems
---

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
