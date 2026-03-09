# Kernel Feature Wishlist

A curated collection of kernel feature ideas maintained by the
[UAPI Group](https://uapi-group.org/). Browse the full list at
**[uapi-group.org/kernel-features](https://uapi-group.org/kernel-features/)**.

## Overview

This repository tracks kernel feature ideas across several categories:

- **In Progress** — features currently being designed or implemented
- **Wishlist** — ideas and proposals waiting for someone to pick them up
- **Completed** — features that have been merged into the kernel

Each feature is documented in its own page under `website/content/` with a
description, use-case, and category tags.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to:

- Propose a new feature idea
- Claim an existing wishlist item
- Mark a feature as completed

**When implementing ideas on this list or ideas inspired by this list,
please point that out explicitly and clearly in the associated patches
and Cc `Christian Brauner <brauner (at) kernel (dot) org>`.**

## Local development

```sh
git clone --recurse-submodules https://github.com/uapi-group/kernel-features.git
cd kernel-features/website
hugo server
```

Requires [Hugo](https://gohugo.io/) (extended edition).

## License

[MIT](LICENSE)
