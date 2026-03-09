# Website

This directory contains the Hugo-based static site for the kernel feature wishlist.

## Theme

The site uses the [hugo-book](https://github.com/alex-shpak/hugo-book) theme,
included as a git submodule. After cloning, run:

```sh
git submodule init && git submodule update
```

## Content layout

```
content/
  _index.md              Landing page
  in-progress/           Features being actively worked on
  wishlist/              Ideas and proposals
  completed/             Features merged into the kernel
```

Each feature is a separate Markdown file with YAML front matter containing
`title`, `status`, `categories`, and optionally `commit` (for completed items).

## Local development

From this directory:

```sh
hugo server --minify --disableFastRender
```

Review at http://localhost:1313/kernel-features/ .

## Build

```sh
hugo --minify -d ../public
```
