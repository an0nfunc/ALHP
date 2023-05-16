# ALHP

[![](https://img.shields.io/badge/license-GPL-blue?style=flat-square)](https://somegit.dev/anonfunc/ALHP.GO/src/branch/master/LICENSE)
[![](https://img.shields.io/badge/package-status-informational?style=flat-square)](https://alhp.dev/packages.html)
[![](https://goreportcard.com/badge/somegit.dev/ALHP/ALHP.GO?style=flat-square)](https://goreportcard.com/report/somegit.dev/ALHP/ALHP.GO)
[![](https://pkg.go.dev/badge/somegit.dev/ALHP/ALHP.GO)](https://pkg.go.dev/somegit.dev/ALHP/ALHP.GO)
[![](https://img.shields.io/liberapay/patrons/anonfunc.svg?logo=liberapay&style=flat-square)](https://liberapay.com/anonfunc/)

Buildbot for Archlinux-based repos build with different
[x86-64 feature levels](https://www.phoronix.com/scan.php?page=news_item&px=GCC-11-x86-64-Feature-Levels), `-O3` and
[LTO](https://en.wikipedia.org/wiki/Interprocedural_optimization).

> ⚠️ NVIDIA graphic users using the **proprietary driver** is highly recommended reading the
> [FAQ about Linux kernel modules](#directly-linked-kernel-modules) ⚠️

---
<!-- TOC -->

* [Quickstart](#quickstart)
* [Remove ALHP packages](#remove-alhp-packages)
* [FAQ](#faq)
    * [LTO](#lto)
    * [Linux Kernel packages](#linux-kernel-packages)
    * [Directly linked kernel modules](#directly-linked-kernel-modules)
    * [Mirrors](#mirrors)
    * [What packages are built](#what-packages-are-built)
    * [Debug symbols](#debug-symbols)
* [Matrix](#matrix)
* [Donations](#donations)
* [License and Legal](#license-and-legal)

<!-- TOC -->

---

## Quickstart

### 1. Check your system for support

> **Important**: Before you enable any of these repos, check if your system supports the feature level you want to
> enable
(e.g. `x86-64-v3`).
> **If you don't check beforehand, you might be unable to boot your system anymore and need to downgrade any package
that you may have upgraded.**

Check which feature-levels your CPU supports with

```bash
/lib/ld-linux-x86-64.so.2 --help
```

Example output snippet for a system supporting up to `x86-64-v3`:

```
Subdirectories of glibc-hwcaps directories, in priority order:
  x86-64-v4
  x86-64-v3 (supported, searched)
  x86-64-v2 (supported, searched)
```

### 2. Install keyring & mirrorlist

Install [alhp-keyring](https://aur.archlinux.org/packages/alhp-keyring/)
and [alhp-mirrorlist](https://aur.archlinux.org/packages/alhp-mirrorlist/) from **AUR**.

Example with `yay`:

```bash
yay -S alhp-keyring alhp-mirrorlist
```

`alhp-keyring` provides the current signing keys used by ALHP, `alhp-mirrorlist` a selection of mirrors.

### 3. Choose a mirror (optional)

Edit `/etc/pacman.d/alhp-mirrorlist` and comment out/in mirrors you want to have enabled/disabled. Per default selected
is a cloudflare-based mirror which
[*should* provide decent speed worldwide](https://somegit.dev/ALHP/ALHP.GO/issues/38#issuecomment-891).
> Note: Only `alhp.dev` is hosted by ALHP directly. If you have problems with a mirror,
> open an issue at [the mirrorlist repo](https://somegit.dev/ALHP/alhp-mirrorlist).

### 4. Modify /etc/pacman.conf

Add the appropriate repos **above** your regular Archlinux repos.

Example for `x86-64-v3`:

```editorconfig
[core-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[extra-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[community-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[community]
Include = /etc/pacman.d/mirrorlist
```

Replace `x86-64-v3` with the x86-64 feature level you want to enable.
> ALHP only builds for `x86-64-v3` and `x86-64-v2` at the moment (list is subject to change). You can see all available
> repositories
> [here](https://alhp.dev/).

### 5. Update package database and upgrade:

```
pacman -Suy
```

## Remove ALHP packages

To disable ALHP remove all *x86-64-vX* entries in `/etc/pacman.conf` and remove `alhp-keyring` and `alhp-mirrorlist`.

After that you can refresh pacmans databases and downgrade all packages like:

```
pacman -Suuy
```

## FAQ

### LTO

Enabled for all packages build after 04 Nov 2021 12:07:00
UTC. [More details.](https://somegit.dev/ALHP/ALHP.GO/issues/52)
LTO status is visible per package on the package status page.

### Linux Kernel packages

`KCFLAGS`/`KCPPFLAGS` are used to build the kernel packages with our additional flags.

### Directly linked kernel modules

Due to our increase in pkgrel, building the kernel packages **breaks all directly linked modules** like `nvidia`
(not `nvidia-dkms`) or `virtualbox-host-modules-arch` (not `virtualbox-host-dkms`). **Their respective `dkms`-variant is
not affected**. This issue is being tracked in #68, a solution is being worked on.

### Mirrors

You want to mirror ALHP? You are welcome to do
so, [see alhp-mirrorlist for how to become one](https://somegit.dev/ALHP/alhp-mirrorlist#how-to-become-a-mirror).

### What packages are built

Packages [excluded](https://www.reddit.com/r/archlinux/comments/oflged/alhp_archlinux_recompiled_for_x8664v3_experimental/h4fkinu?utm_source=share&utm_medium=web2x&context=3)
from building (besides all 'any' architecture packages) are being listed in issue #16.
Also [package status page](https://alhp.dev/packages.html) (search for `blacklisted`).

### Debug symbols

ALHP provides a debuginfod instance under `debuginfod.alhp.dev`.

To use it, have `debuginfod` installed on your system and add it to your `DEBUGINFOD_URLS` with:

```bash
echo "https://debuginfod.alhp.dev" > /etc/debuginfod/alhp.urls
```

## Matrix

For any non-issue questions or if you just want to chat, ALHP has a matrix
room [here](https://matrix.to/#/#alhp:ofsg.eu) (`#alhp@ofsg.eu`). You can also find me (@idlegandalf)
in `#archlinux:archlinux.org`.

## Donations

I appreciate any money you want to throw my way, but donations are strictly optional. Donations are primarily used to
pay for server costs. Also consider [donating to the **Archlinux Team**](https://archlinux.org/donate/), without their
work ALHP would not be possible.

[![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/anonfunc/)

## License and Legal

This project including all of its source files is released under the terms of the GNU General Public License version 2
(or any later version). See [LICENSE](https://somegit.dev/ALHP/ALHP.GO/src/branch/master/LICENSE) for details.
