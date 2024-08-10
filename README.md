# ALHP

[![](https://img.shields.io/badge/license-GPL-blue?style=flat-square)](https://somegit.dev/anonfunc/ALHP.GO/src/branch/master/LICENSE)
[![](https://img.shields.io/badge/package-status-informational?style=flat-square)](https://status.alhp.dev)
[![](https://goreportcard.com/badge/somegit.dev/ALHP/ALHP.GO?style=flat-square)](https://goreportcard.com/report/somegit.dev/ALHP/ALHP.GO)
[![](https://pkg.go.dev/badge/somegit.dev/ALHP/ALHP.GO)](https://pkg.go.dev/somegit.dev/ALHP/ALHP.GO)
[![](https://img.shields.io/liberapay/patrons/anonfunc.svg?logo=liberapay&style=flat-square)](https://liberapay.com/anonfunc/)

Buildbot for Archlinux-based repos build with different
[x86-64 feature levels](https://www.phoronix.com/scan.php?page=news_item&px=GCC-11-x86-64-Feature-Levels), `-O3` and
[LTO](https://en.wikipedia.org/wiki/Interprocedural_optimization).

> [!WARNING]
> NVIDIA graphic users using the **proprietary driver** is highly recommended reading the
> [FAQ about Linux kernel modules](#directly-linked-kernel-modules)

---
<!-- TOC -->

* [ALHP](#alhp)
  * [Quickstart](#quickstart)
  * [FAQ](#faq)
  * [Matrix](#matrix)
  * [Donations](#donations)
  * [License and Legal](#license-and-legal)
<!-- TOC -->

---

## Quickstart

### 1. Check your system for support

> [!CAUTION]
> Before you enable any of these repos, check if your system supports the feature level you want to
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

> [!NOTE]
> ALHP builds for `x86-64-v2`, `x86-64-v3` and `x86-64-v4` at the moment. You can see all available
> repositories
> [here](https://alhp.dev/).

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
> [!NOTE]
> `cdn.alhp.dev` and `alhp.dev` are provided by ALHP directly. If you have problems with a mirror,
> open an issue at [the mirrorlist repo](https://somegit.dev/ALHP/alhp-mirrorlist).

### 4. Modify /etc/pacman.conf

Add the appropriate repos **above** your regular Archlinux repos.

Example for `x86-64-v3`:

```editorconfig
[core-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[core]
Include = /etc/pacman.d/mirrorlist

[extra-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

# if you need [multilib] support
[multilib-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist

[multilib]
Include = /etc/pacman.d/mirrorlist
```

Replace `x86-64-v3` with the x86-64 feature level you want to enable.

> [!TIP]
> Stacking multiple levels is possible, as described in https://somegit.dev/ALHP/ALHP.GO/issues/255#issuecomment-3335.

### 5. Update package database and upgrade:

```
pacman -Suy
```

## FAQ

### Remove ALHP packages

To disable ALHP remove all *x86-64-vX* entries in `/etc/pacman.conf` and remove `alhp-keyring` and `alhp-mirrorlist`.

After that you can refresh pacmans databases and downgrade all packages like:

```
pacman -Suuy
```

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
Also [package status page](https://status.alhp.dev) (search for `blacklisted`).

### Why is package X not up-to-date

Also relevant for: **I can't find package X / Application X fails to start because it links to an old/newer lib**

ALHP build packages **after** they are released in the official Archlinux Repos (not including `[*-testing]`).
This leads to packages being delayed if the current batch contains many packages or packages which take a while to
build (e.g. `chromium`).

You can always check on the progress of the current build-cycle on
the [package status page](https://status.alhp.dev).
Please refrain from opening issues caused by packages currently in queue/not yet build/not yet moved to the repo.
Please keep in mind that large rebuilds such as `openssl` or `python` can take days to complete on our current build
hardware.

### Debug symbols

ALHP provides a debuginfod instance under `debuginfod.alhp.dev`.

To use it, have `debuginfod` installed on your system and add it to your `DEBUGINFOD_URLS` with:

```bash
echo "https://debuginfod.alhp.dev" > /etc/debuginfod/alhp.urls
```

### Switch between levels

If you want to switch between levels, e.g. from `x86-64-v3` to `x86-64-v4`, you need to revert to official packages
first, then enable your desired repos again.

1. Comment or remove ALHP repo entries in `/etc/pacman.conf`.
2. Downgrade packages with `pacman -Suuy`.
3. Clear pacman's package cache with `pacman -Scc`.
4. Uncomment/add your desired repos to `/etc/pacman.conf` and update with `pacman -Suy`.

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
