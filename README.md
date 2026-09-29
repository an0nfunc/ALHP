# ALHP

[![](https://img.shields.io/badge/package-status-informational?style=flat-square)](https://status.alhp.dev)
[![](https://goreportcard.com/badge/somegit.dev/ALHP/ALHP.GO?style=flat-square)](https://goreportcard.com/report/somegit.dev/ALHP/ALHP.GO)
[![](https://pkg.go.dev/badge/somegit.dev/ALHP/ALHP.GO)](https://pkg.go.dev/somegit.dev/ALHP/ALHP.GO)
[![](https://img.shields.io/badge/license-GPL-blue?style=flat-square)](https://somegit.dev/ALHP/ALHP.GO/src/branch/main/LICENSE)
[![](https://img.shields.io/liberapay/patrons/anonfunc.svg?logo=liberapay&style=flat-square)](https://liberapay.com/anonfunc/)

Buildbot for Archlinux based repos with different
[x86-64 feature levels](https://www.phoronix.com/scan.php?page=news_item&px=GCC-11-x86-64-Feature-Levels), `-O3` and
[LTO](https://en.wikipedia.org/wiki/Interprocedural_optimization).

> [!WARNING]
> Users of prebuilt kernel module packages, such as `nvidia-open` (not `nvidia-open-dkms`), are strongly encouraged to
> read the [FAQ about directly linked kernel modules](#directly-linked-kernel-modules) before enabling any repos.

---
<!-- TOC -->
* [Quick Start](#quick-start)
* [FAQ](#faq)
* [Matrix](#matrix)
* [Donations](#donations)
* [License and Legal](#license-and-legal)
<!-- TOC -->

---

## Quick Start

### 1. Check your system for support

> [!CAUTION]
> Before enabling any of these repos, make sure that your system supports the level of functionality you want to
> enable (e.g. `x86-64-v3`).
> **If you don't check first, you may not be able to boot your system and will have to downgrade any packages you may
have upgraded.**

Check which feature levels your CPU supports with

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
> ALHP repos for `x86-64-v2`, `x86-64-v3` and `x86-64-v4` are currently available. You can see all available
> repositories [here](https://alhp.dev/).

### 2. Install keyring & mirrorlist

Install [alhp-keyring](https://aur.archlinux.org/packages/alhp-keyring/)
and [alhp-mirrorlist](https://aur.archlinux.org/packages/alhp-mirrorlist/) from the **AUR**.

Example with `yay`:

```bash
yay -S alhp-keyring alhp-mirrorlist
```

`alhp-keyring` provides the current signing keys used by ALHP, `alhp-mirrorlist` a selection of mirrors.

### 3. Choose a mirror (optional)

Edit `/etc/pacman.d/alhp-mirrorlist` and comment in/out the mirrors you want to enable/disable.
By default, a CDN mirror provided by ALHP is selected.
> [!NOTE]
> `cdn.alhp.dev` and `alhp.dev` are provided directly by ALHP. If you have problems with a mirror,
> open an issue at [the mirrorlist repo](https://somegit.dev/ALHP/alhp-mirrorlist).

### 4. Modify pacman.conf

Add the ALHP repos to your `/etc/pacman.conf`. Make sure the appropriate ALHP repository is **above** the Archlinux
repo.

Example for `x86-64-v3`, with the optional tips explained below marked `# tip`:

```editorconfig
[core-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist
# tip: hide duplicate search results
Usage = Sync Install Upgrade

# tip: fall back to a lower level
[core-x86-64-v2]
Include = /etc/pacman.d/alhp-mirrorlist
Usage = Sync Install Upgrade

[core]
Include = /etc/pacman.d/mirrorlist

[extra-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist
# tip: hide duplicate search results
Usage = Sync Install Upgrade

# tip: fall back to a lower level
[extra-x86-64-v2]
Include = /etc/pacman.d/alhp-mirrorlist
Usage = Sync Install Upgrade

[extra]
Include = /etc/pacman.d/mirrorlist

# if you need [multilib] support
[multilib-x86-64-v3]
Include = /etc/pacman.d/alhp-mirrorlist
# tip: hide duplicate search results
Usage = Sync Install Upgrade

# tip: fall back to a lower level
[multilib-x86-64-v2]
Include = /etc/pacman.d/alhp-mirrorlist
Usage = Sync Install Upgrade

[multilib]
Include = /etc/pacman.d/mirrorlist
```

Replace `x86-64-v3` with the x86-64 feature level you want to enable.

> [!TIP]
> **Hide duplicate search results:** `Usage = Sync Install Upgrade` leaves out `Search`, so `pacman -Ss` lists each
> package once, from the Arch repos, while installs and upgrades still come from ALHP.

> [!TIP]
> **Fall back to a lower level:** ALHP repos of a lower level can be stacked below yours. A package missing from your
> level, e.g. because it failed to build there, then comes from the lower level instead of Arch. Once your level has it,
> pacman only switches on the package's next version. Leave these sections out on `x86-64-v2`.

### 5. Update package database and upgrade

```
pacman -Suy
```

## FAQ

### Remove ALHP packages

To disable ALHP, remove all *x86-64-vX* entries in `/etc/pacman.conf` and remove `alhp-keyring` and `alhp-mirrorlist`.

After that, you can update pacman's databases and downgrade all packages, like

```
pacman -Suuy
```

### LTO

Packages are built with LTO, unless it is known to break them or their LTO link fails, in which case they are built
without it. [More details.](https://somegit.dev/ALHP/ALHP.GO/issues/52)
LTO status is visible per package on the package status page.

### Linux Kernel packages

`KCFLAGS`/`KCPPFLAGS` are used to build the kernel packages with our additional flags.

### Directly linked kernel modules

ALHP's kernel packages carry our increased pkgrel in their kernel release (e.g. `-arch1-1.1` instead of `-arch1-1`),
while prebuilt module packages such as `nvidia-open`, `nvidia-open-lts`, `acpi_call`, `vhba-module` or `r8168-lts` are
built for Arch's kernel. **Their modules will not load with an ALHP kernel.** Use the `dkms` variant where one exists
(e.g. `nvidia-open-dkms`, `acpi_call-dkms`, `vhba-module-dkms`), which builds the module for the running kernel.
This is tracked in [#68](https://somegit.dev/ALHP/ALHP.GO/issues/68).

### Mirrors

You want to mirror ALHP? You are welcome to do
so, [see alhp-mirrorlist for how to become one](https://somegit.dev/ALHP/alhp-mirrorlist#how-to-become-a-mirror).

### What packages are built

Everything in `core`, `extra` and `multilib`, except `any` architecture packages, Haskell packages (GHC ignores our
flags) and a list of excluded packages, which is tracked with the reasons in
[#16](https://somegit.dev/ALHP/ALHP.GO/issues/16). The
[package status page](https://status.alhp.dev) shows every package's state, including why a package was skipped
(e.g. `blacklisted`).

### Why is package X not up-to-date

Also relevant for: **I can't find package X / Application X fails to start because it links to an old/newer lib**

ALHP builds packages **after** they are released in the official Archlinux repos (excluding `[*-testing]`).
This will cause packages to be delayed if the current batch contains many packages, or packages that take a while to
build (e.g. `chromium`).

You can always check on the progress of the current build cycle on the [package status page](https://status.alhp.dev).
Please refrain from opening issues caused by packages currently in queue/not yet built/not yet moved to the repo.
Please keep in mind that large rebuilds such as `openssl` or `python` can take days to complete on our current build
hardware. Upgrading while such a rebuild is in progress can leave ALHP and Arch packages at mismatched versions, which
is tracked in [#281](https://somegit.dev/ALHP/ALHP.GO/issues/281).

### Debug symbols

ALHP provides a debuginfod instance under `debuginfod.alhp.dev`.

To use it, have `debuginfod` installed on your system and add it to your `DEBUGINFOD_URLS` with:

```bash
echo "https://debuginfod.alhp.dev" > /etc/debuginfod/alhp.urls
```

### Switch between levels

If you want to switch between levels, e.g. from `x86-64-v3` to `x86-64-v4`, you need to revert to official packages
first, and then enable your desired repos again.

1. Comment out or remove the ALHP repo entries in `/etc/pacman.conf`.
2. Downgrade packages with `pacman -Suuy`.
3. Clear pacman's package cache with `pacman -Scc`.
4. Uncomment/add your desired repos to `/etc/pacman.conf` and update with `pacman -Suy`.

## Matrix

For any non-issue questions, or if you just want to chat, ALHP has a Matrix
room [here](https://matrix.to/#/#alhp:ofsg.eu) (`#alhp@ofsg.eu`). You can also find me (@idlegandalf)
in `#archlinux:archlinux.org`.

## Donations

I appreciate any money you want to throw my way, but donations are strictly optional. Donations are primarily used to
pay for server costs. Also consider [donating to the **Archlinux Team**](https://archlinux.org/donate/), without their
work ALHP would not be possible.

[![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/anonfunc/)

## License and Legal

This project and all of its source code is released under the terms of the GNU General Public License, version 2
or any later version. See [LICENSE](https://somegit.dev/ALHP/ALHP.GO/src/branch/main/LICENSE) for details.
