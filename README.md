# ALHP

[![](https://img.shields.io/badge/license-GPL-blue)](https://git.harting.dev/anonfunc/ALHP.GO/src/branch/master/LICENSE) [![](https://img.shields.io/badge/package-status-informational)](https://alhp.anonfunc.dev/packages.html) [![](https://img.shields.io/liberapay/patrons/anonfunc.svg?logo=liberapay)](https://liberapay.com/anonfunc/)

Buildbot for Archlinux-based repos build with different
[x86-64 feature levels](https://www.phoronix.com/scan.php?page=news_item&px=GCC-11-x86-64-Feature-Levels), `-O3` and
[LTO](https://en.wikipedia.org/wiki/Interprocedural_optimization).

## Check your system for support

**Important**: Before you enable any of these repos, check if your system supports the feature level you want to enable
(e.g. `x86-64-v3`). You can do that with

```bash
/lib/ld-linux-x86-64.so.2 --help
```

If you don't check beforehand you might be unable to boot your system anymore and need to downgrade any package that you
may have upgraded.

Example output snippet for a system supporting up to `x86-64-v3`:

```
Subdirectories of glibc-hwcaps directories, in priority order:
  x86-64-v4
  x86-64-v3 (supported, searched)
  x86-64-v2 (supported, searched)
```

## Enable Repos

To enable these complement repos you need to install [alhp-keyring](https://aur.archlinux.org/packages/alhp-keyring/)
and [alhp-mirrorlist](https://aur.archlinux.org/packages/alhp-mirrorlist/) from **AUR** and modify `/etc/pacman.conf`
to add them above your regular repos.

### Choose a mirror (optional)

Edit `/etc/pacman.d/alhp-mirrorlist` and comment out/in mirrors you want to have enabled/disabled. Per default selected
is a cloudflare-based mirror which
[*should* provide decent speed worldwide](https://git.harting.dev/ALHP/ALHP.GO/issues/38#issuecomment-891).
> Note: Only `alhp.harting.dev` is hosted by ALHP directly. If you have problems with one mirror,
> open an issue at [alhp-mirrorlist](https://git.harting.dev/ALHP/alhp-mirrorlist).

### Modify /etc/pacman.conf

Add the appropriate repos **above** your regular Archlinux repos.

Example for `x86-64-v3`

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

Replace `x86-64-v3` with your x86-64 feature level.
> ALHP only builds for `x86-64-v3` at the moment (list is subject to change). You can see all available repositories
> [here](https://alhp.harting.dev/).

Update package database and upgrade:
```
pacman -Suy
```

## Remove Repos

To disable ALHP remove all *x86-64-vX* entries in `/etc/pacman.conf` and remove `alhp-keyring` and `alhp-mirrorlist`.

After that you can refresh pacmans databases and downgrade all packages like:
```
pacman -Suuy
```

## Package eligibility

Packages [excluded](https://www.reddit.com/r/archlinux/comments/oflged/alhp_archlinux_recompiled_for_x8664v3_experimental/h4fkinu?utm_source=share&utm_medium=web2x&context=3)
from building (besides all 'any' architecture packages) are being listed in issue #16.
Also [package status page](https://alhp.anonfunc.dev/packages.html).

## FAQ

### LTO

Enabled for all packages build after 04 Nov 2021 12:07:00
UTC. [More details.](https://git.harting.dev/anonfunc/ALHP.GO/issues/52)
LTO status is visible per package on the package status page.

### Mirrors

You want to mirror ALHP? You are welcome to do
so, [see alhp-mirrorlist for how to become one](https://git.harting.dev/ALHP/alhp-mirrorlist#how-to-become-a-mirror).

## Donations

I appreciate any money you want to throw my way, but donations are strictly optional. Donations are primarily used to
pay for server costs. Also consider [donating to the **Archlinux Team**](https://archlinux.org/donate/), without their
work ALHP would not be possible.

[![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/anonfunc/)