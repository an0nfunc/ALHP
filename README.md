# ALHP

![](https://img.shields.io/badge/license-GPL-blue) ![](https://img.shields.io/liberapay/patrons/anonfunc.svg?logo=liberapay)

Build script for archlinux instructionset enabled repos. All packages are build with `-march=<cpu-set> -O3`. Some
packages will fail to build, they will just be provided from the official repos as usual.

[Package status page](https://alhp.anonfunc.dev/packages.html)

## Check your system for support

**Important**: Before you enable any of these repos, check if your system supports x86-64-v3. You can do that
with `/lib/ld-linux-x86-64.so.2 --help`. If you don't check beforehand you might be unable to boot your system anymore
and need to downgrade any package that you may have upgraded.

Example output snippet for a system supporting up to `x86-64-v3`:

```
Subdirectories of glibc-hwcaps directories, in priority order:
  x86-64-v4
  x86-64-v3 (supported, searched)
  x86-64-v2 (supported, searched)
```

## Enable Repos

To enable these complement repos you need to add them above the regular repos in `/etc/pacman.conf`

### Choose a mirror (optional)

You can choose from different available mirrors.
> Note: Only `alhp.harting.dev` is hosted by ALHP directly. Make sure you use an up-to-date mirror.

- `alhp.harting.dev` (Tier 0, Central Europe)
- `www.gardling.com/alhp` (Tier 1, North America, provided by @titaniumtown)

### Example pacman.conf

Replace `alhp.harting.dev` if you want to use another mirror (see section above).

```editorconfig
[core-x86-64-v3]
Server = https://alhp.harting.dev/$repo/os/$arch/

[extra-x86-64-v3]
Server = https://alhp.harting.dev/$repo/os/$arch/

[community-x86-64-v3]
Server = https://alhp.harting.dev/$repo/os/$arch/

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[community]
Include = /etc/pacman.d/mirrorlist
```

Replace `x86-64-v3` with your cpu-set. More information about all available options
on [this gcc page](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html). Currently, alhp.harting.dev only builds
for `x86-64-v3` (list is subject to change). You can see all available repositories [here](https://alhp.harting.dev/).

After finished adding the repos to `pacman.conf` you need to import and sign the used pgp key:

Import:

```
pacman-key --keyserver keyserver.ubuntu.com --recv-keys 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298
```

Local sign:

```
pacman-key --lsign-key 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298
```

Update package database and upgrade:

```
pacman -Suy
```

## Remove Repos

To disable ALHP remove all *-x86-64-v3 entries in `/etc/pacman.conf`.

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
LTO status visible per package on the package status page.

### error: *-x86-64-v3: signature from "Archlinux CIE Repos (Build 2020/2021) <cie@harting.dev>" is unknown trust

You get this because the new, extended key has unknown trust value attached to it. To fix it, first import the key again
to be sure you got the extended one:
`pacman-key --keyserver keyserver.ubuntu.com --recv-keys 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298`

After that you just have to set the trust on this key with (as root, for `pacman-key`):

```
pacman-key --edit-key 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298

pub  rsa4096/E3D0D2CD3952E298
     created: 2020-08-12  expires: 2022-07-09  usage: SC  
     trust: unknown       validity: unknown
[ unknown] (1). Archlinux CIE Repos (Build 2020/2021) <cie@harting.dev>

gpg> trust
pub  rsa4096/E3D0D2CD3952E298
     created: 2020-08-12  expires: 2022-07-09  usage: SC  
     trust: unknown       validity: unknown
[ unknown] (1). Archlinux CIE Repos (Build 2020/2021) <cie@harting.dev>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 4
````

### Mirrors

You want to mirror ALHP? You are welcome to do
so, [see this issue for how to become one](https://git.harting.dev/anonfunc/ALHP.GO/issues/38#issuecomment-744).

### Donations

I appreciate any money you want to throw my way, but donations are strictly optional. Also
consider [donating to the Archlinux Team](https://archlinux.org/donate/), without their work ALHP would not be possible.

[![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/anonfunc/)