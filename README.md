# alhp

Build script for archlinux instructionset enabled repos.
All packages are build with -march=<cpu-set> and -O3. Some packages will not build with -O3, they will just be provided from the official repos as usual.

## Check your system for support

**Important**: Before you enable any of these repos, check if your system supports x86-64-v3. You can do that with `/lib/ld-linux-x86-64.so.2 --help`. If you don't check beforehand you might be unable to boot your system anymore and need to downgrade any package that you may have upgraded.

Example output snippet for a system supporting up to `x86-64-v3`:

```
Subdirectories of glibc-hwcaps directories, in priority order:
  x86-64-v4
  x86-64-v3 (supported, searched)
  x86-64-v2 (supported, searched)
```

## Enable Repos

To enable these complement repos you need to add them above the regular repos in `/etc/pacman.conf`

### Example pacman.conf

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

Replace `x86-64-v3` with your cpu-set. More information about all available options on [this gcc page](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html).
Currently, alhp.harting.dev only builds for `x86-64-v3` (list is subject to change).
You can see all available repositories [here](https://alhp.harting.dev/). 

After finished adding the repos to `pacman.conf` you need to import and sign the used pgp key:

Import:
```
pacman-key --keyserver keyserver.ubuntu.com --recv-keys 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298
```

Local sign:
```
pacman-key --lsign-key 0D4D2FDAF45468F3DDF59BEDE3D0D2CD3952E298
```

Update package database:
```
pacman -Sy
```

## Replace packages
Following command reinstalls all packages found in the repo **extra-x86-64-v3** that are already installed.
Replace `extra-x86-64-v3` with whatever repo you want to install.

```shell script
pacman -S $(pacman -Sl x86-64-v3 | grep installed | cut -f 2 -d " " | perl -pe 's/\R/ /g;')
```

This is only needed once, new updates are coming from this new repo then, as usual.