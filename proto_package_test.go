package main

import (
	"os"
	"strings"
	"testing"
)

const PkgbuildTest = `# Maintainer: Jan Alexander Steffens (heftig) <heftig@archlinux.org>

pkgname=gnome-todo
pkgver=41.0+r69+ga9a5b7cd
pkgrel=1
pkgdesc="Task manager for GNOME"
url="https://wiki.gnome.org/Apps/Todo"
arch=(x86_64)
license=(GPL)
depends=(evolution-data-server libpeas python gtk4 libportal-gtk4 libadwaita)
makedepends=(gobject-introspection appstream-glib git meson yelp-tools)
groups=(gnome-extra)
_commit=a9a5b7cdde0244331d2d49220f04018be60c018e  # master
source=("git+https://gitlab.gnome.org/GNOME/gnome-todo.git#commit=$_commit")
sha256sums=('SKIP')

pkgver() {
  cd $pkgname
  git describe --tags | sed 's/^GNOME_TODO_//;s/_/./g;s/[^-]*-g/r&/;s/-/+/g'

}

prepare() {
  cd $pkgname
}

build() {
  arch-meson $pkgname build
  meson compile -C build
}

check() (
  glib-compile-schemas "${GSETTINGS_SCHEMA_DIR:=$PWD/$pkgname/data}"
  export GSETTINGS_SCHEMA_DIR

  meson test -C build --print-errorlogs
)

package() {
  meson install -C build --destdir "$pkgdir"
}

# vim:set sw=2 et:
`

const PkgbuildTestWithPkgrelSub = `# Maintainer: Jan Alexander Steffens (heftig) <heftig@archlinux.org>

pkgname=gnome-todo
pkgver=41.0+r69+ga9a5b7cd
pkgrel=1.1
pkgdesc="Task manager for GNOME"
url="https://wiki.gnome.org/Apps/Todo"
arch=(x86_64)
license=(GPL)
depends=(evolution-data-server libpeas python gtk4 libportal-gtk4 libadwaita)
makedepends=(gobject-introspection appstream-glib git meson yelp-tools)
groups=(gnome-extra)
_commit=a9a5b7cdde0244331d2d49220f04018be60c018e  # master
source=("git+https://gitlab.gnome.org/GNOME/gnome-todo.git#commit=$_commit")
sha256sums=('SKIP')

pkgver() {
  cd $pkgname
  git describe --tags | sed 's/^GNOME_TODO_//;s/_/./g;s/[^-]*-g/r&/;s/-/+/g'

}

prepare() {
  cd $pkgname
}

build() {
  arch-meson $pkgname build
  meson compile -C build
}

check() (
  glib-compile-schemas "${GSETTINGS_SCHEMA_DIR:=$PWD/$pkgname/data}"
  export GSETTINGS_SCHEMA_DIR

  meson test -C build --print-errorlogs
)

package() {
  meson install -C build --destdir "$pkgdir"
}

# vim:set sw=2 et:
`

func TestCloneBranch(t *testing.T) { //nolint:paralleltest
	for _, tc := range []struct {
		name      string
		useLatest bool
		tagVer    string
		want      string
	}{
		{"state-tag-default", false, "3.3-4", "3.3-4"},
		{"main-when-drift", true, "3.3-4", "main"},
		{"main-ignores-empty-tag", true, "", "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &ProtoPackage{
				UseLatest: tc.useLatest,
				State:     &StateInfo{TagVer: tc.tagVer},
			}
			if got := p.cloneBranch(); got != tc.want {
				t.Errorf("cloneBranch() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSkipReasonsDistinct(t *testing.T) { //nolint:paralleltest
	if SkipReasonAnyArch == SkipReasonAnyArchMoved {
		t.Fatal("any-arch skip reasons must remain distinguishable: callers and operators inspect skip_reason to tell why a package was dropped")
	}
}

func TestIncreasePkgRel(t *testing.T) { //nolint:paralleltest
	pkgbuild, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Fatal("unable to setup temp. PKGBUILD")
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(pkgbuild.Name())

	_, err = pkgbuild.WriteString(PkgbuildTest)
	if err != nil {
		t.Fatal("unable to write to temp. PKGBUILD")
	}
	_ = pkgbuild.Close()

	buildPkg := &ProtoPackage{
		Pkgbase:  "gnome-todo",
		Pkgbuild: pkgbuild.Name(),
	}

	err = buildPkg.increasePkgRel(1)
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	versionSplit := strings.Split(buildPkg.Version, "-")
	if versionSplit[len(versionSplit)-1] != "1.1" {
		t.Logf("increasePkgRel: expected 1.1 pkgrel, got: %s", buildPkg.Version)
		t.Fail()
	}

	buildPkg.Srcinfo = nil
	err = buildPkg.genSrcinfo()
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	if buildPkg.Srcinfo.Pkgrel != "1.1" {
		t.Logf("increasePkgRel: expected 1.1 pkgrel, got: %s", buildPkg.Srcinfo.Pkgrel)
		t.Fail()
	}
}

func TestIncreasePkgRelWithPkgSub(t *testing.T) { //nolint:paralleltest
	pkgbuild, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Fatal("unable to setup temp. PKGBUILD")
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(pkgbuild.Name())

	_, err = pkgbuild.WriteString(PkgbuildTestWithPkgrelSub)
	if err != nil {
		t.Fatal("unable to write to temp. PKGBUILD")
	}
	_ = pkgbuild.Close()

	buildPkg := &ProtoPackage{
		Pkgbase:  "gnome-todo",
		Pkgbuild: pkgbuild.Name(),
	}

	err = buildPkg.increasePkgRel(1)
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	versionSplit := strings.Split(buildPkg.Version, "-")
	if versionSplit[len(versionSplit)-1] != "1.2" {
		t.Logf("increasePkgRel: expected 1.2 pkgrel, got: %s", buildPkg.Version)
		t.Fail()
	}

	buildPkg.Srcinfo = nil
	err = buildPkg.genSrcinfo()
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	if buildPkg.Srcinfo.Pkgrel != "1.2" {
		t.Logf("increasePkgRel: expected 1.2 pkgrel, got: %s", buildPkg.Srcinfo.Pkgrel)
		t.Fail()
	}
}
