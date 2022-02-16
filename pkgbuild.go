package main

import (
	"path/filepath"
	"strings"
)

type PKGBUILD string

// FullRepo returns full-repo from PKGBUILD'S path
func (p PKGBUILD) FullRepo() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-2]
}

// Repo returns repo from PKGBUILD's path
func (p PKGBUILD) Repo() string {
	return strings.Split(p.FullRepo(), "-")[0]
}

// PkgBase returns pkgbase from PKGBUILD's path
func (p PKGBUILD) PkgBase() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-4]
}
