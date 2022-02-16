package main

import (
	"path/filepath"
	"strings"
)

type PKGBUILD string

func (p PKGBUILD) FullRepo() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-2]
}

func (p PKGBUILD) Repo() string {
	return strings.Split(p.FullRepo(), "-")[0]
}

func (p PKGBUILD) PkgBase() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-4]
}
