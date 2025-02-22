package main

import (
	"context"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
)

type Package string

// Name returns package's name
func (pkg Package) Name() string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	return strings.Join(fNameSplit[:len(fNameSplit)-3], "-")
}

// MArch returns package's march
func (pkg Package) MArch() *string {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	res := strings.Join(strings.Split(splitPath[len(splitPath)-4], "-")[1:], "-")
	return &res
}

// Repo returns package's dbpackage.Repository
func (pkg Package) Repo() dbpackage.Repository {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	return dbpackage.Repository(strings.Split(splitPath[len(splitPath)-4], "-")[0])
}

// FullRepo returns package's dbpackage.Repository-march
func (pkg Package) FullRepo() *string {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	return &splitPath[len(splitPath)-4]
}

// Version returns version extracted from package
func (pkg Package) Version() string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	return strings.Join(fNameSplit[len(fNameSplit)-3:len(fNameSplit)-1], "-")
}

// Arch returns package's Architecture
func (pkg Package) Arch() *string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	fNameSplit = strings.Split(fNameSplit[len(fNameSplit)-1], ".")
	return &fNameSplit[0]
}

// HasValidSignature returns if package has valid detached signature file
func (pkg Package) HasValidSignature() (bool, error) {
	cmd := exec.Command("gpg", "--verify", string(pkg)+".sig") //nolint:gosec
	res, err := cmd.CombinedOutput()
	switch {
	case cmd.ProcessState.ExitCode() == 2 || cmd.ProcessState.ExitCode() == 1:
		return false, nil
	case cmd.ProcessState.ExitCode() == 0:
		return true, nil
	case err != nil:
		return false, fmt.Errorf("error checking signature: %w (%s)", err, res)
	}

	return false, nil
}

// DBPackage returns ent.DBPackage for package
func (pkg Package) DBPackage(ctx context.Context, db *ent.Client) (*ent.DBPackage, error) {
	return pkg.DBPackageIsolated(ctx, *pkg.MArch(), pkg.Repo(), db)
}

// DBPackageIsolated returns ent.DBPackage like DBPackage, but not relying on the path for march and repo
func (pkg Package) DBPackageIsolated(ctx context.Context, march string, repo dbpackage.Repository, db *ent.Client) (*ent.DBPackage, error) {
	dbPkg, err := db.DBPackage.Query().Where(func(s *sql.Selector) {
		s.Where(
			sql.And(
				sqljson.ValueContains(dbpackage.FieldPackages, pkg.Name()),
				sql.EQ(dbpackage.FieldMarch, march),
				sql.EQ(dbpackage.FieldRepository, repo)),
		)
	}).Only(ctx)
	if ent.IsNotFound(err) {
		log.Debugf("not found in database: %s", pkg.Name())
		return nil, err
	} else if err != nil {
		return nil, err
	}
	return dbPkg, nil
}
