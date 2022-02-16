package main

import (
	"context"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"fmt"
	"git.harting.dev/ALHP/ALHP.GO/ent"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"path/filepath"
	"strings"
)

type Package string

// Name returns the name from Package
func (path Package) Name() string {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	return strings.Join(fNameSplit[:len(fNameSplit)-3], "-")
}

func (path Package) MArch() string {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return strings.Join(strings.Split(splitPath[len(splitPath)-4], "-")[1:], "-")
}

func (path Package) Repo() dbpackage.Repository {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return dbpackage.Repository(strings.Split(splitPath[len(splitPath)-4], "-")[0])
}

func (path Package) FullRepo() string {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return splitPath[len(splitPath)-4]
}

func (path Package) Version() string {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	return strings.Join(fNameSplit[len(fNameSplit)-3:len(fNameSplit)-1], "-")
}

func (path Package) Arch() string {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	fNameSplit = strings.Split(fNameSplit[len(fNameSplit)-1], ".")
	return fNameSplit[0]
}

func (path Package) HasValidSignature() (bool, error) {
	cmd := exec.Command("gpg", "--verify", string(path)+".sig")
	res, err := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 2 || cmd.ProcessState.ExitCode() == 1 {
		return false, nil
	} else if cmd.ProcessState.ExitCode() == 0 {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("error checking signature: %w (%s)", err, res)
	}

	return false, nil
}

func (path *Package) DBPackage(db *ent.Client) (*ent.DbPackage, error) {
	return path.DBPackageIsolated(path.MArch(), path.Repo(), db)
}

func (path *Package) DBPackageIsolated(march string, repo dbpackage.Repository, db *ent.Client) (*ent.DbPackage, error) {
	dbPkg, err := db.DbPackage.Query().Where(func(s *sql.Selector) {
		s.Where(
			sql.And(
				sqljson.ValueContains(dbpackage.FieldPackages, path.Name()),
				sql.EQ(dbpackage.FieldMarch, march),
				sql.EQ(dbpackage.FieldRepository, repo)),
		)
	}).Only(context.Background())
	if ent.IsNotFound(err) {
		log.Debugf("Not found in database: %s", path.Name())
		return nil, err
	} else if err != nil {
		return nil, err
	}
	return dbPkg, nil
}
