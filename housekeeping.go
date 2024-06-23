package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
	"sync"
	"time"
)

func housekeeping(repo, march string, wg *sync.WaitGroup) error {
	defer wg.Done()
	fullRepo := repo + "-" + march
	log.Debugf("[%s] start housekeeping", fullRepo)
	packages, err := Glob(filepath.Join(conf.Basedir.Repo, fullRepo, "/**/*.pkg.tar.zst"))
	if err != nil {
		return err
	}

	log.Debugf("[HK/%s] removing orphans, signature check", fullRepo)
	for _, path := range packages {
		mPackage := Package(path)

		dbPkg, err := mPackage.DBPackage(db)
		if ent.IsNotFound(err) {
			log.Infof("[HK] removing orphan %s->%s", fullRepo, filepath.Base(path))
			pkg := &ProtoPackage{
				FullRepo: *mPackage.FullRepo(),
				PkgFiles: []string{path},
				March:    *mPackage.MArch(),
			}
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			continue
		} else if err != nil {
			log.Warningf("[HK] error fetching %s->%q from db: %v", fullRepo, path, err)
			continue
		}

		pkg := &ProtoPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      mPackage.Repo(),
			FullRepo:  *mPackage.FullRepo(),
			DBPackage: dbPkg,
			March:     *mPackage.MArch(),
			Arch:      *mPackage.Arch(),
		}

		matchNoBuild, err := MatchGlobList(pkg.Pkgbase, conf.Blacklist.Packages)
		if err != nil {
			log.Errorf("[HK] %s->%s error parsing no-build glob: %v", pkg.FullRepo, mPackage.Name(), err)
			continue
		}

		// check if package is still part of repo
		dbs, err := alpmHandle.SyncDBs()
		if err != nil {
			return err
		}
		buildManager.alpmMutex.Lock()
		pkgResolved, err := dbs.FindSatisfier(mPackage.Name())
		buildManager.alpmMutex.Unlock()
		if err != nil ||
			pkgResolved.DB().Name() != pkg.DBPackage.Repository.String() ||
			pkgResolved.DB().Name() != pkg.Repo.String() ||
			pkgResolved.Architecture() != pkg.Arch ||
			pkgResolved.Name() != mPackage.Name() ||
			matchNoBuild {
			switch {
			case err != nil:
				log.Infof("[HK] %s->%s not included in repo (resolve error: %v)", pkg.FullRepo, mPackage.Name(), err)
			case pkgResolved.DB().Name() != pkg.DBPackage.Repository.String():
				log.Infof("[HK] %s->%s not included in repo (repo mismatch: repo:%s != db:%s)", pkg.FullRepo,
					mPackage.Name(), pkgResolved.DB().Name(), pkg.DBPackage.Repository.String())
			case pkgResolved.DB().Name() != pkg.Repo.String():
				log.Infof("[HK] %s->%s not included in repo (repo mismatch: repo:%s != pkg:%s)", pkg.FullRepo,
					mPackage.Name(), pkgResolved.DB().Name(), pkg.Repo.String())
			case pkgResolved.Architecture() != pkg.Arch:
				log.Infof("[HK] %s->%s not included in repo (arch mismatch: repo:%s != pkg:%s)", pkg.FullRepo,
					mPackage.Name(), pkgResolved.Architecture(), pkg.Arch)
			case pkgResolved.Name() != mPackage.Name():
				log.Infof("[HK] %s->%s not included in repo (name mismatch: repo:%s != pkg:%s)", pkg.FullRepo,
					mPackage.Name(), pkgResolved.Name(), mPackage.Name())
			case matchNoBuild:
				log.Infof("[HK] %s->%s not included in repo (blacklisted pkgbase %s)", pkg.FullRepo, mPackage.Name(), pkg.Pkgbase)
			}

			// package not found on mirror/db -> not part of any repo anymore
			err = pkg.findPkgFiles()
			if err != nil {
				log.Errorf("[HK] %s->%s unable to get pkg-files: %v", pkg.FullRepo, mPackage.Name(), err)
				continue
			}
			err = db.DBPackage.DeleteOne(pkg.DBPackage).Exec(context.Background())
			pkg.DBPackage = nil
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			if err != nil {
				return err
			}
			continue
		}

		if pkg.DBPackage.LastVerified.Before(pkg.DBPackage.BuildTimeStart) {
			err := pkg.DBPackage.Update().SetLastVerified(time.Now().UTC()).Exec(context.Background())
			if err != nil {
				return err
			}
			// check if pkg signature is valid
			valid, err := mPackage.HasValidSignature()
			if err != nil {
				return err
			}
			if !valid {
				log.Infof("[HK] %s->%s invalid package signature", pkg.FullRepo, pkg.Pkgbase)
				buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
				continue
			}
		}

		// compare db-version with repo version
		repoVer, err := pkg.repoVersion()
		if err == nil && repoVer != dbPkg.RepoVersion {
			log.Infof("[HK] %s->%s update repoVersion %s->%s", pkg.FullRepo, pkg.Pkgbase, dbPkg.RepoVersion, repoVer)
			pkg.DBPackage, err = pkg.DBPackage.Update().SetRepoVersion(repoVer).ClearTagRev().Save(context.Background())
			if err != nil {
				return err
			}
		}
	}

	// check all packages from db for existence
	dbPackages, err := db.DBPackage.Query().Where(
		dbpackage.And(
			dbpackage.RepositoryEQ(dbpackage.Repository(repo)),
			dbpackage.March(march),
		)).All(context.Background())
	if err != nil {
		return err
	}

	log.Debugf("[HK/%s] checking %d packages from database", fullRepo, len(dbPackages))

	for _, dbPkg := range dbPackages {
		pkg := &ProtoPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      dbPkg.Repository,
			March:     dbPkg.March,
			FullRepo:  dbPkg.Repository.String() + "-" + dbPkg.March,
			DBPackage: dbPkg,
		}

		if !pkg.isAvailable(alpmHandle) {
			log.Infof("[HK] %s->%s not found on mirror, removing", pkg.FullRepo, pkg.Pkgbase)
			err = db.DBPackage.DeleteOne(dbPkg).Exec(context.Background())
			if err != nil {
				log.Errorf("[HK] error deleting package %s->%s: %v", pkg.FullRepo, dbPkg.Pkgbase, err)
			}
			continue
		}

		switch {
		case dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion != "":
			// check lastVersionBuild
			if dbPkg.LastVersionBuild != dbPkg.RepoVersion {
				log.Infof("[HK] %s->%s updating lastVersionBuild %s -> %s", fullRepo, dbPkg.Pkgbase, dbPkg.LastVersionBuild, dbPkg.RepoVersion)
				dbPkg, err = dbPkg.Update().SetLastVersionBuild(dbPkg.RepoVersion).Save(context.Background())
				if err != nil {
					log.Warningf("[HK] error updating lastVersionBuild for %s->%s: %v", fullRepo, dbPkg.Pkgbase, err)
				}
			}

			var existingSplits []string
			var missingSplits []string
			for _, splitPkg := range dbPkg.Packages {
				pkgFile := filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch,
					splitPkg+"-"+dbPkg.RepoVersion+"-"+conf.Arch+".pkg.tar.zst")
				_, err = os.Stat(pkgFile)
				switch {
				case os.IsNotExist(err):
					missingSplits = append(missingSplits, splitPkg)
				case err != nil:
					log.Warningf("[HK] error reading package-file %s: %v", splitPkg, err)
				default:
					existingSplits = append(existingSplits, pkgFile)
				}
			}
			if len(missingSplits) > 0 {
				log.Infof("[HK] %s->%s missing split-package(s): %s", fullRepo, dbPkg.Pkgbase, missingSplits)
				pkg.DBPackage, err = pkg.DBPackage.Update().
					ClearRepoVersion().
					ClearTagRev().
					SetStatus(dbpackage.StatusQueued).
					Save(context.Background())
				if err != nil {
					return err
				}

				pkg := &ProtoPackage{
					FullRepo:  fullRepo,
					PkgFiles:  existingSplits,
					March:     march,
					DBPackage: dbPkg,
				}
				buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
			}

			rawState, err := os.ReadFile(filepath.Join(conf.Basedir.Work, stateDir, dbPkg.Repository.String()+"-"+conf.Arch, dbPkg.Pkgbase))
			if err != nil {
				log.Infof("[HK] state not found for %s->%s: %v, removing package", fullRepo, dbPkg.Pkgbase, err)
				pkg := &ProtoPackage{
					FullRepo:  fullRepo,
					PkgFiles:  existingSplits,
					March:     march,
					DBPackage: dbPkg,
				}
				buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
				continue
			}

			state, err := parseState(string(rawState))
			if err != nil {
				log.Warningf("[HK] error parsing state file for %s->%s: %v", fullRepo, dbPkg.Pkgbase, err)
				continue
			}

			if dbPkg.TagRev != nil && state.TagRev == *dbPkg.TagRev && state.PkgVer != dbPkg.Version {
				log.Infof("[HK] reseting package %s->%s with mismatched state information (%s!=%s)",
					fullRepo, dbPkg.Pkgbase, state.PkgVer, dbPkg.Version)
				err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearTagRev().Exec(context.Background())
				if err != nil {
					return err
				}
			}
		case dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion == "":
			log.Infof("[HK] reseting missing package %s->%s with no repo version", fullRepo, dbPkg.Pkgbase)
			err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearTagRev().ClearRepoVersion().Exec(context.Background())
			if err != nil {
				return err
			}
		case dbPkg.Status == dbpackage.StatusSkipped && dbPkg.RepoVersion != "" && strings.HasPrefix(dbPkg.SkipReason, "blacklisted"):
			log.Infof("[HK] delete blacklisted package %s->%s", fullRepo, dbPkg.Pkgbase)
			pkg := &ProtoPackage{
				FullRepo:  fullRepo,
				March:     march,
				DBPackage: dbPkg,
			}
			buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
		case dbPkg.Status == dbpackage.StatusFailed && dbPkg.RepoVersion != "":
			log.Infof("[HK] package %s->%s failed but still present in repo, removing", fullRepo, dbPkg.Pkgbase)
			pkg := &ProtoPackage{
				FullRepo:  fullRepo,
				March:     march,
				DBPackage: dbPkg,
			}
			buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
		}
	}

	log.Debugf("[HK/%s] all tasks finished", fullRepo)
	return nil
}

func logHK() error {
	// check if package for log exists and if error can be fixed by rebuild
	logFiles, err := Glob(filepath.Join(conf.Basedir.Repo, logDir, "/**/*.log"))
	if err != nil {
		return err
	}

	for _, logFile := range logFiles {
		pathSplit := strings.Split(logFile, string(filepath.Separator))
		extSplit := strings.Split(filepath.Base(logFile), ".")
		pkgbase := strings.Join(extSplit[:len(extSplit)-1], ".")
		march := pathSplit[len(pathSplit)-2]

		pkg := ProtoPackage{
			Pkgbase: pkgbase,
			March:   march,
		}

		if exists, err := pkg.exists(); err != nil {
			return err
		} else if !exists {
			_ = os.Remove(logFile)
			continue
		}

		pkgSkipped, err := db.DBPackage.Query().Where(
			dbpackage.Pkgbase(pkg.Pkgbase),
			dbpackage.March(pkg.March),
			dbpackage.StatusEQ(dbpackage.StatusSkipped),
		).Exist(context.Background())
		if err != nil {
			return err
		}

		if pkgSkipped {
			_ = os.Remove(logFile)
			continue
		}

		logContent, err := os.ReadFile(logFile)
		if err != nil {
			return err
		}
		sLogContent := string(logContent)

		if rePortError.MatchString(sLogContent) || reSigError.MatchString(sLogContent) || reDownloadError.MatchString(sLogContent) ||
			reDownloadError2.MatchString(sLogContent) {
			rows, err := db.DBPackage.Update().Where(dbpackage.Pkgbase(pkg.Pkgbase), dbpackage.March(pkg.March),
				dbpackage.StatusEQ(dbpackage.StatusFailed)).ClearTagRev().SetStatus(dbpackage.StatusQueued).Save(context.Background())
			if err != nil {
				return err
			}

			if rows > 0 {
				log.Infof("[HK/%s/%s] fixable build-error detected, requeueing package (%d)", pkg.March, pkg.Pkgbase, rows)
			}
		} else if reLdError.MatchString(sLogContent) || reRustLTOError.MatchString(sLogContent) {
			rows, err := db.DBPackage.Update().Where(
				dbpackage.Pkgbase(pkg.Pkgbase),
				dbpackage.March(pkg.March),
				dbpackage.StatusEQ(dbpackage.StatusFailed),
				dbpackage.LtoNotIn(dbpackage.LtoAutoDisabled, dbpackage.LtoDisabled),
			).ClearTagRev().SetStatus(dbpackage.StatusQueued).SetLto(dbpackage.LtoAutoDisabled).Save(context.Background())
			if err != nil {
				return err
			}

			if rows > 0 {
				log.Infof("[HK/%s/%s] fixable build-error detected (linker-error), requeueing package (%d)", pkg.March, pkg.Pkgbase, rows)
			}
		}
	}
	return nil
}

func debugHK() {
	for _, march := range conf.March {
		if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, march)); err == nil {
			log.Debugf("[DHK/%s] start cleanup debug packages", march)
			cleanCmd := exec.Command("paccache", "-rc", filepath.Join(conf.Basedir.Debug, march), "-k", "1") //nolint:gosec
			res, err := cleanCmd.CombinedOutput()
			if err != nil {
				log.Warningf("[DHK/%s] cleanup debug packages failed: %v (%s)", march, err, string(res))
			}
		}
	}
}
