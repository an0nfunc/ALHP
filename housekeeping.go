package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"os"
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
	log.Debugf("[%s] Start housekeeping", fullRepo)
	packages, err := Glob(filepath.Join(conf.Basedir.Repo, fullRepo, "/**/*.pkg.tar.zst"))
	if err != nil {
		return err
	}

	log.Debugf("[HK/%s] removing orphans, signature check", fullRepo)
	for _, path := range packages {
		mPackage := Package(path)

		dbPkg, err := mPackage.DBPackage(db)
		if ent.IsNotFound(err) {
			log.Infof("[HK/%s] removing orphan %s", fullRepo, filepath.Base(path))
			pkg := &ProtoPackage{
				FullRepo: mPackage.FullRepo(),
				PkgFiles: []string{path},
				March:    mPackage.MArch(),
			}
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			continue
		} else if err != nil {
			log.Warningf("[HK/%s] Problem fetching package from db for %s: %v", fullRepo, path, err)
			continue
		}

		pkg := &ProtoPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      mPackage.Repo(),
			FullRepo:  mPackage.FullRepo(),
			DBPackage: dbPkg,
			March:     mPackage.MArch(),
			Arch:      mPackage.Arch(),
		}

		var upstream string
		switch pkg.DBPackage.Repository {
		case dbpackage.RepositoryCore, dbpackage.RepositoryExtra:
			upstream = "upstream-core-extra"
		case dbpackage.RepositoryCommunity:
			upstream = "upstream-community"
		}
		pkg.Pkgbuild = filepath.Join(conf.Basedir.Work, upstreamDir, upstream, dbPkg.Pkgbase, "repos",
			pkg.DBPackage.Repository.String()+"-"+conf.Arch, "PKGBUILD")

		// check if package is still part of repo
		dbs, err := alpmHandle.SyncDBs()
		if err != nil {
			return err
		}
		buildManager.alpmMutex.Lock()
		pkgResolved, err := dbs.FindSatisfier(mPackage.Name())
		buildManager.alpmMutex.Unlock()
		if err != nil || pkgResolved.DB().Name() != pkg.DBPackage.Repository.String() || pkgResolved.DB().Name() != pkg.Repo.String() ||
			pkgResolved.Architecture() != pkg.Arch || pkgResolved.Name() != mPackage.Name() {
			// package not found on mirror/db -> not part of any repo anymore
			log.Infof("[HK/%s/%s] not included in repo", pkg.FullRepo, mPackage.Name())
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			err = db.DbPackage.DeleteOne(pkg.DBPackage).Exec(context.Background())
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
				log.Infof("[HK/%s/%s] invalid package signature", pkg.FullRepo, pkg.Pkgbase)
				buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
				continue
			}
		}

		// compare db-version with repo version
		repoVer, err := pkg.repoVersion()
		if err == nil && repoVer != dbPkg.RepoVersion {
			log.Infof("[HK/%s/%s] update %s->%s in db", pkg.FullRepo, pkg.Pkgbase, dbPkg.RepoVersion, repoVer)
			pkg.DBPackage, err = pkg.DBPackage.Update().SetRepoVersion(repoVer).ClearHash().Save(context.Background())
			if err != nil {
				return err
			}
		}
	}

	// check all packages from db for existence
	dbPackages, err := db.DbPackage.Query().Where(
		dbpackage.And(
			dbpackage.RepositoryEQ(dbpackage.Repository(repo)),
			dbpackage.March(march),
		)).All(context.Background())
	if err != nil {
		return err
	}

	log.Debugf("[HK/%s] checking %d existing package-files", fullRepo, len(dbPackages))

	for _, dbPkg := range dbPackages {
		pkg := &ProtoPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      dbPkg.Repository,
			March:     dbPkg.March,
			FullRepo:  dbPkg.Repository.String() + "-" + dbPkg.March,
			DBPackage: dbPkg,
		}

		if !pkg.isAvailable(alpmHandle) {
			log.Infof("[HK/%s/%s] not found on mirror, removing", pkg.FullRepo, pkg.Pkgbase)
			err = db.DbPackage.DeleteOne(dbPkg).Exec(context.Background())
			if err != nil {
				log.Errorf("[HK] Error deleting package %s: %v", dbPkg.Pkgbase, err)
			}
			continue
		}

		switch {
		case dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion != "":
			// check lastVersionBuild
			if dbPkg.LastVersionBuild != dbPkg.RepoVersion {
				oldVer := dbPkg.LastVersionBuild
				dbPkg, err = dbPkg.Update().SetLastVersionBuild(dbPkg.RepoVersion).Save(context.Background())
				if err != nil {
					log.Warningf("[HK/%s] error updating lastVersionBuild for %s: %v", fullRepo, dbPkg.Pkgbase, err)
				}
				log.Infof("[HK/%s] updated lastVersionBuild %s -> %s", fullRepo, oldVer, dbPkg.RepoVersion)
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
				log.Infof("[HK/%s] missing split-package(s) %s for pkgbase %s", fullRepo, missingSplits, dbPkg.Pkgbase)
				pkg.DBPackage, err = pkg.DBPackage.Update().ClearRepoVersion().ClearHash().SetStatus(dbpackage.StatusQueued).Save(context.Background())
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
		case dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion == "":
			log.Infof("[HK] reseting missing package %s with no repo version", dbPkg.Pkgbase)
			err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearHash().ClearRepoVersion().Exec(context.Background())
			if err != nil {
				return err
			}
		case dbPkg.Status == dbpackage.StatusSkipped && dbPkg.RepoVersion != "" && strings.HasPrefix(dbPkg.SkipReason, "blacklisted"):
			log.Infof("[HK] delete blacklisted package %s", dbPkg.Pkgbase)
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

		pkgSkipped, err := db.DbPackage.Query().Where(
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

		if rePortError.MatchString(sLogContent) || reSigError.MatchString(sLogContent) || reDownloadError.MatchString(sLogContent) {
			rows, err := db.DbPackage.Update().Where(dbpackage.And(dbpackage.Pkgbase(pkg.Pkgbase), dbpackage.March(pkg.March),
				dbpackage.StatusEQ(dbpackage.StatusFailed))).ClearHash().SetStatus(dbpackage.StatusQueued).Save(context.Background())
			if err != nil {
				return err
			}

			if rows > 0 {
				log.Infof("[HK/%s/%s] fixable build-error detected, requeueing package (%d)", pkg.March, pkg.Pkgbase, rows)
			}
		} else if reLdError.MatchString(sLogContent) || reRustLTOError.MatchString(sLogContent) {
			rows, err := db.DbPackage.Update().Where(
				dbpackage.Pkgbase(pkg.Pkgbase),
				dbpackage.March(pkg.March),
				dbpackage.StatusEQ(dbpackage.StatusFailed),
				dbpackage.LtoNotIn(dbpackage.LtoAutoDisabled, dbpackage.LtoDisabled),
			).ClearHash().SetStatus(dbpackage.StatusQueued).SetLto(dbpackage.LtoAutoDisabled).Save(context.Background())
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
