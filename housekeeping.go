package main

import (
	"context"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
	"sync"
	"time"
)

const defaultSigRecheckInterval = 24 * time.Hour

func sigRecheckInterval() time.Duration {
	return confDuration(conf.Housekeeping.SignatureRecheckInterval, defaultSigRecheckInterval,
		"housekeeping.signature_recheck_interval")
}

func housekeeping(ctx context.Context, repo, march string, provided providedSonames, wg *sync.WaitGroup) error {
	defer wg.Done()
	fullRepo := repo + "-" + march
	log.Debugf("[%s] start housekeeping", fullRepo)
	packages, err := Glob(filepath.Join(conf.Basedir.Repo, fullRepo, "/**/*.pkg.tar.zst"))
	if err != nil {
		return err
	}

	if err := repoDBHK(ctx, fullRepo, packages); err != nil {
		log.Warningf("[HK/%s] repo-db check failed: %v", fullRepo, err)
	}

	log.Debugf("[HK/%s] removing orphans, signature check", fullRepo)
	backfilled := 0
	for _, path := range packages {
		mPackage := Package(path)

		dbPkg, err := mPackage.DBPackage(ctx, db)
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
			MatchGlobList(pkg.Pkgbase, conf.Blacklist.Packages) {
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
			case MatchGlobList(pkg.Pkgbase, conf.Blacklist.Packages):
				log.Infof("[HK] %s->%s not included in repo (blacklisted pkgbase %s)", pkg.FullRepo, mPackage.Name(), pkg.Pkgbase)
			}

			// package not found on mirror/db -> not part of any repo anymore
			err = pkg.findPkgFiles()
			if err != nil {
				log.Errorf("[HK] %s->%s unable to get pkg-files: %v", pkg.FullRepo, mPackage.Name(), err)
				continue
			}
			err = db.DBPackage.DeleteOne(pkg.DBPackage).Exec(ctx)
			pkg.DBPackage = nil
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			if err != nil {
				return err
			}
			continue
		}

		needsSigRecheck := pkg.DBPackage.LastVerified.Before(pkg.DBPackage.BuildTimeStart) ||
			time.Since(pkg.DBPackage.LastVerified) > sigRecheckInterval()

		if needsSigRecheck {
			valid, err := mPackage.HasValidSignature()
			if err != nil {
				return err
			}
			if !valid {
				log.Infof("[HK] %s->%s invalid package signature, purging+requeue", pkg.FullRepo, pkg.Pkgbase)
				pkg.DBPackage, err = pkg.DBPackage.Update().
					SetStatus(dbpackage.StatusQueued).
					ClearTagRev().
					SetLastVerified(time.Now().UTC()).
					Save(ctx)
				if err != nil {
					return err
				}
				buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
				continue
			}
			if err := pkg.DBPackage.Update().SetLastVerified(time.Now().UTC()).Exec(ctx); err != nil {
				return err
			}
		}

		// compare db-version with repo version
		repoVer, err := pkg.repoVersion()
		if err == nil && repoVer != dbPkg.RepoVersion {
			log.Infof("[HK] %s->%s update repoVersion %s->%s", pkg.FullRepo, pkg.Pkgbase, dbPkg.RepoVersion, repoVer)
			pkg.DBPackage, err = pkg.DBPackage.Update().SetRepoVersion(repoVer).ClearTagRev().Save(ctx)
			if err != nil {
				return err
			}
		}

		// detect packages linked against a soname the repos no longer carry.
		// Purging drops clients back to upstream Arch's working package right
		// away, the requeue then supersedes it with a pkgrel-bumped rebuild.
		// Only settled packages, for the same reason as the drift check below.
		if pkg.DBPackage.Status == dbpackage.StatusLatest {
			stale := staleRecorded(pkg.DBPackage.Sonames, provided)

			// packages built before sonames were recorded have no baseline, so
			// read it off what is published. Bounded per repo per cycle: this
			// decompresses every package and the whole repo needs one pass.
			// Gated on nil, not on length: a scanned package with nothing
			// trackable records an empty slice, and treating that as unscanned
			// would re-scan it every cycle and starve the budget.
			if pkg.DBPackage.Sonames == nil && backfilled < sonameBackfillPerRepo {
				backfilled++
				recorded, bErr := backfillSonames(ctx, pkg, pkgResolved, provided)
				if bErr != nil {
					log.Warningf("[HK] %s->%s soname backfill failed: %v", pkg.FullRepo, pkg.Pkgbase, bErr)
				} else {
					stale = recorded
				}
			}

			if len(stale) > 0 {
				log.Infof("[HK] %s->%s soname mismatch (%s), purging+requeue", pkg.FullRepo, pkg.Pkgbase,
					mismatchStrings(stale))
				pkg.DBPackage, err = pkg.DBPackage.Update().
					SetStatus(dbpackage.StatusQueued).
					ClearTagRev().
					ClearSonames().
					Save(ctx)
				if err != nil {
					return err
				}
				buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
				continue
			}
		}

		// detect upstream version drift: Arch sometimes ships a pkgrel
		// rebuild without updating state.git, so state.TagRev never
		// changes and genQueue never re-queues. Compare directly against
		// the pacman sync DB (always current) and force a re-queue.
		// Only act on settled packages; a Queued/Building/Delayed row is
		// already moving and our SetStatus(Queued) would race it.
		// Compare against RepoVersion (what we actually published): the
		// Version column gets rewritten to state.PkgVer by isEligible's
		// "repo higher than PKGBUILD" branch on subsequent passes, so it
		// would falsely report drift on every cycle for drift-built pkgs.
		if pkg.DBPackage.Status == dbpackage.StatusLatest &&
			pkg.DBPackage.RepoVersion != "" && pkgResolved.Version() != "" &&
			alpm.VerCmp(pkgResolved.Version(), pkg.DBPackage.RepoVersion) > 0 {
			log.Infof("[HK] %s->%s upstream version drift detected (repo: %s < upstream: %s), requeuing",
				pkg.FullRepo, pkg.Pkgbase, pkg.DBPackage.RepoVersion, pkgResolved.Version())
			pkg.DBPackage, err = pkg.DBPackage.Update().
				SetStatus(dbpackage.StatusQueued).
				ClearTagRev().
				Save(ctx)
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
		)).All(ctx)
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

		if !pkg.isAvailable(ctx, alpmHandle) {
			log.Infof("[HK] %s->%s not found on mirror, removing", pkg.FullRepo, pkg.Pkgbase)
			err = db.DBPackage.DeleteOne(dbPkg).Exec(ctx)
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
				nDBPkg, err := dbPkg.Update().SetLastVersionBuild(dbPkg.RepoVersion).Save(ctx)
				if err != nil {
					log.Warningf("[HK] error updating lastVersionBuild for %s->%s: %v", fullRepo, dbPkg.Pkgbase, err)
				} else {
					dbPkg = nDBPkg
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
					Save(ctx)
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

			// A drift rebuild that built from main and picked up a tag upstream
			// staged but never released. Purge it and rebuild from the pinned
			// tag; leaving it published ships a package no mirror carries.
			//
			// This assumes conf.Blacklist.Repo excludes the sub-repos, as the
			// shipped config does. genQueue would otherwise queue testing and
			// staging state files too, and such a build is legitimately ahead of
			// both the released state file and the mirror while looking identical
			// here: TagRev cannot tell the two apart, because movePackagesLive
			// re-pins it from the released state file for every published row.
			// The result would be a purge and rebuild every cycle.
			if pkg.SyncPkg != nil && aheadOfUpstream(dbPkg.Version, state.PkgVer, pkg.SyncPkg.Version()) {
				log.Infof("[HK] %s->%s published %s which upstream never released (state: %s, upstream repo: %s), purging",
					fullRepo, dbPkg.Pkgbase, dbPkg.Version, state.PkgVer, pkg.SyncPkg.Version())
				pkg.DBPackage, err = pkg.DBPackage.Update().
					SetStatus(dbpackage.StatusQueued).
					ClearTagRev().
					ClearRepoVersion().
					Save(ctx)
				if err != nil {
					return err
				}
				buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
				continue
			}

			// Only reset when state.git has moved ahead of us. If dbPkg is
			// already at-or-above state.PkgVer the mismatch is from a drift
			// rebuild (built from main while state.git stayed stale) and we
			// must not bounce it back to queued — that produces a build loop.
			if dbPkg.TagRev != nil && state.TagRev == *dbPkg.TagRev &&
				state.PkgVer != dbPkg.Version &&
				alpm.VerCmp(state.PkgVer, dbPkg.Version) > 0 {
				log.Infof("[HK] reseting package %s->%s with mismatched state information (%s!=%s)",
					fullRepo, dbPkg.Pkgbase, state.PkgVer, dbPkg.Version)
				err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearTagRev().Exec(ctx)
				if err != nil {
					return err
				}
			}
		case dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion == "":
			log.Infof("[HK] reseting missing package %s->%s with no repo version", fullRepo, dbPkg.Pkgbase)
			err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearTagRev().ClearRepoVersion().Exec(ctx)
			if err != nil {
				return err
			}
		case dbPkg.Status == dbpackage.StatusSkipped && dbPkg.RepoVersion != "" && !strings.HasPrefix(dbPkg.SkipReason, "delayed"):
			log.Infof("[HK] delete skipped package %s->%s", fullRepo, dbPkg.Pkgbase)
			pkg := &ProtoPackage{
				FullRepo:  fullRepo,
				March:     march,
				DBPackage: dbPkg,
			}
			buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
		case dbPkg.Status == dbpackage.StatusSkipped && dbPkg.SkipReason == "blacklisted" && !MatchGlobList(pkg.Pkgbase, conf.Blacklist.Packages):
			log.Infof("[HK] requeue previously blacklisted package %s->%s", fullRepo, dbPkg.Pkgbase)
			err = dbPkg.Update().SetStatus(dbpackage.StatusQueued).ClearSkipReason().ClearTagRev().Exec(ctx)
			if err != nil {
				return err
			}
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

// backfillSonames reads the needed sonames off a package that predates soname
// recording, and reports the ones the repos no longer satisfy. When the package
// is fine its baseline is stored, so later cycles are a map lookup instead of
// another pass over the artifacts.
//
// Declared dependencies come from the upstream package rather than a SRCINFO:
// ALHP builds the same PKGBUILD, so the dependency list is the same, and no
// clone is needed to read it.
func backfillSonames(ctx context.Context, pkg *ProtoPackage, syncPkg alpm.IPackage,
	provided providedSonames,
) ([]SonameMismatch, error) {
	if err := pkg.findPkgFiles(); err != nil {
		return nil, err
	}

	// findPkgFiles matches on pkgname alone, so an artifact paccache has not
	// collected yet would fold its own sonames into the scan. Filtered into a
	// local slice: pkg.PkgFiles is what the caller's purge acts on, and it has
	// to keep covering every version on disk.
	published := make([]string, 0, len(pkg.PkgFiles))
	for _, file := range pkg.PkgFiles {
		if Package(file).Version() == pkg.DBPackage.RepoVersion && !Package(file).IsDebug() {
			published = append(published, file)
		}
	}

	scan, err := scanPackagesSonames(published)
	if err != nil {
		return nil, err
	}

	recorded := []string{}
	if len(scan.Needed) > 0 {
		buildManager.alpmMutex.Lock()
		depends := syncPkg.Depends().Slice()
		deps := make([]string, 0, len(depends))
		for _, dep := range depends {
			deps = append(deps, dep.Name)
		}
		stale, sErr := staleAgainstDeps(scan, deps, alpmHandle, provided)
		buildManager.alpmMutex.Unlock()
		if sErr != nil {
			return nil, sErr
		}
		if len(stale) > 0 {
			return stale, nil
		}
		recorded = scan.trackable(provided)
	}

	// record even when there is nothing trackable, so this package is not
	// re-scanned on every future cycle
	if err := pkg.DBPackage.Update().SetSonames(recorded).Exec(ctx); err != nil {
		return nil, fmt.Errorf("error recording sonames: %w", err)
	}
	return nil, nil
}

// repoDBHK compares a repo's pacman db against the package files on disk.
// Nothing else does: the loops above compare files against db_packages rows,
// and repoVersion reads the version off the filename, so a db entry pointing at
// a deleted file (404 for clients) or a package on disk the db never learned
// about (invisible to clients) passes every existing check.
func repoDBHK(ctx context.Context, fullRepo string, onDisk []string) error {
	repoDir := filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch)
	dbFile := repoDBPath(fullRepo)
	if _, err := os.Stat(dbFile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	listed, err := repoDBEntries(ctx, dbFile)
	if err != nil {
		return err
	}
	if len(listed) == 0 && len(onDisk) == 0 {
		return nil
	}
	// guard both directions: an unreadable db makes every package look
	// unlisted, an empty file list makes every entry look orphaned
	if len(listed) == 0 || len(onDisk) == 0 {
		log.Warningf("[HK/%s] skipping repo-db check: %d db entries, %d packages on disk",
			fullRepo, len(listed), len(onDisk))
		return nil
	}

	diskFiles := make(map[string]struct{}, len(onDisk))
	diskByName := make(map[string]string, len(onDisk))
	for _, path := range onDisk {
		if filepath.Dir(path) != repoDir {
			continue
		}
		diskFiles[filepath.Base(path)] = struct{}{}
		name := Package(path).Name()
		// paccache can leave more than one version behind, keep the newest
		if prev, ok := diskByName[name]; !ok ||
			alpm.VerCmp(Package(path).Version(), Package(prev).Version()) > 0 {
			diskByName[name] = path
		}
	}

	fix, orphans := diffRepoDB(fullRepo, listed, diskFiles, diskByName)

	// a correct db never disagrees with disk at scale, so a large delta means our
	// own view is wrong (mid-move, partial mount) rather than the db. Bounds the
	// orphan removals only: a re-add cannot lose anything, and neither can the
	// removal paired with it, since the file is on disk and the add follows.
	if maxDrop := max(1, len(listed)/maxDBFixFraction); len(orphans) > maxDrop {
		log.Errorf("[HK/%s] repo-db check wants to drop %d of %d entries, refusing",
			fullRepo, len(orphans), len(listed))
		fix.remove = slices.DeleteFunc(fix.remove, func(name string) bool {
			return slices.Contains(orphans, name)
		})
		orphans = nil
	}

	// the db read and the file list were sampled a moment apart, so re-check the
	// removals that a missing file justified. The removals paired with a re-add
	// are exempt: a file existing is their precondition, not a contradiction.
	fix.remove = slices.DeleteFunc(fix.remove, func(name string) bool {
		if !slices.Contains(orphans, name) {
			return false
		}
		matches, err := filepath.Glob(filepath.Join(repoDir, name+"-*.pkg.tar.zst"))
		if err != nil {
			return true
		}
		// the glob is a prefix match, so an unrelated split package can match:
		// only a file whose pkgname is this one counts
		return slices.ContainsFunc(matches, func(match string) bool {
			return Package(match).Name() == name
		})
	})

	if len(fix.readd) > 0 || len(fix.remove) > 0 {
		buildManager.repoFix[fullRepo] <- fix
	}
	return nil
}

// diffRepoDB works out how to bring a repo db back in line with the packages on
// disk. Split out from repoDBHK so the decision logic is testable without a
// repo, a db or the worker channels.
//
// orphans are the removals justified by no package file existing for that
// pkgname, as opposed to the ones paired with a re-add. Only those are worth
// re-checking against the directory, since a file appearing is what would
// invalidate them.
func diffRepoDB(fullRepo string, listed map[string]string, diskFiles map[string]struct{},
	diskByName map[string]string,
) (fix repoDBFix, orphans []string) {
	// a re-add whose pkgname the db already lists has to be paired with a
	// removal: repo-add is invoked with -n (skip if pkgname-pkgver is already
	// there) and -p (skip a downgrade), either of which would silently ignore
	// the file. repoWorker runs the removals first, so the add then lands.
	queued := make(map[string]struct{})
	readd := func(name, path string) {
		// both loops below can reach the same package
		if _, dup := queued[name]; dup {
			return
		}
		queued[name] = struct{}{}
		fix.readd = append(fix.readd, path)
		if _, stale := listed[name]; stale {
			fix.remove = append(fix.remove, name)
		}
	}

	for name, filename := range listed {
		if _, ok := diskFiles[filename]; ok {
			continue
		}
		path, ok := diskByName[name]
		if !ok {
			log.Infof("[HK] %s->%s db lists missing %s with no package on disk, dropping entry",
				fullRepo, name, filename)
			fix.remove = append(fix.remove, name)
			orphans = append(orphans, name)
			continue
		}
		log.Infof("[HK] %s->%s db lists missing %s, re-adding %s", fullRepo, name,
			filename, filepath.Base(path))
		readd(name, path)
	}

	for name, path := range diskByName {
		filename, ok := listed[name]
		if !ok {
			log.Infof("[HK] %s->%s on disk but absent from db, adding %s", fullRepo, name,
				filepath.Base(path))
			readd(name, path)
			continue
		}
		// the db lists an older version whose file still exists, which a
		// partially applied repo-add leaves behind
		if alpm.VerCmp(Package(path).Version(), Package(filename).Version()) > 0 {
			log.Infof("[HK] %s->%s db lists %s but %s is newer, re-adding", fullRepo, name,
				filename, filepath.Base(path))
			readd(name, path)
		}
	}

	return fix, orphans
}

// fields of a repo db desc entry that repoDBEntries cares about
const (
	dbDescFilename = "%FILENAME%"
	dbDescName     = "%NAME%"
)

const (
	// maxDBFixFraction bounds how much of a db one check may drop, as 1/n.
	maxDBFixFraction = 10
	// sonameBackfillPerRepo bounds how many packages one housekeeping pass
	// reads sonames off, since each one decompresses the whole package.
	sonameBackfillPerRepo = 50
)

// repoDBEntries maps pkgname to the %FILENAME% the repo db advertises for it.
// Read via bsdtar since the db is tar.xz and the stdlib has no xz decoder.
func repoDBEntries(ctx context.Context, dbFile string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "bsdtar", "-xOf", dbFile, "*/desc")
	out, err := cmd.Output()
	if err != nil {
		// an empty db has no members to match, which bsdtar reports as an error
		if cmd.ProcessState.ExitCode() == 1 && len(out) == 0 {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("error reading %s: %w", dbFile, err)
	}

	return parseRepoDBDesc(string(out)), nil
}

// parseRepoDBDesc pulls pkgname and %FILENAME% out of concatenated desc files.
func parseRepoDBDesc(out string) map[string]string {
	entries := make(map[string]string)
	var name, filename string
	flush := func() {
		if name != "" && filename != "" {
			entries[name] = filename
		}
		name, filename = "", ""
	}

	// every field is a %NAME% line followed by its value, so read ahead by one
	// instead of tracking which section we are in
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i+1 >= len(lines) {
			break
		}
		switch line {
		case dbDescFilename:
			// the first field of every entry, so the previous one is complete
			flush()
			filename = lines[i+1]
		case dbDescName:
			name = lines[i+1]
		}
	}
	flush()

	return entries
}

func logHK(ctx context.Context) error {
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

		if exists, err := pkg.exists(ctx); err != nil {
			return err
		} else if !exists {
			_ = os.Remove(logFile)
			continue
		}

		pkgSkipped, err := db.DBPackage.Query().Where(
			dbpackage.Pkgbase(pkg.Pkgbase),
			dbpackage.March(pkg.March),
			dbpackage.StatusEQ(dbpackage.StatusSkipped),
		).Exist(ctx)
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
				dbpackage.StatusEQ(dbpackage.StatusFailed),
				// a build we killed leaves a log truncated mid-stream, which can match
				// one of these patterns by accident; requeueing it just rebuilds the hang
				dbpackage.SkipReasonNotIn(SkipReasonStalled, SkipReasonTimeout),
			).ClearTagRev().SetStatus(dbpackage.StatusQueued).Save(ctx)
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
				dbpackage.SkipReasonNotIn(SkipReasonStalled, SkipReasonTimeout),
			).ClearTagRev().SetStatus(dbpackage.StatusQueued).SetLto(dbpackage.LtoAutoDisabled).Save(ctx)
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
