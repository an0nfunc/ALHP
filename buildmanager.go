package main

import (
	"context"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
	"sync"
	"time"
)

type BuildManager struct {
	repoPurge    map[string]chan []*ProtoPackage
	repoAdd      map[string]chan []*ProtoPackage
	repoWG       *sync.WaitGroup
	alpmMutex    *sync.RWMutex
	building     []*ProtoPackage
	buildingLock *sync.RWMutex
	queueSignal  chan struct{}
}

func (b *BuildManager) refreshSRCINFOs(ctx context.Context, path string) error {
	pkgBuilds, err := Glob(path)
	if err != nil {
		return fmt.Errorf("error scanning for PKGBUILDs: %w", err)
	}

	wg := new(sync.WaitGroup)
	workerChan := make(chan string, runtime.NumCPU())

	for o := 0; o < runtime.NumCPU(); o++ {
		wg.Add(1)
		go b.SRCINFOWorker(ctx, workerChan, wg)
	}

	go func() {
		for _, pkgbuild := range pkgBuilds {
			workerChan <- pkgbuild
		}
		close(workerChan)
	}()

	wg.Wait()
	return nil
}

func (b *BuildManager) SRCINFOWorker(ctx context.Context, workIn chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for pkgbuild := range workIn {
		mPkgbuild := PKGBUILD(pkgbuild)
		if mPkgbuild.FullRepo() == "trunk" || !Contains(conf.Repos, mPkgbuild.Repo()) ||
			containsSubStr(mPkgbuild.FullRepo(), conf.Blacklist.Repo) {
			continue
		}

		for _, march := range conf.March {
			dbPkg, dbErr := db.DbPackage.Query().Where(
				dbpackage.And(
					dbpackage.Pkgbase(mPkgbuild.PkgBase()),
					dbpackage.RepositoryEQ(dbpackage.Repository(mPkgbuild.Repo())),
					dbpackage.March(march),
				),
			).Only(context.Background())

			if ent.IsNotFound(dbErr) {
				log.Debugf("[%s/%s] Package not found in database", mPkgbuild.Repo(), mPkgbuild.PkgBase())
			} else if dbErr != nil {
				log.Errorf("[%s/%s] Problem querying db for package: %v", mPkgbuild.Repo(), mPkgbuild.PkgBase(), dbErr)
			}

			// compare b3sum of PKGBUILD file to hash in database, only proceed if hash differs
			// reduces the amount of PKGBUILDs that need to be parsed with makepkg, which is _really_ slow, significantly
			b3s, err := b3sum(pkgbuild)
			if err != nil {
				log.Errorf("Error hashing PKGBUILD: %v", err)
			}

			if dbPkg != nil && b3s == dbPkg.Hash {
				log.Debugf("[%s/%s] Skipped: PKGBUILD hash matches db (%s)", mPkgbuild.Repo(), mPkgbuild.PkgBase(), b3s)
				continue
			} else if dbPkg != nil && b3s != dbPkg.Hash && dbPkg.SrcinfoHash != b3s {
				log.Debugf("[%s/%s] srcinfo cleared", mPkgbuild.Repo(), mPkgbuild.PkgBase())
				dbPkg = dbPkg.Update().ClearSrcinfo().SaveX(context.Background())
			}

			proto := &ProtoPackage{
				Pkgbuild:  pkgbuild,
				Pkgbase:   mPkgbuild.PkgBase(),
				Repo:      dbpackage.Repository(mPkgbuild.Repo()),
				March:     march,
				FullRepo:  mPkgbuild.Repo() + "-" + march,
				Hash:      b3s,
				DBPackage: dbPkg,
			}

			_, err = proto.isEligible(ctx)
			if err != nil {
				log.Infof("Unable to determine status for package %s: %v", proto.Pkgbase, err)
				b.repoPurge[proto.FullRepo] <- []*ProtoPackage{proto}
			} else if proto.DBPackage != nil {
				proto.DBPackage.Update().SetPkgbuild(proto.Pkgbuild).ExecX(ctx)
			}
		}
	}
}

func (b *BuildManager) buildQueue(queue []*ProtoPackage, ctx context.Context) error {
	var doneQ []*ProtoPackage
	doneQLock := new(sync.RWMutex)
	var unknownBuilds bool

	for len(doneQ) != len(queue) {
		up := 0
		b.buildingLock.RLock()
		if (pkgList2MaxMem(b.building) < conf.Build.MemoryLimit && !unknownBuilds) || (unknownBuilds && len(b.building) < 1) {
			b.buildingLock.RUnlock()
			for _, pkg := range queue {
				// check if package is already build
				doneQLock.RLock()
				if ContainsPkg(doneQ, pkg, true) {
					doneQLock.RUnlock()
					continue
				}
				doneQLock.RUnlock()

				// check if package is already building (we do not build packages from different marchs simultaneously)
				b.buildingLock.RLock()
				if ContainsPkg(b.building, pkg, false) {
					log.Debugf("[Q] skipped already building package %s->%s", pkg.FullRepo, pkg.Pkgbase)
					b.buildingLock.RUnlock()
					continue
				}
				b.buildingLock.RUnlock()

				// only check for memory on known-memory-builds
				// otherwise build them one-at-a-time
				// TODO: add initial compile mode for new repos
				if !unknownBuilds {
					// check if package has unknown memory usage
					if pkg.DBPackage.MaxRss == nil {
						log.Debugf("[Q] skipped unknown package %s->%s", pkg.FullRepo, pkg.Pkgbase)
						up++
						continue
					}

					// check if package can be build with current memory limit
					if datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB > conf.Build.MemoryLimit {
						log.Warningf("[Q] %s->%s exeeds memory limit: %s->%s", pkg.FullRepo, pkg.Pkgbase,
							datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB, conf.Build.MemoryLimit)
						doneQLock.Lock()
						doneQ = append(doneQ, pkg)
						doneQLock.Unlock()
						continue
					}

					b.buildingLock.RLock()
					currentMemLoad := pkgList2MaxMem(b.building)
					b.buildingLock.RUnlock()

					// check if package can be build right now
					if !unknownBuilds && currentMemLoad+(datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB) > conf.Build.MemoryLimit {
						log.Debugf("[Q] skipped package with max_rss %s while load %s: %s->%s",
							datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB, currentMemLoad, pkg.Pkgbase, pkg.March)
						continue
					}
				} else {
					b.buildingLock.RLock()
					if len(b.building) >= 1 {
						b.buildingLock.RUnlock()
						continue
					}
					b.buildingLock.RUnlock()
				}

				b.buildingLock.Lock()
				b.building = append(b.building, pkg)
				b.buildingLock.Unlock()

				go func(pkg *ProtoPackage) {
					dur, err := pkg.build(ctx)
					if err != nil {
						log.Warningf("[Q] error building package %s->%s in %s: %s", pkg.FullRepo, pkg.Pkgbase, dur, err)
						b.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
					} else {
						log.Infof("[Q] build successful: %s->%s (%s)", pkg.FullRepo, pkg.Pkgbase, dur)
					}
					doneQLock.Lock()
					b.buildingLock.Lock()
					doneQ = append(doneQ, pkg)

					for i := 0; i < len(b.building); i++ {
						if b.building[i].PkgbaseEquals(pkg, true) {
							b.building = append(b.building[:i], b.building[i+1:]...)
							break
						}
					}
					doneQLock.Unlock()
					b.buildingLock.Unlock()
					b.queueSignal <- struct{}{}
				}(pkg)
			}
		} else {
			log.Debugf("[Q] memory/build limit reached, waiting for package to finish...")
			b.buildingLock.RUnlock()
			<-b.queueSignal
		}

		// if only unknown packages are left, enable unknown buildmode
		b.buildingLock.RLock()
		if up == len(queue)-(len(doneQ)+len(b.building)) {
			unknownBuilds = true
		}
		b.buildingLock.RUnlock()
		up = 0
	}
	return nil
}

func (b *BuildManager) htmlWorker(ctx context.Context) {
	type Pkg struct {
		Pkgbase              string
		Status               string
		Class                string
		Skip                 string
		Version              string
		Svn2GitVersion       string
		BuildDate            string
		BuildDuration        time.Duration
		Checked              string
		Log                  string
		LTO                  bool
		LTOUnknown           bool
		LTODisabled          bool
		LTOAutoDisabled      bool
		DebugSym             bool
		DebugSymNotAvailable bool
		DebugSymUnknown      bool
	}

	type Repo struct {
		Name     string
		Packages []Pkg
	}

	type March struct {
		Name  string
		Repos []Repo
	}

	type tpl struct {
		March       []March
		Generated   string
		Latest      int
		Failed      int
		Skipped     int
		Queued      int
		LTOEnabled  int
		LTOUnknown  int
		LTODisabled int
	}

	for {
		gen := &tpl{}

		for _, march := range conf.March {
			addMarch := March{
				Name: march,
			}

			for _, repo := range conf.Repos {
				addRepo := Repo{
					Name: repo,
				}

				pkgs := db.DbPackage.Query().Order(ent.Asc(dbpackage.FieldPkgbase)).
					Where(dbpackage.MarchEQ(march), dbpackage.RepositoryEQ(dbpackage.Repository(repo))).AllX(ctx)

				for _, pkg := range pkgs {
					addPkg := Pkg{
						Pkgbase:        pkg.Pkgbase,
						Status:         strings.ToUpper(pkg.Status.String()),
						Class:          statusID2string(pkg.Status),
						Skip:           pkg.SkipReason,
						Version:        pkg.RepoVersion,
						Svn2GitVersion: pkg.Version,
					}

					if pkg.STime != nil && pkg.UTime != nil {
						addPkg.BuildDuration = time.Duration(*pkg.STime+*pkg.UTime) * time.Second
					}

					if !pkg.BuildTimeStart.IsZero() {
						addPkg.BuildDate = pkg.BuildTimeStart.UTC().Format(time.RFC1123)
					}

					if !pkg.Updated.IsZero() {
						addPkg.Checked = pkg.Updated.UTC().Format(time.RFC1123)
					}

					if pkg.Status == dbpackage.StatusFailed {
						addPkg.Log = fmt.Sprintf("%s/%s/%s.log", logDir, pkg.March, pkg.Pkgbase)
					}

					switch pkg.Lto {
					case dbpackage.LtoUnknown:
						if pkg.Status != dbpackage.StatusSkipped && pkg.Status != dbpackage.StatusFailed {
							addPkg.LTOUnknown = true
						}
					case dbpackage.LtoEnabled:
						addPkg.LTO = true
					case dbpackage.LtoDisabled:
						addPkg.LTODisabled = true
					case dbpackage.LtoAutoDisabled:
						addPkg.LTOAutoDisabled = true
					}

					switch pkg.DebugSymbols {
					case dbpackage.DebugSymbolsUnknown:
						if pkg.Status != dbpackage.StatusSkipped && pkg.Status != dbpackage.StatusFailed {
							addPkg.DebugSymUnknown = true
						}
					case dbpackage.DebugSymbolsAvailable:
						addPkg.DebugSym = true
					case dbpackage.DebugSymbolsNotAvailable:
						addPkg.DebugSymNotAvailable = true
					}

					addRepo.Packages = append(addRepo.Packages, addPkg)
				}
				addMarch.Repos = append(addMarch.Repos, addRepo)
			}
			gen.March = append(gen.March, addMarch)
		}

		gen.Generated = time.Now().UTC().Format(time.RFC1123)

		var v []struct {
			Status dbpackage.Status `json:"status"`
			Count  int              `json:"count"`
		}

		db.DbPackage.Query().GroupBy(dbpackage.FieldStatus).Aggregate(ent.Count()).ScanX(ctx, &v)

		for _, c := range v {
			switch c.Status {
			case dbpackage.StatusFailed:
				gen.Failed = c.Count
			case dbpackage.StatusSkipped:
				gen.Skipped = c.Count
			case dbpackage.StatusLatest:
				gen.Latest = c.Count
			case dbpackage.StatusQueued:
				gen.Queued = c.Count
			}
		}

		var v2 []struct {
			Status dbpackage.Lto `json:"lto"`
			Count  int           `json:"count"`
		}

		db.DbPackage.Query().Where(dbpackage.StatusNEQ(dbpackage.StatusSkipped)).
			GroupBy(dbpackage.FieldLto).Aggregate(ent.Count()).ScanX(ctx, &v2)

		for _, c := range v2 {
			switch c.Status {
			case dbpackage.LtoUnknown:
				gen.LTOUnknown = c.Count
			case dbpackage.LtoDisabled, dbpackage.LtoAutoDisabled:
				gen.LTODisabled += c.Count
			case dbpackage.LtoEnabled:
				gen.LTOEnabled = c.Count
			}
		}

		statusTpl, err := template.ParseFiles("tpl/packages.html")
		if err != nil {
			log.Warningf("[HTML] Error parsing template file: %v", err)
			continue
		}

		f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, "packages.html"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			log.Warningf("[HTML] Erro ropening output file: %v", err)
			continue
		}
		err = statusTpl.Execute(f, gen)
		if err != nil {
			log.Warningf("[HTML] Error filling template: %v", err)
		}
		_ = f.Close()

		time.Sleep(time.Minute * 5)
	}
}

func (b *BuildManager) repoWorker(repo string) {
	for {
		select {
		case pkgL := <-b.repoAdd[repo]:
			b.repoWG.Add(1)
			toAdd := make([]string, 0)
			for _, pkg := range pkgL {
				toAdd = append(toAdd, pkg.PkgFiles...)
			}

			args := []string{"-s", "-v", "-p", "-n", filepath.Join(conf.Basedir.Repo, repo, "os", conf.Arch, repo) + ".db.tar.xz"}
			args = append(args, toAdd...)
			cmd := exec.Command("repo-add", args...)
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil && cmd.ProcessState.ExitCode() != 1 {
				log.Panicf("%s while repo-add: %v", string(res), err)
			}

			for _, pkg := range pkgL {
				pkg.toDBPackage(true)
				if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, pkg.March,
					pkg.DBPackage.Packages[0]+"-debug-"+pkg.Version+"-"+conf.Arch+".pkg.tar.zst")); err == nil {
					pkg.DBPackage = pkg.DBPackage.Update().
						SetStatus(dbpackage.StatusLatest).
						ClearSkipReason().
						SetDebugSymbols(dbpackage.DebugSymbolsAvailable).
						SetRepoVersion(pkg.Version).
						SetHash(pkg.Hash).
						SaveX(context.Background())
				} else {
					pkg.DBPackage = pkg.DBPackage.Update().
						SetStatus(dbpackage.StatusLatest).
						ClearSkipReason().
						SetDebugSymbols(dbpackage.DebugSymbolsNotAvailable).
						SetRepoVersion(pkg.Version).
						SetHash(pkg.Hash).
						SaveX(context.Background())
				}
			}

			cmd = exec.Command("paccache", "-rc", filepath.Join(conf.Basedir.Repo, repo, "os", conf.Arch), "-k", "1") //nolint:gosec
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Warningf("Error running paccache: %v", err)
			}
			err = updateLastUpdated()
			if err != nil {
				log.Warningf("Error updating lastupdate: %v", err)
			}
			b.repoWG.Done()
		case pkgL := <-b.repoPurge[repo]:
			for _, pkg := range pkgL {
				if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"); err != nil {
					continue
				}
				if len(pkg.PkgFiles) == 0 {
					if err := pkg.findPkgFiles(); err != nil {
						log.Warningf("[%s/%s] Unable to find files: %v", pkg.FullRepo, pkg.Pkgbase, err)
						continue
					} else if len(pkg.PkgFiles) == 0 {
						continue
					}
				}

				var realPkgs []string
				for _, filePath := range pkg.PkgFiles {
					if _, err := os.Stat(filePath); err == nil {
						realPkgs = append(realPkgs, Package(filePath).Name())
					}
				}

				if len(realPkgs) == 0 {
					continue
				}

				b.repoWG.Add(1)
				args := []string{"-s", "-v", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"}
				args = append(args, realPkgs...)
				cmd := exec.Command("repo-remove", args...)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil && cmd.ProcessState.ExitCode() == 1 {
					log.Warningf("Error while deleting package %s: %s", pkg.Pkgbase, string(res))
				}

				if pkg.DBPackage != nil {
					_ = pkg.DBPackage.Update().ClearRepoVersion().ClearHash().Exec(context.Background())
				}

				for _, file := range pkg.PkgFiles {
					_ = os.Remove(file)
					_ = os.Remove(file + ".sig")
				}
				err = updateLastUpdated()
				if err != nil {
					log.Warningf("Error updating lastupdate: %v", err)
				}
				b.repoWG.Done()
			}
		}
	}
}

func (b *BuildManager) syncWorker(ctx context.Context) error {
	err := os.MkdirAll(filepath.Join(conf.Basedir.Work, upstreamDir), 0o755)
	if err != nil {
		log.Fatalf("Error creating upstream dir: %v", err)
	}

	for {
		for gitDir, gitURL := range conf.Svn2git {
			gitPath := filepath.Join(conf.Basedir.Work, upstreamDir, gitDir)

			if _, err := os.Stat(gitPath); os.IsNotExist(err) {
				cmd := exec.Command("git", "clone", "--depth=1", gitURL, gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil {
					log.Fatalf("Error running git clone: %v", err)
				}
			} else if err == nil {
				cmd := exec.Command("git", "reset", "--hard")
				cmd.Dir = gitPath
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil {
					log.Fatalf("Error running git reset: %v", err)
				}

				cmd = exec.Command("git", "pull")
				cmd.Dir = gitPath
				res, err = cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil {
					log.Warningf("Failed to update git repo %s: %v", gitDir, err)
				}
			}
		}

		// housekeeping
		wg := new(sync.WaitGroup)
		for _, repo := range repos {
			wg.Add(1)
			splitRepo := strings.Split(repo, "-")
			repo := repo
			go func() {
				err := housekeeping(splitRepo[0], strings.Join(splitRepo[1:], "-"), wg)
				if err != nil {
					log.Warningf("[%s] housekeeping failed: %v", repo, err)
				}
			}()
		}
		wg.Wait()

		err := logHK()
		if err != nil {
			log.Warningf("log-housekeeping failed: %v", err)
		}

		// fetch updates between sync runs
		b.alpmMutex.Lock()
		err = alpmHandle.Release()
		if err != nil {
			log.Fatalf("Error releasing ALPM handle: %v", err)
		}

		if err := retry.Fibonacci(ctx, 1*time.Second, func(ctx context.Context) error {
			if err := setupChroot(); err != nil {
				log.Warningf("Unable to upgrade chroot, trying again later.")
				return retry.RetryableError(err)
			}
			return nil
		}); err != nil {
			log.Fatal(err)
		}

		alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot),
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "/var/lib/pacman"))
		if err != nil {
			log.Warningf("Error while ALPM-init: %v", err)
		}
		b.alpmMutex.Unlock()

		// do refreshSRCINFOs twice here
		// since MirrorLatest depends on the DB being correct, there can be packages queued which should not be queued,
		// so we check them twice to eliminate those.
		log.Debugf("generating build-queue for PKGBUILDs found in %s", filepath.Join(conf.Basedir.Work, upstreamDir, "/**/PKGBUILD"))
		err = b.refreshSRCINFOs(ctx, filepath.Join(conf.Basedir.Work, upstreamDir, "/**/PKGBUILD"))
		if err != nil {
			log.Fatalf("error refreshing PKGBUILDs: %v", err)
		}
		log.Debugf("regenerating build-queue for PKGBUILDs found in %s", filepath.Join(conf.Basedir.Work, upstreamDir, "/**/PKGBUILD"))
		err = b.refreshSRCINFOs(ctx, filepath.Join(conf.Basedir.Work, upstreamDir, "/**/PKGBUILD"))
		if err != nil {
			log.Fatalf("error refreshing PKGBUILDs: %v", err)
		}

		queue, err := genQueue()
		if err != nil {
			log.Warningf("Error building buildQueue: %v", err)
		} else {
			log.Debugf("buildQueue with %d items", len(queue))

			err = b.buildQueue(queue, ctx)
			if err != nil {
				return err
			}
		}

		if ctx.Err() == nil {
			for _, repo := range repos {
				err = movePackagesLive(repo)
				if err != nil {
					log.Errorf("[%s] Error moving packages live: %v", repo, err)
				}
			}
		} else {
			return ctx.Err()
		}

		log.Debugf("build-cycle finished")
		time.Sleep(time.Duration(*checkInterval) * time.Minute)
	}
}
