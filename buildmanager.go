package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
	"sync"
	"time"
)

const MaxUnknownBuilder = 2

type BuildManager struct {
	repoPurge    map[string]chan []*ProtoPackage
	repoAdd      map[string]chan []*ProtoPackage
	repoWG       *sync.WaitGroup
	alpmMutex    *sync.RWMutex
	building     []*ProtoPackage
	buildingLock *sync.RWMutex
	queueSignal  chan struct{}
}

func (b *BuildManager) buildQueue(ctx context.Context, queue []*ProtoPackage) error {
	var (
		doneQ         []*ProtoPackage
		doneQLock     = new(sync.RWMutex)
		unknownBuilds bool
		queueNoMatch  bool
	)

	for len(doneQ) != len(queue) {
		up := 0
		b.buildingLock.RLock()
		if (pkgList2MaxMem(b.building) < conf.Build.MemoryLimit &&
			!unknownBuilds && !queueNoMatch) ||
			(unknownBuilds && len(b.building) < MaxUnknownBuilder) {
			queueNoMatch = true
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

					// check if package can be built with current memory limit
					if datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB > conf.Build.MemoryLimit { //nolint:gosec
						log.Warningf("[Q] %s->%s exeeds memory limit: %s->%s", pkg.FullRepo, pkg.Pkgbase,
							datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB, conf.Build.MemoryLimit) //nolint:gosec
						doneQLock.Lock()
						doneQ = append(doneQ, pkg)
						doneQLock.Unlock()
						continue
					}

					b.buildingLock.RLock()
					currentMemLoad := pkgList2MaxMem(b.building)
					b.buildingLock.RUnlock()

					// check if package can be build right now
					if currentMemLoad+(datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB) > conf.Build.MemoryLimit { //nolint:gosec
						log.Debugf("[Q] skipped package with max_rss %s while load %s: %s->%s",
							datasize.ByteSize(*pkg.DBPackage.MaxRss)*datasize.KB, currentMemLoad, pkg.Pkgbase, pkg.March) //nolint:gosec
						continue
					}
				} else {
					b.buildingLock.RLock()
					if len(b.building) >= MaxUnknownBuilder {
						b.buildingLock.RUnlock()
						continue
					}
					b.buildingLock.RUnlock()
				}

				b.buildingLock.Lock()
				b.building = append(b.building, pkg)
				b.buildingLock.Unlock()
				queueNoMatch = false

				go func(pkg *ProtoPackage) {
					dur, err := pkg.build(ctx)
					if err != nil && !errors.Is(err, ErrorNotEligible) {
						log.Warningf("[Q] error building package %s->%s in %s: %s", pkg.FullRepo, pkg.Pkgbase, dur, err)
						b.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
					} else if err == nil {
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
			queueNoMatch = false
		}

		// if only unknown packages are left, enable unknown buildmode
		b.buildingLock.RLock()
		if up == len(queue)-(len(doneQ)+len(b.building)) {
			unknownBuilds = true
		}
		b.buildingLock.RUnlock()
	}
	return nil
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
				err = pkg.toDBPackage(true)
				if err != nil {
					log.Warningf("error getting db entry for %s: %v", pkg.Pkgbase, err)
					continue
				}

				pkgUpd := pkg.DBPackage.Update().
					SetStatus(dbpackage.StatusLatest).
					ClearSkipReason().
					SetRepoVersion(pkg.Version).
					SetTagRev(pkg.State.TagRev)

				if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, pkg.March,
					pkg.DBPackage.Packages[0]+"-debug-"+pkg.Version+"-"+conf.Arch+".pkg.tar.zst")); err == nil {
					pkgUpd = pkgUpd.SetDebugSymbols(dbpackage.DebugSymbolsAvailable)
				} else {
					pkgUpd = pkgUpd.SetDebugSymbols(dbpackage.DebugSymbolsNotAvailable)
				}
				pkg.DBPackage = pkgUpd.SaveX(context.Background())
			}

			cmd = exec.Command("paccache", "-rc", filepath.Join(conf.Basedir.Repo, repo, "os", conf.Arch), "-k", "1") //nolint:gosec
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Warningf("error running paccache: %v", err)
			}

			err = updateLastUpdated()
			if err != nil {
				log.Warningf("error updating lastupdate: %v", err)
			}
			b.repoWG.Done()
		case pkgL := <-b.repoPurge[repo]:
			for _, pkg := range pkgL {
				if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"); err != nil {
					continue
				}
				if len(pkg.PkgFiles) == 0 {
					if err := pkg.findPkgFiles(); err != nil {
						log.Warningf("[%s/%s] unable to find files: %v", pkg.FullRepo, pkg.Pkgbase, err)
						continue
					} else if len(pkg.PkgFiles) == 0 {
						if pkg.DBPackage != nil {
							_ = pkg.DBPackage.Update().ClearRepoVersion().ClearTagRev().Exec(context.Background())
						}
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
					log.Warningf("error while deleting package %s: %s", pkg.Pkgbase, string(res))
				}

				if pkg.DBPackage != nil {
					_ = pkg.DBPackage.Update().ClearRepoVersion().ClearTagRev().Exec(context.Background())
				}

				for _, file := range pkg.PkgFiles {
					_ = os.Remove(file)
					_ = os.Remove(file + ".sig")
				}
				err = updateLastUpdated()
				if err != nil {
					log.Warningf("error updating lastupdate: %v", err)
				}
				b.repoWG.Done()
			}
		}
	}
}

func (b *BuildManager) syncWorker(ctx context.Context) error {
	err := os.MkdirAll(conf.Basedir.Work, 0o755)
	if err != nil {
		log.Fatalf("error creating work dir %s: %v", conf.Basedir.Work, err)
	}

	gitPath := filepath.Join(conf.Basedir.Work, stateDir)
	for {
		if _, err := os.Stat(gitPath); os.IsNotExist(err) {
			cmd := exec.Command("git", "clone", "--depth=1", conf.StateRepo, gitPath) //nolint:gosec
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Fatalf("error cloning state repo: %v", err)
			}
		} else if err == nil {
			cmd := exec.Command("git", "reset", "--hard")
			cmd.Dir = gitPath
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Fatalf("error reseting state repo: %v", err)
			}

			cmd = exec.Command("git", "pull")
			cmd.Dir = gitPath
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Warningf("failed to update state repo: %v", err)
			}
		}

		// housekeeping
		wg := new(sync.WaitGroup)
		for _, repo := range repos {
			wg.Add(1)
			splitRepo := strings.Split(repo, "-")
			go func() { //nolint:contextcheck
				err := housekeeping(splitRepo[0], strings.Join(splitRepo[1:], "-"), wg)
				if err != nil {
					log.Warningf("[%s] housekeeping failed: %v", repo, err)
				}
			}()
		}
		wg.Wait()

		err := logHK() //nolint:contextcheck
		if err != nil {
			log.Warningf("log-housekeeping failed: %v", err)
		}
		debugHK()

		// fetch updates between sync runs
		b.alpmMutex.Lock()
		err = alpmHandle.Release()
		if err != nil {
			log.Fatalf("error releasing ALPM handle: %v", err)
		}

		if err := retry.Fibonacci(ctx, 1*time.Second, func(_ context.Context) error {
			if err := setupChroot(); err != nil {
				log.Warningf("unable to upgrade chroot, trying again later")
				return retry.RetryableError(err)
			}
			return nil
		}); err != nil {
			log.Fatal(err)
		}

		alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot),
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "/var/lib/pacman"))
		if err != nil {
			log.Warningf("error while alpm-init: %v", err)
		}
		b.alpmMutex.Unlock()

		queue, err := b.genQueue() //nolint:contextcheck
		if err != nil {
			log.Errorf("error building queue: %v", err)
		} else {
			log.Debugf("build-queue with %d items", len(queue))
			err = b.buildQueue(ctx, queue)
			if err != nil {
				return err
			}
		}

		if ctx.Err() == nil {
			for _, repo := range repos {
				err = movePackagesLive(repo) //nolint:contextcheck
				if err != nil {
					log.Errorf("[%s] error moving packages live: %v", repo, err)
				}
			}
		} else {
			return ctx.Err()
		}

		log.Debugf("build-cycle finished")
		time.Sleep(time.Duration(*checkInterval) * time.Minute)
	}
}

func (b *BuildManager) genQueue() ([]*ProtoPackage, error) {
	stateFiles, err := Glob(filepath.Join(conf.Basedir.Work, stateDir, "**/*"))
	if err != nil {
		return nil, fmt.Errorf("error scanning for state-files: %w", err)
	}

	var pkgbuilds []*ProtoPackage
	for _, stateFile := range stateFiles {
		stat, err := os.Stat(stateFile)
		if err != nil || stat.IsDir() || strings.Contains(stateFile, ".git") || strings.Contains(stateFile, "README.md") {
			continue
		}

		repo, subRepo, arch, err := stateFileMeta(stateFile)
		if err != nil {
			log.Warningf("[QG] error generating statefile metadata %s: %v", stateFile, err)
			continue
		}

		if !Contains(conf.Repos, repo) || (subRepo != nil && Contains(conf.Blacklist.Repo, *subRepo)) {
			continue
		}

		rawState, err := os.ReadFile(stateFile)
		if err != nil {
			log.Warningf("[QG] cannot read statefile %s: %v", stateFile, err)
			continue
		}

		state, err := parseState(string(rawState))
		if err != nil {
			log.Warningf("[QG] cannot parse statefile %s: %v", stateFile, err)
			continue
		}

		for _, march := range conf.March {
			pkg := &ProtoPackage{
				Pkgbase:  state.Pkgbase,
				Repo:     dbpackage.Repository(repo),
				March:    march,
				FullRepo: repo + "-" + march,
				State:    state,
				Version:  state.PkgVer,
				Arch:     arch,
			}

			err = pkg.toDBPackage(false)
			if err != nil {
				log.Warningf("[QG] error getting/creating dbpackage %s: %v", state.Pkgbase, err)
				continue
			}

			if !pkg.isAvailable(alpmHandle) {
				log.Debugf("[QG] %s->%s not available on mirror, skipping build", pkg.FullRepo, pkg.Pkgbase)
				continue
			}

			aBuild, err := pkg.IsBuilt()
			if err != nil {
				log.Warningf("[QG] %s->%s error determining built packages: %v", pkg.FullRepo, pkg.Pkgbase, err)
			}
			if aBuild {
				log.Infof("[QG] %s->%s already built, skipping build", pkg.FullRepo, pkg.Pkgbase)
				continue
			}

			if pkg.DBPackage == nil {
				err = pkg.toDBPackage(true)
				if err != nil {
					log.Warningf("[QG] error getting/creating dbpackage %s: %v", state.Pkgbase, err)
					continue
				}
			}

			if pkg.DBPackage.TagRev != nil && *pkg.DBPackage.TagRev == state.TagRev {
				continue
			}

			// try download .SRCINFO from repo
			srcInfo, err := downloadSRCINFO(pkg.DBPackage.Pkgbase, state.TagRev)
			if err == nil {
				pkg.Srcinfo = srcInfo
			}

			if !pkg.isEligible(context.Background()) {
				continue
			}

			pkg.DBPackage = pkg.DBPackage.Update().SetStatus(dbpackage.StatusQueued).SaveX(context.Background())
			pkgbuilds = append(pkgbuilds, pkg)
		}
	}

	return pkgbuilds, nil
}
