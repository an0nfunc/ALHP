package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
	"ALHP.go/ent/migrate"
	"bytes"
	"context"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"flag"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	_ "github.com/jackc/pgx/v4/stdlib"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"gopkg.in/yaml.v2"
	"html/template"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	conf          *Conf
	repos         []string
	alpmHandle    *alpm.Handle
	buildManager  *BuildManager
	db            *ent.Client
	journalLog    = flag.Bool("journal", false, "Log to systemd journal instead of stdout")
	checkInterval = flag.Int("interval", 5, "How often svn2git should be checked in minutes (default: 5)")
)

func (b *BuildManager) buildWorker(id int, march string) {
	err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 18)
	if err != nil {
		log.Warningf("[%s/worker-%d] Failed to drop priority: %v", march, id, err)
	}

	for {
		select {
		case pkg := <-b.build[march]:
			if b.exit {
				log.Infof("Worker %s/%d exited...", march, id)
				return
			} else {
				b.buildWG.Add(1)
			}

			start := time.Now().UTC()

			log.Infof("[%s/%s/%s] Build starting", pkg.FullRepo, pkg.Pkgbase, pkg.Version)

			pkg.toDbPackage(true)
			pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusBuilding).ClearSkipReason().SaveX(context.Background())

			err := pkg.importKeys()
			if err != nil {
				log.Warningf("[%s/%s/%s] Failed to import pgp keys: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
			}

			buildDir, err := pkg.setupBuildDir()
			if err != nil {
				log.Errorf("[%s/%s/%s] Error setting up builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
				b.buildWG.Done()
				continue
			}

			buildNo := 1
			versionSlice := strings.Split(pkg.DbPackage.LastVersionBuild, ".")
			if strings.Join(versionSlice[:len(versionSlice)-1], ".") == pkg.Version {
				buildNo, err = strconv.Atoi(versionSlice[len(versionSlice)-1])
				if err != nil {
					log.Errorf("[%s/%s/%s] Failed to read build from pkgrel: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					err = cleanBuildDir(buildDir)
					if err != nil {
						log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					}
					b.buildWG.Done()
					continue
				}
				buildNo++
			}

			err = pkg.increasePkgRel(buildNo)
			if err != nil {
				log.Errorf("[%s/%s/%s] Failed to increase pkgrel: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
				err = cleanBuildDir(buildDir)
				if err != nil {
					log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
				}
				b.buildWG.Done()
				continue
			}

			if contains(conf.KernelToPatch, pkg.Pkgbase) {
				err = pkg.prepareKernelPatches()
				if err != nil {
					log.Warningf("[%s/%s/%s] Failed to modify PKGBUILD for kernel patch: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					pkg.DbPackage.Update().SetStatus(dbpackage.StatusFailed).SetSkipReason("failed to apply patch").SetHash(pkg.Hash).ExecX(context.Background())
					err = cleanBuildDir(buildDir)
					if err != nil {
						log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					}
					b.buildWG.Done()
					continue
				}
			}

			pkg.PkgFiles = []string{}

			// default to LTO
			makepkgFile := "makepkg-%s-lto.conf"
			if pkg.DbPackage.Lto == dbpackage.LtoDisabled || pkg.DbPackage.Lto == dbpackage.LtoAutoDisabled {
				// use non-lto makepkg.conf if LTO is blacklisted for this package
				makepkgFile = "makepkg-%s.conf"
			}
			cmd := exec.Command("sh", "-c",
				"cd "+filepath.Dir(pkg.Pkgbuild)+"&&makechrootpkg -c -D "+conf.Basedir.Makepkg+" -l worker-"+march+"-"+strconv.Itoa(id)+" -r "+conf.Basedir.Chroot+" -- "+
					"-m --noprogressbar --config "+filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf(makepkgFile, pkg.March)))
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			check(cmd.Start())

			b.buildProcMutex.Lock()
			b.buildProcesses = append(b.buildProcesses, cmd.Process)
			b.buildProcMutex.Unlock()

			err = cmd.Wait()

			b.buildProcMutex.Lock()
			for i := range b.buildProcesses {
				if b.buildProcesses[i].Pid == cmd.Process.Pid {
					b.buildProcesses = append(b.buildProcesses[:i], b.buildProcesses[i+1:]...)
					break
				}
			}
			b.buildProcMutex.Unlock()

			if err != nil {
				if b.exit {
					err = cleanBuildDir(buildDir)
					if err != nil {
						log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					}
					b.buildWG.Done()
					continue
				}

				if pkg.DbPackage.Lto != dbpackage.LtoAutoDisabled && pkg.DbPackage.Lto != dbpackage.LtoDisabled && reLdError.Match(out.Bytes()) {
					log.Infof("[%s/%s/%s] ld error detected, disabling LTO", pkg.FullRepo, pkg.Pkgbase, pkg.Version)
					pkg.DbPackage.Update().SetStatus(dbpackage.StatusQueued).SetSkipReason("non-LTO rebuild").SetLto(dbpackage.LtoAutoDisabled).ExecX(context.Background())
					err = cleanBuildDir(buildDir)
					if err != nil {
						log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
					}
					b.buildWG.Done()
					continue
				}

				log.Warningf("[%s/%s/%s] Build failed (%d)", pkg.FullRepo, pkg.Pkgbase, pkg.Version, cmd.ProcessState.ExitCode())

				check(os.MkdirAll(filepath.Join(conf.Basedir.Repo, logDir, march), 0755))
				check(os.WriteFile(filepath.Join(conf.Basedir.Repo, logDir, march, pkg.Pkgbase+".log"), out.Bytes(), 0644))

				pkg.DbPackage.Update().SetStatus(dbpackage.StatusFailed).ClearSkipReason().SetBuildTimeStart(start).SetBuildTimeEnd(time.Now().UTC()).SetHash(pkg.Hash).ExecX(context.Background())

				// purge failed package from repo
				b.repoPurge[pkg.FullRepo] <- pkg

				err = cleanBuildDir(buildDir)
				if err != nil {
					log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
				}
				b.buildWG.Done()
				continue
			}

			pkgFiles, err := filepath.Glob(filepath.Join(filepath.Dir(pkg.Pkgbuild), "*.pkg.tar.zst"))
			check(err)

			if len(pkgFiles) == 0 {
				log.Warningf("No packages found after building %s. Abort build.", pkg.Pkgbase)

				err = cleanBuildDir(buildDir)
				if err != nil {
					log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
				}
				b.buildWG.Done()
				continue
			}

			for _, file := range pkgFiles {
				cmd = exec.Command("gpg", "--batch", "--detach-sign", file)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil {
					log.Warningf("Failed to sign %s: %s", pkg.Pkgbase, err)
					b.buildWG.Done()
					continue
				}
			}

			copyFiles, err := filepath.Glob(filepath.Join(filepath.Dir(pkg.Pkgbuild), "*.pkg.tar.zst*"))
			check(err)

			for _, file := range copyFiles {
				_, err = copyFile(file, filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, filepath.Base(file)))
				if err != nil {
					check(err)
					b.buildWG.Done()
					continue
				}

				if filepath.Ext(file) != ".sig" {
					pkg.PkgFiles = append(pkg.PkgFiles, filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, filepath.Base(file)))
				}
			}

			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, logDir, march, pkg.Pkgbase+".log")); err == nil {
				check(os.Remove(filepath.Join(conf.Basedir.Repo, logDir, march, pkg.Pkgbase+".log")))
			}

			if pkg.DbPackage.Lto != dbpackage.LtoDisabled && pkg.DbPackage.Lto != dbpackage.LtoAutoDisabled {
				pkg.DbPackage.Update().SetStatus(dbpackage.StatusBuild).SetLto(dbpackage.LtoEnabled).SetBuildTimeStart(start).SetLastVersionBuild(pkg.Version).SetBuildTimeEnd(time.Now().UTC()).ExecX(context.Background())
			} else {
				pkg.DbPackage.Update().SetStatus(dbpackage.StatusBuild).SetBuildTimeStart(start).SetBuildTimeEnd(time.Now().UTC()).SetLastVersionBuild(pkg.Version).ExecX(context.Background())
			}

			log.Infof("[%s/%s/%s] Build successful (%s)", pkg.FullRepo, pkg.Pkgbase, pkg.Version, time.Since(start))
			b.repoAdd[pkg.FullRepo] <- pkg

			err = cleanBuildDir(buildDir)
			if err != nil {
				log.Warningf("[%s/%s/%s] Error removing builddir: %v", pkg.FullRepo, pkg.Pkgbase, pkg.Version, err)
			}
		}
	}
}

func (b *BuildManager) parseWorker() {
	for {
		if b.exit {
			return
		}
		select {
		case pkg := <-b.parse:
			if err := pkg.genSrcinfo(); err != nil {
				log.Warningf("Failed to generate SRCINFO for %s: %v", pkg.Pkgbase, err)
				b.parseWG.Done()
				continue
			}
			pkg.Version = constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)

			if !pkg.isAvailable(alpmHandle) {
				log.Debugf("[%s/%s] Not available on mirror, skipping build", pkg.FullRepo, pkg.Pkgbase)
				b.parseWG.Done()
				continue
			}

			pkg.toDbPackage(true)
			skipping := false
			if contains(pkg.Srcinfo.Arch, "any") {
				log.Debugf("Skipped %s: any-Package", pkg.Srcinfo.Pkgbase)
				pkg.DbPackage.SkipReason = "arch = any"
				pkg.DbPackage.Status = dbpackage.StatusSkipped
				skipping = true
			} else if contains(conf.Blacklist.Packages, pkg.Srcinfo.Pkgbase) {
				log.Debugf("Skipped %s: blacklisted package", pkg.Srcinfo.Pkgbase)
				pkg.DbPackage.SkipReason = "blacklisted"
				pkg.DbPackage.Status = dbpackage.StatusSkipped
				skipping = true
			} else if contains(pkg.Srcinfo.MakeDepends, "ghc") || contains(pkg.Srcinfo.MakeDepends, "haskell-ghc") || contains(pkg.Srcinfo.Depends, "ghc") || contains(pkg.Srcinfo.Depends, "haskell-ghc") {
				// Skip Haskell packages for now, as we are facing linking problems with them,
				// most likely caused by not having a dependency check implemented yet and building at random.
				// https://git.harting.dev/anonfunc/ALHP.GO/issues/11
				log.Debugf("Skipped %s: haskell package", pkg.Srcinfo.Pkgbase)
				pkg.DbPackage.SkipReason = "blacklisted (haskell)"
				pkg.DbPackage.Status = dbpackage.StatusSkipped
				skipping = true
			} else if isPkgFailed(pkg) {
				log.Debugf("Skipped %s: failed build", pkg.Srcinfo.Pkgbase)
				skipping = true
			}

			if skipping {
				pkg.DbPackage = pkg.DbPackage.Update().SetUpdated(time.Now()).SetVersion(pkg.Version).
					SetPackages(packages2slice(pkg.Srcinfo.Packages)).SetStatus(pkg.DbPackage.Status).
					SetSkipReason(pkg.DbPackage.SkipReason).SetHash(pkg.Hash).SaveX(context.Background())
				b.repoPurge[pkg.FullRepo] <- pkg
				b.parseWG.Done()
				continue
			} else {
				pkg.DbPackage = pkg.DbPackage.Update().SetUpdated(time.Now()).SetPackages(packages2slice(pkg.Srcinfo.Packages)).SetVersion(pkg.Version).SaveX(context.Background())
			}

			if contains(conf.Blacklist.LTO, pkg.Pkgbase) {
				pkg.DbPackage = pkg.DbPackage.Update().SetLto(dbpackage.LtoDisabled).SaveX(context.Background())
			}

			repoVer, err := pkg.repoVersion()
			if err != nil {
				pkg.DbPackage = pkg.DbPackage.Update().ClearRepoVersion().SaveX(context.Background())
			} else if err == nil && alpm.VerCmp(repoVer, pkg.Version) > 0 {
				log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", pkg.Srcinfo.Pkgbase, pkg.Version, repoVer)
				pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetHash(pkg.Hash).SaveX(context.Background())
				b.parseWG.Done()
				continue
			}

			isLatest, local, syncVersion, err := pkg.isMirrorLatest(alpmHandle)
			if err != nil {
				switch err.(type) {
				default:
					log.Warningf("[%s/%s] Problem solving dependencies: %v", pkg.FullRepo, pkg.Srcinfo.Pkgbase, err)
				case MultiplePKGBUILDError:
					log.Infof("Skipped %s: Multiple PKGBUILDs for dependency found: %v", pkg.Srcinfo.Pkgbase, err)
					pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(context.Background())
					b.repoPurge[pkg.FullRepo] <- pkg
					b.parseWG.Done()
					continue
				case UnableToSatisfyError:
					log.Infof("Skipped %s: unable to resolve dependencies: %v", pkg.Srcinfo.Pkgbase, err)
					pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(context.Background())
					b.repoPurge[pkg.FullRepo] <- pkg
					b.parseWG.Done()
					continue
				}
			}

			pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusQueued).SaveX(context.Background())

			if !isLatest {
				if local != nil {
					log.Infof("Delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)", pkg.Srcinfo.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
					pkg.DbPackage.Update().SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).ExecX(context.Background())
				} else {
					log.Infof("Delayed %s: not all dependencies are up to date or resolvable", pkg.Srcinfo.Pkgbase)
					pkg.DbPackage.Update().SetSkipReason("waiting for mirror").ExecX(context.Background())
				}

				// Purge delayed packages in case delay is caused by inconsistencies in svn2git.
				// Worst case would be clients downloading a package update twice, once from their official mirror,
				// and then after build from ALHP. Best case we prevent a not buildable package from staying in the repos
				// in an outdated version.
				b.repoPurge[pkg.FullRepo] <- pkg
				b.parseWG.Done()
				continue
			}

			b.parseWG.Done()

			b.queuedLock.RLock()
			if b.queued[pkg.March] >= conf.Build.Batch {
				b.queuedLock.RUnlock()
				continue
			}
			b.queuedLock.RUnlock()
			b.queuedLock.Lock()
			b.queued[pkg.March]++
			b.queuedLock.Unlock()

			b.build[pkg.March] <- pkg
		}
	}
}

func (b *BuildManager) htmlWorker() {
	type Pkg struct {
		Pkgbase         string
		Status          string
		Class           string
		Skip            string
		Version         string
		Svn2GitVersion  string
		BuildDate       string
		BuildDuration   time.Duration
		Checked         string
		Log             string
		LTO             bool
		LTOUnknown      bool
		LTODisabled     bool
		LTOAutoDisabled bool
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

				pkgs := db.DbPackage.Query().Order(ent.Asc(dbpackage.FieldPkgbase)).Where(dbpackage.MarchEQ(march), dbpackage.RepositoryEQ(dbpackage.Repository(repo))).AllX(context.Background())

				for _, pkg := range pkgs {

					addPkg := Pkg{
						Pkgbase:        pkg.Pkgbase,
						Status:         strings.ToUpper(pkg.Status.String()),
						Class:          statusId2string(pkg.Status),
						Skip:           pkg.SkipReason,
						Version:        pkg.RepoVersion,
						Svn2GitVersion: pkg.Version,
					}

					if !pkg.BuildTimeEnd.IsZero() && !pkg.BuildTimeStart.IsZero() && pkg.BuildTimeStart.Before(pkg.BuildTimeEnd) {
						addPkg.BuildDuration = pkg.BuildTimeEnd.Sub(pkg.BuildTimeStart)
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

		db.DbPackage.Query().GroupBy(dbpackage.FieldStatus).Aggregate(ent.Count()).ScanX(context.Background(), &v)

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

		db.DbPackage.Query().Where(dbpackage.StatusNEQ(dbpackage.StatusSkipped)).GroupBy(dbpackage.FieldLto).Aggregate(ent.Count()).ScanX(context.Background(), &v2)

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
		check(err)

		f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, "packages.html"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		check(statusTpl.Execute(f, gen))
		check(f.Close())

		time.Sleep(time.Minute)
	}
}

func (b *BuildManager) repoWorker(repo string) {
	for {
		select {
		case pkg := <-b.repoAdd[repo]:
			args := []string{"-s", "-v", "-p", "-n", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"}
			args = append(args, pkg.PkgFiles...)
			cmd := exec.Command("repo-add", args...)
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil && cmd.ProcessState.ExitCode() != 1 {
				log.Panicf("%s while repo-add: %v", string(res), err)
			}

			pkg.toDbPackage(true)
			pkg.DbPackage = pkg.DbPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetRepoVersion(pkg.Version).SetHash(pkg.Hash).SaveX(context.Background())

			cmd = exec.Command("paccache",
				"-rc", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch),
				"-k", "1")
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			check(err)
			updateLastUpdated()
			b.buildWG.Done()
		case pkg := <-b.repoPurge[repo]:
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
				fNameSplit := strings.Split(filepath.Base(filePath), "-")
				pkgname := strings.Join(fNameSplit[:len(fNameSplit)-3], "-")
				realPkgs = append(realPkgs, pkgname)
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

			if pkg.DbPackage != nil {
				_ = pkg.DbPackage.Update().ClearRepoVersion().Exec(context.Background())
			}

			for _, file := range pkg.PkgFiles {
				_ = os.Remove(file)
				_ = os.Remove(file + ".sig")
			}
			updateLastUpdated()
			b.repoWG.Done()
		}
	}
}

func (b *BuildManager) syncWorker() {
	check(os.MkdirAll(conf.Basedir.Upstream, 0755))

	for i := 0; i < runtime.NumCPU(); i++ {
		go b.parseWorker()
	}

	for {
		b.buildWG.Wait()

		for gitDir, gitURL := range conf.Svn2git {
			gitPath := filepath.Join(conf.Basedir.Upstream, gitDir)

			if _, err := os.Stat(gitPath); os.IsNotExist(err) {
				cmd := exec.Command("git", "clone", "--depth=1", gitURL, gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)
			} else if err == nil {
				cmd := exec.Command("sh", "-c", "cd "+gitPath+" && git reset --hard")
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)

				cmd = exec.Command("sh", "-c", "cd "+gitPath+" && git pull")
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
			repo := repo
			go func() {
				err := housekeeping(repo, wg)
				if err != nil {
					log.Warningf("[%s] housekeeping failed: %v", repo, err)
				}
			}()
		}
		wg.Wait()

		// fetch updates between sync runs
		b.alpmMutex.Lock()
		check(alpmHandle.Release())
		err := setupChroot()
		for err != nil {
			log.Warningf("Unable to upgrade chroot, trying again later.")
			time.Sleep(time.Minute)
			err = setupChroot()
		}

		alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Chroot, pristineChroot), filepath.Join(conf.Basedir.Chroot, pristineChroot, "/var/lib/pacman"))
		check(err)
		b.alpmMutex.Unlock()

		// clear batch limits
		b.queuedLock.Lock()
		b.queued = map[string]int{}
		b.queuedLock.Unlock()

		pkgBuilds, err := Glob(filepath.Join(conf.Basedir.Upstream, "/**/PKGBUILD"))
		check(err)

		for _, pkgbuild := range pkgBuilds {
			if b.exit {
				return
			}

			sPkgbuild := strings.Split(pkgbuild, "/")
			repo := sPkgbuild[len(sPkgbuild)-2]

			if repo == "trunk" || !contains(conf.Repos, strings.Split(repo, "-")[0]) || containsSubStr(repo, conf.Blacklist.Repo) {
				continue
			}

			for _, march := range conf.March {
				// compare b3sum of PKGBUILD file to hash in database, only proceed if hash differs
				// reduces the amount of PKGBUILDs that need to be parsed with makepkg, which is _really_ slow, significantly
				dbPkg, dbErr := db.DbPackage.Query().Where(dbpackage.And(
					dbpackage.Pkgbase(sPkgbuild[len(sPkgbuild)-4]),
					dbpackage.RepositoryEQ(dbpackage.Repository(strings.Split(repo, "-")[0])), dbpackage.March(march)),
				).Only(context.Background())

				if dbErr != nil {
					switch dbErr.(type) {
					case *ent.NotFoundError:
						log.Debugf("[%s/%s] Package not found in database", strings.Split(repo, "-")[0], sPkgbuild[len(sPkgbuild)-4])
						break
					default:
						log.Errorf("[%s/%s] Problem querying db for package: %v", strings.Split(repo, "-")[0], sPkgbuild[len(sPkgbuild)-4], dbErr)
					}
				}

				b3s, err := b3sum(pkgbuild)
				check(err)

				if dbPkg != nil && b3s == dbPkg.Hash {
					log.Debugf("[%s/%s] Skipped: PKGBUILD hash matches db (%s)", strings.Split(repo, "-")[0], sPkgbuild[len(sPkgbuild)-4], b3s)
					continue
				}

				// send to parse
				b.parseWG.Add(1)
				b.parse <- &BuildPackage{
					Pkgbuild: pkgbuild,
					Pkgbase:  sPkgbuild[len(sPkgbuild)-4],
					Repo:     dbpackage.Repository(strings.Split(repo, "-")[0]),
					March:    march,
					FullRepo: strings.Split(repo, "-")[0] + "-" + march,
					Hash:     b3s,
				}
			}
		}

		b.parseWG.Wait()
		time.Sleep(time.Duration(*checkInterval) * time.Minute)
	}
}

func main() {
	killSignals := make(chan os.Signal, 1)
	signal.Notify(killSignals, syscall.SIGINT, syscall.SIGTERM)

	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGUSR1)

	flag.Parse()

	confStr, err := os.ReadFile("config.yaml")
	check(err)

	err = yaml.Unmarshal(confStr, &conf)
	check(err)

	lvl, err := log.ParseLevel(conf.Logging.Level)
	check(err)
	log.SetLevel(lvl)
	if *journalLog {
		journalhook.Enable()
	}

	err = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 5)
	if err != nil {
		log.Warningf("Failed to drop priority: %v", err)
	}

	err = os.MkdirAll(conf.Basedir.Repo, 0755)
	check(err)

	if conf.Db.Driver == "pgx" {
		pdb, err := sql.Open("pgx", conf.Db.ConnectTo)
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", conf.Db.ConnectTo, err)
		}

		drv := sql.OpenDB(dialect.Postgres, pdb.DB())
		db = ent.NewClient(ent.Driver(drv))
	} else {
		db, err = ent.Open(conf.Db.Driver, conf.Db.ConnectTo)
		if err != nil {
			log.Panicf("Failed to open database %s: %v", conf.Db.ConnectTo, err)
		}
		defer func(Client *ent.Client) {
			_ = Client.Close()
		}(db)
	}

	if err := db.Schema.Create(context.Background(), migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		log.Panicf("Automigrate failed: %v", err)
	}

	buildManager = &BuildManager{
		build:     make(map[string]chan *BuildPackage),
		parse:     make(chan *BuildPackage, 10000),
		repoPurge: make(map[string]chan *BuildPackage),
		repoAdd:   make(map[string]chan *BuildPackage),
		exit:      false,
	}

	err = setupChroot()
	if err != nil {
		log.Fatalf("Unable to setup chroot: %v", err)
	}
	syncMarchs()

	alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Chroot, pristineChroot), filepath.Join(conf.Basedir.Chroot, pristineChroot, "/var/lib/pacman"))
	check(err)

	go buildManager.syncWorker()
	go buildManager.htmlWorker()

killLoop:
	for {
		select {
		case <-killSignals:
			break killLoop
		case <-reloadSignals:
			confStr, err := os.ReadFile("config.yaml")
			if err != nil {
				log.Fatalf("Unable to open config: %v", err)
			}

			err = yaml.Unmarshal(confStr, &conf)
			if err != nil {
				log.Fatalf("Unable to parse config: %v", err)
			}

			lvl, err := log.ParseLevel(conf.Logging.Level)
			if err != nil {
				log.Fatalf("Failure setting logging level: %v", err)
			}
			log.SetLevel(lvl)
			log.Infof("Config reloaded")
		}
	}

	buildManager.exit = true
	buildManager.buildProcMutex.RLock()
	for _, p := range buildManager.buildProcesses {
		pgid, err := syscall.Getpgid(p.Pid)
		check(err)

		check(syscall.Kill(-pgid, syscall.SIGTERM))
	}
	buildManager.buildProcMutex.RUnlock()
	buildManager.buildWG.Wait()
	buildManager.repoWG.Wait()
	check(alpmHandle.Release())
}
