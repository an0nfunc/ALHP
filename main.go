package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
	"ALHP.go/ent/migrate"
	"bytes"
	"context"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"gopkg.in/yaml.v2"
	"html/template"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	conf         = Conf{}
	repos        []string
	alpmHandle   *alpm.Handle
	reMarch      = regexp.MustCompile(`(-march=)(.+?) `)
	rePkgRel     = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile    = regexp.MustCompile(`^(.*)-.*-.*-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	buildManager BuildManager
	db           *ent.Client
	dbLock       sync.RWMutex
)

func (b *BuildManager) buildWorker(id int) {
	err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 18)
	if err != nil {
		log.Warningf("[worker-%d] Failed to drop priority: %v", id, err)
	}

	for {
		select {
		case pkg := <-b.build:
			if b.exit {
				log.Infof("Worker %d exited...", id)
				return
			} else {
				b.buildWG.Add(1)
			}

			start := time.Now()

			log.Infof("[%s/%s] Build starting", pkg.FullRepo, pkg.Pkgbase)

			dbPkg := getDbPackage(pkg)
			dbLock.Lock()
			dbPkg.Update().SetStatus(BUILDING).SetBuildTime(time.Now().UTC()).SetSkipReason("").SaveX(context.Background())
			dbLock.Unlock()

			err := importKeys(pkg)
			if err != nil {
				log.Warningf("[%s/%s] Failed to import pgp keys: %v", pkg.FullRepo, pkg.Pkgbase, err)
			}

			err = increasePkgRel(pkg)
			if err != nil {
				log.Errorf("[%s/%s] Failed to increase pkgrel: %v", pkg.FullRepo, pkg.Pkgbase, err)
				b.buildWG.Done()
				continue
			}
			pkg.PkgFiles = []string{}

			cmd := exec.Command("sh", "-c",
				"cd "+filepath.Dir(pkg.Pkgbuild)+"&&makechrootpkg -c -D "+conf.Basedir.Makepkg+" -l worker-"+strconv.Itoa(id)+" -r "+conf.Basedir.Chroot+" -- "+
					"--config "+filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf("makepkg-%s.conf", pkg.March)))
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
					gitClean(pkg)
					b.buildWG.Done()
					continue
				}

				log.Warningf("[%s/%s] Build failed, exit code %d", pkg.FullRepo, pkg.Pkgbase, cmd.ProcessState.ExitCode())

				b.failedMutex.Lock()
				f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, pkg.FullRepo+"_failed.txt"), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, os.ModePerm)
				check(err)

				_, err = f.WriteString(fmt.Sprintf("%s==%s\n", pkg.Pkgbase, constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)))
				check(err)
				check(f.Close())
				b.failedMutex.Unlock()

				check(os.MkdirAll(filepath.Join(conf.Basedir.Repo, "logs"), os.ModePerm))
				check(os.WriteFile(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log"), out.Bytes(), os.ModePerm))

				dbPkg := getDbPackage(pkg)
				dbLock.Lock()
				dbPkg.Update().SetStatus(FAILED).SetBuildTime(time.Now()).SetBuildDuration(uint64(time.Now().Sub(start).Milliseconds())).SaveX(context.Background())
				dbLock.Unlock()

				gitClean(pkg)
				b.buildWG.Done()
				continue
			}

			pkgFiles, err := filepath.Glob(filepath.Join(filepath.Dir(pkg.Pkgbuild), "*.pkg.tar.zst"))
			check(err)
			log.Debug(pkgFiles)

			if len(pkgFiles) == 0 {
				log.Warningf("No packages found after building %s. Abort build.", pkg.Pkgbase)

				gitClean(pkg)
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

			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log")); err == nil {
				check(os.Remove(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log")))
			}

			dbPkg = getDbPackage(pkg)
			dbLock.Lock()
			dbPkg.Update().SetStatus(BUILD).SetBuildDuration(uint64(time.Now().Sub(start).Milliseconds())).SaveX(context.Background())
			dbLock.Unlock()

			log.Infof("[%s/%s] Build successful (%s)", pkg.FullRepo, pkg.Pkgbase, time.Now().Sub(start))
			b.repoAdd[pkg.FullRepo] <- pkg

			gitClean(pkg)
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
			cmd := exec.Command("sh", "-c", "cd "+filepath.Dir(pkg.Pkgbuild)+"&&"+"makepkg --printsrcinfo")
			res, err := cmd.Output()
			if err != nil {
				log.Warningf("Failed generate SRCINFO for %s: %v", pkg.Pkgbase, err)
				b.parseWG.Done()
				continue
			}

			info, err := srcinfo.Parse(string(res))
			if err != nil {
				log.Warningf("Failed to parse SRCINFO for %s: %v", pkg.Pkgbase, err)
				b.parseWG.Done()
				continue
			}
			pkg.Srcinfo = info
			pkg.Version = constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)

			dbPkg := getDbPackage(pkg)
			dbLock.Lock()
			dbPkg = dbPkg.Update().SetUpdated(time.Now()).SetVersion(pkg.Version).SaveX(context.Background())
			dbLock.Unlock()

			skipping := false
			if contains(info.Arch, "any") {
				log.Debugf("Skipped %s: any-Package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("arch = any").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if contains(conf.Blacklist.Packages, info.Pkgbase) {
				log.Debugf("Skipped %s: blacklisted package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("blacklisted").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if contains(info.MakeDepends, "ghc") || contains(info.MakeDepends, "haskell-ghc") || contains(info.Depends, "ghc") || contains(info.Depends, "haskell-ghc") {
				// Skip Haskell packages for now, as we are facing linking problems with them,
				// most likely caused by not having a dependency check implemented yet and building at random.
				// https://git.harting.dev/anonfunc/ALHP.GO/issues/11
				log.Debugf("Skipped %s: haskell package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("blacklisted (haskell)").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if isPkgFailed(pkg) {
				log.Debugf("Skipped %s: failed build", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(FAILED).SetSkipReason("").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			}

			if skipping {
				b.repoPurge[pkg.FullRepo] <- pkg
				b.parseWG.Done()
				continue
			}

			repoVer := getVersionFromRepo(pkg)
			dbLock.Lock()
			dbPkg = dbPkg.Update().SetRepoVersion(repoVer).SaveX(context.Background())
			dbLock.Unlock()
			if repoVer != "" && alpm.VerCmp(repoVer, pkg.Version) > 0 {
				log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", info.Pkgbase, pkg.Version, repoVer)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(LATEST).SetSkipReason("").SaveX(context.Background())
				dbLock.Unlock()
				b.parseWG.Done()
				continue
			}

			isLatest, local, syncVersion, err := isMirrorLatest(alpmHandle, pkg)
			if err != nil {
				log.Warningf("[%s/%s] Problem solving dependencies: %v", pkg.FullRepo, info.Pkgbase, err)
			}

			dbLock.Lock()
			dbPkg = dbPkg.Update().SetStatus(QUEUED).SaveX(context.Background())
			dbLock.Unlock()

			if !isLatest {
				if local != nil {
					log.Infof("Delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)", info.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
					dbLock.Lock()
					dbPkg = dbPkg.Update().SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).SaveX(context.Background())
					dbLock.Unlock()
				} else {
					log.Infof("Delayed %s: not all dependencies are up to date", info.Pkgbase)
					dbLock.Lock()
					dbPkg = dbPkg.Update().SetSkipReason("waiting for mirror").SaveX(context.Background())
					dbLock.Unlock()
				}

				b.parseWG.Done()
				continue
			}

			b.parseWG.Done()
			b.build <- pkg
		}
	}
}

func (b *BuildManager) htmlWorker() {
	type Pkg struct {
		Pkgbase        string
		Status         string
		Class          string
		Skip           string
		Version        string
		Svn2GitVersion string
		BuildDate      string
		BuildDuration  time.Duration
		Checked        string
		Log            string
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
		March     []March
		Generated time.Time
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

				dbLock.RLock()
				pkgs := db.DbPackage.Query().Order(ent.Asc(dbpackage.FieldPkgbase)).Where(dbpackage.MarchEQ(march), dbpackage.RepositoryEQ(repo)).AllX(context.Background())
				dbLock.RUnlock()

				for _, pkg := range pkgs {
					status, class := statusId2string(pkg.Status)

					addPkg := Pkg{
						Pkgbase:        pkg.Pkgbase,
						Status:         status,
						Class:          class,
						Skip:           pkg.SkipReason,
						Version:        pkg.RepoVersion,
						Svn2GitVersion: pkg.Version,
					}

					if pkg.BuildDuration > 0 {
						duration, err := time.ParseDuration(strconv.Itoa(int(pkg.BuildDuration)) + "ms")
						check(err)
						addPkg.BuildDuration = duration
					}

					if !pkg.BuildTime.IsZero() {
						addPkg.BuildDate = pkg.BuildTime.UTC().Format(time.RFC3339)
					}

					if !pkg.Updated.IsZero() {
						addPkg.Checked = pkg.Updated.UTC().Format(time.RFC3339)
					}

					if pkg.Status == FAILED {
						addPkg.Log = fmt.Sprintf("logs/%s.log", pkg.Pkgbase)
					}

					addRepo.Packages = append(addRepo.Packages, addPkg)
				}
				addMarch.Repos = append(addMarch.Repos, addRepo)
			}
			gen.March = append(gen.March, addMarch)
		}

		gen.Generated = time.Now().UTC()

		statusTpl, err := template.ParseFiles("tpl/packages.html")
		check(err)

		f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, "packages.html"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
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

			dbPkg := getDbPackage(pkg)
			dbLock.Lock()
			dbPkg = dbPkg.Update().SetStatus(LATEST).SetSkipReason("").SetRepoVersion(pkg.Version).SaveX(context.Background())
			dbLock.Unlock()

			cmd = exec.Command("paccache",
				"-rc", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch),
				"-k", "1")
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			check(err)
			b.buildWG.Done()
		case pkg := <-b.repoPurge[repo]:
			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"); err != nil {
				continue
			}
			if len(pkg.PkgFiles) == 0 {
				findPkgFiles(pkg)
				if len(pkg.PkgFiles) == 0 {
					continue
				}
			}

			var realPkgs []string
			for _, realPkg := range pkg.Srcinfo.Packages {
				realPkgs = append(realPkgs, realPkg.Pkgname)
			}

			b.repoWG.Add(1)
			args := []string{"-s", "-v", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"}
			args = append(args, realPkgs...)
			cmd := exec.Command("repo-remove", args...)
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil && cmd.ProcessState.ExitCode() == 1 {
				log.Debugf("Deleteing package %s failed: Package not found in database", pkg.Pkgbase)
				b.repoWG.Done()
				continue
			}

			dbPkg := getDbPackage(pkg)
			dbLock.Lock()
			dbPkg = dbPkg.Update().SetRepoVersion("").SaveX(context.Background())
			dbLock.Unlock()

			for _, file := range pkg.PkgFiles {
				check(os.Remove(file))
				check(os.Remove(file + ".sig"))
			}
			b.repoWG.Done()
		}
	}
}

func (b *BuildManager) syncWorker() {
	check(os.MkdirAll(conf.Basedir.Upstream, os.ModePerm))

	for i := 0; i < conf.Build.Worker; i++ {
		go b.buildWorker(i)
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go b.parseWorker()
	}

	for {
		b.buildWG.Wait()

		/* TODO: Use `v` to print rudimentary stats
		var v []struct {
			Status int `json:"status"`
			Count  int `json:"count"`
		}

		dbLock.RLock()
		db.DbPackage.Query().GroupBy(dbpackage.FieldStatus).Aggregate(ent.Count()).ScanX(context.Background(), &v)
		dbLock.RUnlock()
		*/

		for gitDir, gitURL := range conf.Svn2git {
			gitPath := filepath.Join(conf.Basedir.Upstream, gitDir)

			if _, err := os.Stat(gitPath); os.IsNotExist(err) {
				cmd := exec.Command("git", "clone", "--depth=1", gitURL, gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)
			} else if err == nil {
				cmd := exec.Command("sudo", "git_clean.sh", gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				if err != nil {
					log.Warningf("Failed to execute %s: %v", cmd.String(), err)
				}

				cmd = exec.Command("sh", "-c", "cd "+gitPath+" && git reset --hard")
				res, err = cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)

				cmd = exec.Command("sh", "-c", "cd "+gitPath+" && git pull")
				res, err = cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)
			}
		}

		// fetch updates between sync runs
		check(alpmHandle.Release())
		setupChroot()
		var err error
		alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Chroot, pristineChroot), filepath.Join(conf.Basedir.Chroot, pristineChroot, "/var/lib/pacman"))
		check(err)

		pkgBuilds, err := Glob(filepath.Join(conf.Basedir.Upstream, "/**/PKGBUILD"))
		check(err)

		// Shuffle pkgbuilds to spread out long-running builds, otherwise pkgBuilds is alphabetically-sorted
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(pkgBuilds), func(i, j int) { pkgBuilds[i], pkgBuilds[j] = pkgBuilds[j], pkgBuilds[i] })

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
				b.parseWG.Add(1)
				b.parse <- &BuildPackage{
					Pkgbuild: pkgbuild,
					Pkgbase:  sPkgbuild[len(sPkgbuild)-4],
					Repo:     strings.Split(repo, "-")[0],
					March:    march,
					FullRepo: strings.Split(repo, "-")[0] + "-" + march,
				}
			}
		}

		b.parseWG.Wait()
		time.Sleep(5 * time.Minute)
	}
}

func main() {
	killSignals := make(chan os.Signal, 1)
	signal.Notify(killSignals, syscall.SIGINT, syscall.SIGTERM)

	confStr, err := os.ReadFile("config.yaml")
	check(err)

	err = yaml.Unmarshal(confStr, &conf)
	check(err)

	lvl, err := log.ParseLevel(conf.Logging.Level)
	check(err)
	log.SetLevel(lvl)
	journalhook.Enable()

	err = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 5)
	if err != nil {
		log.Warningf("Failed to drop priority: %v", err)
	}

	err = os.MkdirAll(conf.Basedir.Repo, os.ModePerm)
	check(err)

	db, err = ent.Open("sqlite3", "file:"+conf.Basedir.Db+"?_fk=1&cache=shared")
	if err != nil {
		log.Panicf("Failed to open database %s: %v", conf.Basedir.Db, err)
	}
	defer func(dbSQLite *ent.Client) {
		check(dbSQLite.Close())
	}(db)

	if err := db.Schema.Create(context.Background(), migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		log.Panicf("Automigrate failed: %v", err)
	}

	buildManager = BuildManager{
		build:     make(chan *BuildPackage, 10000),
		parse:     make(chan *BuildPackage, 10000),
		repoPurge: make(map[string]chan *BuildPackage),
		repoAdd:   make(map[string]chan *BuildPackage),
		exit:      false,
	}

	setupChroot()
	syncMarchs()

	alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Chroot, pristineChroot), filepath.Join(conf.Basedir.Chroot, pristineChroot, "/var/lib/pacman"))
	check(err)

	go buildManager.syncWorker()
	go buildManager.htmlWorker()

	<-killSignals

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
