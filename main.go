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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	conf          *Conf
	repos         []string
	alpmHandle    *alpm.Handle
	reMarch       = regexp.MustCompile(`(-march=)(.+?) `)
	rePkgRel      = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile     = regexp.MustCompile(`^(.*)-.*-.*-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	buildManager  *BuildManager
	db            *ent.Client
	journalLog    = flag.Bool("journal", false, "Log to systemd journal instead of stdout")
	checkInterval = flag.Int("interval", 5, "How often svn2git should be checked in minutes (default: 5)")
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
			dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusBuilding).SetBuildTimeStart(time.Now().UTC()).SetSkipReason("").SaveX(context.Background())

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
			ltoDisabled := false

			// default to LTO
			makepkgFile := "makepkg-%s-lto.conf"
			if contains(conf.Blacklist.LTO, pkg.Pkgbase) {
				// use non-lto makepkg.conf if LTO is blacklisted for this package
				makepkgFile = "makepkg-%s.conf"
				ltoDisabled = true
				dbPkg.Update().SetLto(dbpackage.LtoDisabled).ExecX(context.Background())
			}
			cmd := exec.Command("sh", "-c",
				"cd "+filepath.Dir(pkg.Pkgbuild)+"&&makechrootpkg -c -D "+conf.Basedir.Makepkg+" -l worker-"+strconv.Itoa(id)+" -r "+conf.Basedir.Chroot+" -- "+
					"--config "+filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf(makepkgFile, pkg.March)))
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
				f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, pkg.FullRepo+"_failed.txt"), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, 0644)
				check(err)

				_, err = f.WriteString(fmt.Sprintf("%s==%s\n", pkg.Pkgbase, constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)))
				check(err)
				check(f.Close())
				b.failedMutex.Unlock()

				check(os.MkdirAll(filepath.Join(conf.Basedir.Repo, "logs"), 0755))
				check(os.WriteFile(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log"), out.Bytes(), 0644))

				dbPkg.Update().SetStatus(dbpackage.StatusFailed).SetBuildTimeEnd(time.Now()).SetHash(pkg.Hash).ExecX(context.Background())

				// purge failed package from repo
				b.repoPurge[pkg.FullRepo] <- pkg

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

			if !ltoDisabled {
				dbPkg.Update().SetStatus(dbpackage.StatusBuild).SetLto(dbpackage.LtoEnabled).SetBuildTimeEnd(time.Now().UTC()).ExecX(context.Background())
			} else {
				dbPkg.Update().SetStatus(dbpackage.StatusBuild).SetLto(dbpackage.LtoDisabled).SetBuildTimeEnd(time.Now().UTC()).ExecX(context.Background())
			}

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
			info, err := genSRCINFO(pkg.Pkgbuild)
			if err != nil {
				log.Warningf("Failed to generate SRCINFO for %s: %v", pkg.Pkgbase, err)
				b.parseWG.Done()
				continue
			}
			pkg.Srcinfo = info
			pkg.Version = constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)

			dbPkg := getDbPackage(pkg)
			dbPkg = dbPkg.Update().SetUpdated(time.Now()).SetVersion(pkg.Version).SaveX(context.Background())

			skipping := false
			if contains(info.Arch, "any") {
				log.Debugf("Skipped %s: any-Package", info.Pkgbase)
				dbPkg.SkipReason = "arch = any"
				dbPkg.Status = dbpackage.StatusSkipped
				skipping = true
			} else if contains(conf.Blacklist.Packages, info.Pkgbase) {
				log.Debugf("Skipped %s: blacklisted package", info.Pkgbase)
				dbPkg.SkipReason = "blacklisted"
				dbPkg.Status = dbpackage.StatusSkipped
				skipping = true
			} else if contains(info.MakeDepends, "ghc") || contains(info.MakeDepends, "haskell-ghc") || contains(info.Depends, "ghc") || contains(info.Depends, "haskell-ghc") {
				// Skip Haskell packages for now, as we are facing linking problems with them,
				// most likely caused by not having a dependency check implemented yet and building at random.
				// https://git.harting.dev/anonfunc/ALHP.GO/issues/11
				log.Debugf("Skipped %s: haskell package", info.Pkgbase)
				dbPkg.SkipReason = "blacklisted (haskell)"
				dbPkg.Status = dbpackage.StatusSkipped
				skipping = true
			} else if isPkgFailed(pkg) {
				log.Debugf("Skipped %s: failed build", info.Pkgbase)
				dbPkg.SkipReason = ""
				dbPkg.Status = dbpackage.StatusFailed
				skipping = true
			}

			if skipping {
				dbPkg = dbPkg.Update().SetStatus(dbPkg.Status).SetSkipReason(dbPkg.SkipReason).SetHash(pkg.Hash).SaveX(context.Background())
				b.repoPurge[pkg.FullRepo] <- pkg
				b.parseWG.Done()
				continue
			}

			repoVer := getVersionFromRepo(pkg)
			dbPkg = dbPkg.Update().SetRepoVersion(repoVer).SaveX(context.Background())
			if repoVer != "" && alpm.VerCmp(repoVer, pkg.Version) > 0 {
				log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", info.Pkgbase, pkg.Version, repoVer)
				dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusLatest).SetSkipReason("").SetHash(pkg.Hash).SaveX(context.Background())
				b.parseWG.Done()
				continue
			}

			isLatest, local, syncVersion, err := isMirrorLatest(alpmHandle, pkg)
			if err != nil {
				switch err.(type) {
				default:
					log.Warningf("[%s/%s] Problem solving dependencies: %v", pkg.FullRepo, info.Pkgbase, err)
				case MultiplePKGBUILDError:
					log.Infof("Skipped %s: Multiple PKGBUILDs for dependency found: %v", info.Pkgbase, err)
					dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(context.Background())
					b.repoPurge[pkg.FullRepo] <- pkg
					b.parseWG.Done()
					continue
				case UnableToSatisfyError:
					log.Infof("Skipped %s: unable to resolve dependencies: %v", info.Pkgbase, err)
					dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(context.Background())
					b.repoPurge[pkg.FullRepo] <- pkg
					b.parseWG.Done()
					continue
				}
			}

			dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusQueued).SaveX(context.Background())

			if !isLatest {
				if local != nil {
					log.Infof("Delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)", info.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
					dbPkg.Update().SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).ExecX(context.Background())
				} else {
					log.Infof("Delayed %s: not all dependencies are up to date or resolvable", info.Pkgbase)
					dbPkg.Update().SetSkipReason("waiting for mirror").ExecX(context.Background())
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
		LTO            bool
		LTOUnknown     bool
		LTODisabled    bool
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
		Generated string
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
					status, class := statusId2string(pkg.Status)

					addPkg := Pkg{
						Pkgbase:        pkg.Pkgbase,
						Status:         status,
						Class:          class,
						Skip:           pkg.SkipReason,
						Version:        pkg.RepoVersion,
						Svn2GitVersion: pkg.Version,
					}

					if !pkg.BuildTimeEnd.IsZero() && !pkg.BuildTimeStart.IsZero() {
						addPkg.BuildDuration = pkg.BuildTimeEnd.Sub(pkg.BuildTimeStart)
					}

					if !pkg.BuildTimeStart.IsZero() {
						addPkg.BuildDate = pkg.BuildTimeStart.UTC().Format(time.RFC1123)
					}

					if !pkg.Updated.IsZero() {
						addPkg.Checked = pkg.Updated.UTC().Format(time.RFC1123)
					}

					if pkg.Status == dbpackage.StatusFailed {
						addPkg.Log = fmt.Sprintf("logs/%s.log", pkg.Pkgbase)
					}

					switch pkg.Lto {
					case dbpackage.LtoUnknown:
						addPkg.LTOUnknown = true
					case dbpackage.LtoEnabled:
						addPkg.LTO = true
					case dbpackage.LtoDisabled:
						addPkg.LTODisabled = true
					}

					addRepo.Packages = append(addRepo.Packages, addPkg)
				}
				addMarch.Repos = append(addMarch.Repos, addRepo)
			}
			gen.March = append(gen.March, addMarch)
		}

		gen.Generated = time.Now().UTC().Format(time.RFC1123)

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

			dbPkg := getDbPackage(pkg)
			dbPkg = dbPkg.Update().SetStatus(dbpackage.StatusLatest).SetSkipReason("").SetRepoVersion(pkg.Version).SetHash(pkg.Hash).SaveX(context.Background())

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
			dbPkg = dbPkg.Update().SetRepoVersion("").SaveX(context.Background())

			for _, file := range pkg.PkgFiles {
				check(os.Remove(file))
				check(os.Remove(file + ".sig"))
			}
			updateLastUpdated()
			b.repoWG.Done()
		}
	}
}

func (b *BuildManager) syncWorker() {
	check(os.MkdirAll(conf.Basedir.Upstream, 0755))

	for i := 0; i < conf.Build.Worker; i++ {
		go b.buildWorker(i)
	}

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

			// compare b3sum of PKGBUILD file to hash in database, only proceed if hash differs
			// reduces the amount of PKGBUILDs that need to be parsed with makepkg, which is _really_ slow, significantly
			dbPkg, dbErr := db.DbPackage.Query().Where(dbpackage.And(
				dbpackage.Pkgbase(sPkgbuild[len(sPkgbuild)-4]),
				dbpackage.RepositoryEQ(dbpackage.Repository(strings.Split(repo, "-")[0]))),
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
			for _, march := range conf.March {
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
		build:     make(chan *BuildPackage, 10000),
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
