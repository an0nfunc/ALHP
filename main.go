package main

import (
	"context"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"flag"
	"fmt"
	"git.harting.dev/ALHP/ALHP.GO/ent"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	"git.harting.dev/ALHP/ALHP.GO/ent/migrate"
	"github.com/Jguer/go-alpm/v2"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
	"html/template"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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

		queue, err := b.queue()
		if err != nil {
			log.Warningf("Error building buildQueue: %v", err)
		} else {
			log.Debugf("buildQueue with %d items", len(queue))
			var fastQueue []*ProtoPackage
			var slowQueue []*ProtoPackage

			maxDiff := 0.0
			cutOff := 0.0
			for i := 0; i < len(queue); i++ {
				if i+1 < len(queue) {
					if math.Abs(queue[i].Priority()-queue[i+1].Priority()) > maxDiff {
						maxDiff = math.Abs(queue[i].Priority() - queue[i+1].Priority())
						cutOff = queue[i].Priority()
					}
				}
			}

			for _, pkg := range queue {
				if pkg.Priority() > cutOff && cutOff >= conf.Build.SlowQueueThreshold {
					slowQueue = append(slowQueue, pkg)
				} else {
					fastQueue = append(fastQueue, pkg)
				}
			}

			if len(fastQueue) > 0 && len(slowQueue) > 0 {
				log.Infof("Skipping slowQueue=%d in favor of fastQueue=%d", len(slowQueue), len(fastQueue))
				slowQueue = []*ProtoPackage{}
			}

			err = b.buildQueue(fastQueue, ctx)
			if err != nil {
				return err
			}

			err = b.buildQueue(slowQueue, ctx)
			if err != nil {
				return err
			}

			if err := b.sem.Acquire(ctx, int64(conf.Build.Worker)); err != nil {
				return err
			}
			b.sem.Release(int64(conf.Build.Worker))
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

func main() {
	killSignals := make(chan os.Signal, 1)
	signal.Notify(killSignals, syscall.SIGINT, syscall.SIGTERM)

	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGUSR1)

	flag.Parse()

	confStr, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(confStr, &conf)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	lvl, err := log.ParseLevel(conf.Logging.Level)
	if err != nil {
		log.Fatalf("Error parsing log level from config: %v", err)
	}
	log.SetLevel(lvl)
	if *journalLog {
		journalhook.Enable()
	}

	err = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 5)
	if err != nil {
		log.Infof("Failed to drop priority: %v", err)
	}

	log.Infof("Usable %d bytes of memory ", TotalMemory())

	err = os.MkdirAll(conf.Basedir.Repo, 0o755)
	if err != nil {
		log.Fatalf("Error creating repo dir: %v", err)
	}

	if conf.DB.Driver == "pgx" {
		pdb, err := sql.Open("pgx", conf.DB.ConnectTo)
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", conf.DB.ConnectTo, err)
		}

		drv := sql.OpenDB(dialect.Postgres, pdb.DB())
		db = ent.NewClient(ent.Driver(drv))
	} else {
		db, err = ent.Open(conf.DB.Driver, conf.DB.ConnectTo)
		if err != nil {
			log.Panicf("Failed to open database %s: %v", conf.DB.ConnectTo, err)
		}
		defer func(Client *ent.Client) {
			_ = Client.Close()
		}(db)
	}

	if err := db.Schema.Create(context.Background(), migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		log.Panicf("Automigrate failed: %v", err)
	}

	buildManager = &BuildManager{
		repoPurge: make(map[string]chan []*ProtoPackage),
		repoAdd:   make(map[string]chan []*ProtoPackage),
		sem:       semaphore.NewWeighted(int64(conf.Build.Worker)),
	}

	err = setupChroot()
	if err != nil {
		log.Panicf("Unable to setup chroot: %v", err)
	}
	err = syncMarchs()
	if err != nil {
		log.Panicf("Error syncing marchs: %v", err)
	}

	alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot),
		filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "/var/lib/pacman"))
	if err != nil {
		log.Panicf("Error while ALPM-init: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_ = buildManager.syncWorker(ctx)
	}()
	go buildManager.htmlWorker(ctx)

killLoop:
	for {
		select {
		case <-killSignals:
			break killLoop
		case <-reloadSignals:
			confStr, err := os.ReadFile("config.yaml")
			if err != nil {
				log.Panicf("Unable to open config: %v", err)
			}

			err = yaml.Unmarshal(confStr, &conf)
			if err != nil {
				log.Panicf("Unable to parse config: %v", err)
			}

			lvl, err := log.ParseLevel(conf.Logging.Level)
			if err != nil {
				log.Panicf("Failure setting logging level: %v", err)
			}
			log.SetLevel(lvl)
			log.Infof("Config reloaded")
		}
	}

	cancel()
	buildManager.repoWG.Wait()
	_ = alpmHandle.Release()
}
