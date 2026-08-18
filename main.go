package main

import (
	"context"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"flag"
	"github.com/Jguer/go-alpm/v2"
	_ "github.com/jackc/pgx/v4/stdlib"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"gopkg.in/yaml.v2"
	"os"
	"os/signal"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"somegit.dev/ALHP/ALHP.GO/ent/migrate"
	"sync"
	"syscall"
)

var (
	conf          *Conf
	repos         []string
	alpmHandle    *alpm.Handle
	buildManager  *BuildManager
	db            *ent.Client
	journalLog    = flag.Bool("journal", false, "Log to systemd journal instead of stdout")
	checkInterval = flag.Int("interval", 5, "How often svn2git should be checked in minutes (default: 5)")
	configFile    = flag.String("config", "config.yaml", "set config file name/path")
)

func main() {
	killSignals := make(chan os.Signal, 1)
	signal.Notify(killSignals, syscall.SIGINT, syscall.SIGTERM)

	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGUSR1)

	flag.Parse()

	confStr, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("error reading config file: %v", err)
	}

	err = yaml.Unmarshal(confStr, &conf)
	if err != nil {
		log.Fatalf("error parsing config file: %v", err)
	}

	lvl, err := log.ParseLevel(conf.Logging.Level)
	if err != nil {
		log.Fatalf("error parsing log level from config: %v", err)
	}
	log.SetLevel(lvl)
	if *journalLog {
		journalhook.Enable()
	}

	err = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 5)
	if err != nil {
		log.Infof("failed to drop priority: %v", err)
	}

	err = os.MkdirAll(conf.Basedir.Repo, 0o755)
	if err != nil {
		log.Fatalf("error creating repo dir: %v", err)
	}

	if conf.DB.Driver == "pgx" {
		pdb, err := sql.Open("pgx", conf.DB.ConnectTo)
		if err != nil {
			log.Fatalf("failed to open database %s: %v", conf.DB.ConnectTo, err)
		}

		drv := sql.OpenDB(dialect.Postgres, pdb.DB())
		db = ent.NewClient(ent.Driver(drv))
	} else {
		db, err = ent.Open(conf.DB.Driver, conf.DB.ConnectTo)
		if err != nil {
			log.Panicf("failed to open database %s: %v", conf.DB.ConnectTo, err)
		}
		defer func(Client *ent.Client) {
			_ = Client.Close()
		}(db)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := db.Schema.Create(ctx, migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		log.Panicf("automigrate failed: %v", err)
	}

	if err := seedBuildNo(ctx); err != nil {
		log.Panicf("seeding build numbers failed: %v", err)
	}

	if err := requeueTransient(ctx); err != nil {
		log.Panicf("requeueing transient packages failed: %v", err)
	}

	buildManager = &BuildManager{
		repoPurge:    make(map[string]chan []*ProtoPackage),
		repoAdd:      make(map[string]chan []*ProtoPackage),
		repoFix:      make(map[string]chan repoDBFix),
		queueSignal:  make(chan struct{}),
		alpmMutex:    new(sync.RWMutex),
		building:     []*ProtoPackage{},
		buildingLock: new(sync.RWMutex),
		repoWG:       new(sync.WaitGroup),
		buildWG:      new(sync.WaitGroup),
	}

	buildManager.setupMetrics(conf.Metrics.Port)

	if networkIsolationEnabled() {
		// refuse to start rather than silently build without isolation
		if err := setupNetworkIsolation(ctx); err != nil {
			log.Panicf("network isolation unavailable: %v", err)
		}
	} else {
		log.Warning("build.network_isolation is disabled: builds share the host network namespace, " +
			"and stall_timeout/silence_timeout/timeout cannot kill a build unless ALHP runs as root")
	}

	// before setupChroot: orphans from the last run are dead weight the pacman
	// -Syuu below would otherwise compete with for disk
	sweepBuildDirs()

	err = setupChroot(ctx)
	if err != nil {
		log.Panicf("unable to setup chroot: %v", err)
	}
	err = syncMarchs(ctx)
	if err != nil {
		log.Panicf("error syncing marchs: %v", err)
	}

	alpmHandle, err = initALPM(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot),
		filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "/var/lib/pacman"))
	if err != nil {
		log.Panicf("error while ALPM-init: %v", err)
	}
	// so the first housekeeping pass after a restart checks sonames too
	buildManager.alpmMutex.Lock()
	buildManager.refreshProvided()
	buildManager.alpmMutex.Unlock()

	go func() {
		_ = buildManager.syncWorker(ctx)
	}()

killLoop:
	for {
		select {
		case <-killSignals:
			break killLoop
		case <-reloadSignals:
			confStr, err := os.ReadFile(*configFile)
			if err != nil {
				log.Panicf("unable to open config: %v", err)
			}

			err = yaml.Unmarshal(confStr, &conf)
			if err != nil {
				log.Panicf("unable to parse config: %v", err)
			}

			lvl, err := log.ParseLevel(conf.Logging.Level)
			if err != nil {
				log.Panicf("failure setting logging level: %v", err)
			}
			log.SetLevel(lvl)
			// the startup preflight does not re-run on reload, so state the
			// effective value rather than leaving a flipped flag silent
			log.Infof("config reloaded (network isolation: %t)", networkIsolationEnabled())
		}
	}

	cancel()
	// let in-flight builds return so their deferred cleanup runs; nothing else
	// removes their chroot copies
	buildManager.waitForBuilds()
	buildManager.repoWG.Wait()
	_ = alpmHandle.Release()
}

// seedBuildNo backfills the build-number bookkeeping onto rows written before
// it existed. Left unseeded such a row looks like it never built anything, so
// nextBuildNo restarts it at 1 and republishes a filename that is already on
// mirrors and in user caches.
//
// A purge clears RepoVersion and leaves LastVersionBuild, so a row whose files
// are gone still records what it published, and those rows are exactly the ones
// queued to build next. Reading both is the whole point here and must not be
// narrowed back to RepoVersion alone, in the query or in the raiseBuildNo call.
//
// A row carrying neither restarts at 1. That set is not empty: a build that
// failed after a purge historically had both cleared and cannot be recovered.
// recordFailedBuild no longer clears LastVersionBuild, so it does not grow.
func seedBuildNo(ctx context.Context) error {
	pkgs, err := db.DBPackage.Query().Where(
		dbpackage.Or(dbpackage.MaxVersionBaseIsNil(), dbpackage.MaxVersionBaseEQ("")),
		dbpackage.Or(
			dbpackage.And(dbpackage.RepoVersionNotNil(), dbpackage.RepoVersionNEQ("")),
			dbpackage.And(dbpackage.LastVersionBuildNotNil(), dbpackage.LastVersionBuildNEQ("")),
		),
	).All(ctx)
	if err != nil {
		return err
	}

	seeded := 0
	for _, dbPkg := range pkgs {
		maxVersionBase, buildNo := raiseBuildNo("", 0, dbPkg.RepoVersion, dbPkg.LastVersionBuild)
		if maxVersionBase == "" {
			// only reachable through a version increasePkgRel cannot have written
			log.Warningf("[SEED] %s->%s unreadable versions (repo %q, last build %q), leaving unseeded",
				dbPkg.March, dbPkg.Pkgbase, dbPkg.RepoVersion, dbPkg.LastVersionBuild)
			continue
		}

		if err := dbPkg.Update().SetMaxVersionBase(maxVersionBase).SetBuildNo(buildNo).Exec(ctx); err != nil {
			return err
		}
		seeded++
	}

	if seeded > 0 {
		log.Infof("[SEED] seeded build numbers for %d packages", seeded)
	}
	return nil
}

// requeueTransient returns rows left mid-flight by the previous run to the queue.
//
// Startup only, and it has to stay that way: it rests on the same one-instance-per-
// workspace assumption sweepBuildDirs documents, which is what makes "status says
// building" unambiguous here and racy anywhere else.
//
// Most interrupted builds recover without this, because genQueue keys its
// short-circuit on tag_rev rather than status. Two cases do not: a UseLatest drift
// build bypasses that check and can sit at building with tag_rev already equal to
// state.git, and the shutdown path in buildQueue is the one build error that neither
// purges nor rewrites status, so nothing clears tag_rev for it. A plain SIGTERM
// restart is enough to hit that.
//
// Clearing tag_rev is the half that matters; repo_version is deliberately left
// alone, because a row interrupted mid-rebuild still has its previous version live
// in the repo and isEligible needs to see it to decide whether to rebuild at all.
// Signing is included only so the state cannot strand; nothing assigns it today.
func requeueTransient(ctx context.Context) error {
	requeued, err := db.DBPackage.Update().Where(
		dbpackage.StatusIn(dbpackage.StatusBuilding, dbpackage.StatusSigning),
	).SetStatus(dbpackage.StatusQueued).ClearTagRev().Save(ctx)
	if err != nil {
		return err
	}

	if requeued > 0 {
		log.Infof("[SEED] requeued %d packages left mid-build by the last run", requeued)
	}
	return nil
}

// raiseBuildNo folds versions a row is known to have published into the
// bookkeeping it already carries. Neither dimension is ever lowered, so the
// result is safe to write back unconditionally; an empty base back means nothing
// was readable and there is nothing to record.
//
// The two are raised independently rather than both taken off whichever version
// ranks highest, because they can disagree: a row that published 1.0-2.1 and then
// built 1.0-1.3 has the higher base in one and the higher counter in the other,
// and picking either version wholesale walks the other back onto a number that
// version already used.
func raiseBuildNo(base string, buildNo int, versions ...string) (maxVersionBase string, maxBuildNo int) {
	maxVersionBase, maxBuildNo = base, buildNo
	for _, version := range versions {
		if version == "" {
			continue
		}

		_, versionBuildNo, err := splitPkgRel(pkgRel(version))
		if err != nil {
			continue
		}

		if versionBase := upstreamVersion(version); maxVersionBase == "" ||
			alpm.VerCmp(versionBase, maxVersionBase) > 0 {
			maxVersionBase = versionBase
		}
		maxBuildNo = max(maxBuildNo, versionBuildNo)
	}

	return maxVersionBase, maxBuildNo
}
