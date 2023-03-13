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
)

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
		repoPurge:    make(map[string]chan []*ProtoPackage),
		repoAdd:      make(map[string]chan []*ProtoPackage),
		queueSignal:  make(chan struct{}),
		alpmMutex:    new(sync.RWMutex),
		building:     []*ProtoPackage{},
		buildingLock: new(sync.RWMutex),
		repoWG:       new(sync.WaitGroup),
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
