package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"git.harting.dev/ALHP/ALHP.GO/ent"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	"github.com/Jguer/go-alpm/v2"
	paconf "github.com/Morganamilo/go-pacmanconf"
	"github.com/Morganamilo/go-srcinfo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
	"io"
	"io/fs"
	"lukechampine.com/blake3"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	pacmanConf     = "/usr/share/devtools/pacman-extra.conf"
	makepkgConf    = "/usr/share/devtools/makepkg-x86_64.conf"
	logDir         = "logs"
	pristineChroot = "root"
	buildDir       = "build"
	lastUpdate     = "lastupdate"
	upstreamDir    = "upstream"
	chrootDir      = "chroot"
	makepkgDir     = "makepkg"
	waitingDir     = "to_be_moved"
	makepkgLTO     = "makepkg-%s-non-lto.conf"
	makepkg        = "makepkg-%s.conf"
	flagConfig     = "flags.yaml"
)

var (
	reVar           = regexp.MustCompile(`(?mU)^#?[^\S\r\n]*(\w+)[^\S\r\n]*=[^\S\r\n]*([("])([^)"]+)([)"])[^\S\r\n]*$`)
	reEnvClean      = regexp.MustCompile(`(?m) ([\s\\]+) `)
	rePkgRel        = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgSource     = regexp.MustCompile(`(?msU)^source.*=.*\((.+)\)$`)
	rePkgSum        = regexp.MustCompile(`(?msU)^sha256sums.*=.*\((.+)\)$`)
	rePkgFile       = regexp.MustCompile(`^(.+)(?:-.+){2}-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	reLdError       = regexp.MustCompile(`(?mi).*collect2: error: ld returned (\d+) exit status.*`)
	reDownloadError = regexp.MustCompile(`(?m)^error: could not rename .+$`)
	rePortError     = regexp.MustCompile(`(?m)^OSError: \x5bErrno 98\x5d Address already in use$`)
	reSigError      = regexp.MustCompile(`(?m)^error: .*: signature from .* is invalid$`)
	reRustLTOError  = regexp.MustCompile(`(?m)^error: options \x60-C (.+)\x60 and \x60-C lto\x60 are incompatible$`)
)

type BuildManager struct {
	repoPurge map[string]chan []*ProtoPackage
	repoAdd   map[string]chan []*ProtoPackage
	repoWG    sync.WaitGroup
	alpmMutex sync.RWMutex
	sem       *semaphore.Weighted
}

type Conf struct {
	Arch         string
	Repos, March []string
	Svn2git      map[string]string
	Basedir      struct {
		Repo, Work, Debug string
	}
	DB struct {
		Driver    string
		ConnectTo string `yaml:"connect_to"`
	} `yaml:"db"`
	Build struct {
		Worker             int
		Makej              int
		Checks             bool
		SlowQueueThreshold float64 `yaml:"slow_queue_threshold"`
	}
	Logging struct {
		Level string
	}
	Blacklist struct {
		Packages []string
		Repo     []string
		LTO      []string `yaml:"lto"`
	}
	Housekeeping struct {
		Interval string
	}
	Status struct {
		Class struct {
			Skipped, Queued, Latest, Failed, Signing, Building, Unknown string
		}
	}
	KernelPatches map[string]string `yaml:"kernel_patches"`
	KernelToPatch []string          `yaml:"kernel_to_patch"`
}

type Globs []string

type MultiplePKGBUILDError struct {
	error
}
type UnableToSatisfyError struct {
	error
}

func updateLastUpdated() error {
	err := os.WriteFile(filepath.Join(conf.Basedir.Repo, lastUpdate), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644) //nolint:gosec
	if err != nil {
		return err
	}
	return nil
}

func (b *BuildManager) refreshSRCINFOs(ctx context.Context, path string) error {
	pkgBuilds, err := Glob(path)
	if err != nil {
		return fmt.Errorf("error scanning for PKGBUILDs: %w", err)
	}

	step := int(float32(len(pkgBuilds)) / float32(runtime.NumCPU()))
	cur := 0
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		if i == runtime.NumCPU()-1 {
			step = len(pkgBuilds) - cur
		}

		wg.Add(1)
		go func(pkgBuilds []string) {
			defer wg.Done()
			for _, pkgbuild := range pkgBuilds {
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
					} else if err != nil {
						log.Errorf("[%s/%s] Problem querying db for package: %v", mPkgbuild.Repo(), mPkgbuild.PkgBase(), dbErr)
					}

					// compare b3sum of PKGBUILD file to hash in database, only proceed if hash differs
					// reduces the amount of PKGBUILDs that need to be parsed with makepkg, which is _really_ slow, significantly
					b3s, err := b3sum(pkgbuild)
					if err != nil {
						log.Fatalf("Error hashing PKGBUILD: %v", err)
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
		}(pkgBuilds[cur : cur+step])

		cur += step
	}

	wg.Wait()
	return nil
}

func statusID2string(s dbpackage.Status) string {
	switch s {
	case dbpackage.StatusSkipped:
		return conf.Status.Class.Skipped
	case dbpackage.StatusQueued:
		return conf.Status.Class.Queued
	case dbpackage.StatusLatest:
		return conf.Status.Class.Latest
	case dbpackage.StatusFailed:
		return conf.Status.Class.Failed
	case dbpackage.StatusSigning:
		return conf.Status.Class.Signing
	case dbpackage.StatusBuilding, dbpackage.StatusDelayed:
		return conf.Status.Class.Building
	default:
		return conf.Status.Class.Unknown
	}
}

func b3sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	hash := blake3.New(32, nil) //nolint:gomnd
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func containsSubStr(str string, subList []string) bool {
	for _, checkStr := range subList {
		if strings.Contains(str, checkStr) {
			return true
		}
	}
	return false
}

func cleanBuildDir(dir, chrootDir string) error {
	if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
		err = os.RemoveAll(dir)
		if err != nil {
			return err
		}
	}

	if chrootDir != "" {
		if stat, err := os.Stat(chrootDir); err == nil && stat.IsDir() {
			rmCmd := exec.Command("sudo", "rm_chroot.py", chrootDir)
			_, err := rmCmd.CombinedOutput()
			if err != nil {
				return err
			}
			_ = os.Remove(chrootDir + ".lock")
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("chroot dir was not an directory or failed to stat: %w", err)
		}
	}

	return nil
}

func (b *BuildManager) queue() ([]*ProtoPackage, error) {
	unsortedQueue, err := genQueue()
	if err != nil {
		return nil, fmt.Errorf("error building queue: %w", err)
	}

	sort.Slice(unsortedQueue, func(i, j int) bool {
		return unsortedQueue[i].Priority() < unsortedQueue[j].Priority()
	})

	return unsortedQueue, nil
}

func (b *BuildManager) buildQueue(queue []*ProtoPackage, ctx context.Context) error {
	for _, pkg := range queue {
		if err := b.sem.Acquire(ctx, 1); err != nil {
			return err
		}

		go func(pkg *ProtoPackage) {
			defer b.sem.Release(1)
			dur, err := pkg.build(ctx)
			if err != nil {
				log.Warningf("error building package %s->%s->%s in %s: %s", pkg.March, pkg.Repo, pkg.Pkgbase, dur, err)
				b.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			} else {
				log.Infof("Build successful: %s (%s)", pkg.Pkgbase, dur)
			}
		}(pkg)
	}
	return nil
}

func genQueue() ([]*ProtoPackage, error) {
	pkgs, err := db.DbPackage.Query().Where(dbpackage.Or(dbpackage.StatusEQ(dbpackage.StatusQueued),
		dbpackage.StatusEQ(dbpackage.StatusBuild), dbpackage.StatusEQ(dbpackage.StatusBuilding))).All(context.Background())
	if err != nil {
		return nil, err
	}

	var pkgbuilds []*ProtoPackage
	for _, pkg := range pkgs {
		pkgbuilds = append(pkgbuilds, &ProtoPackage{
			Pkgbase:   pkg.Pkgbase,
			Repo:      pkg.Repository,
			March:     pkg.March,
			FullRepo:  pkg.Repository.String() + "-" + pkg.March,
			Hash:      pkg.Hash,
			DBPackage: pkg,
			Pkgbuild:  pkg.Pkgbuild,
			Version:   pkg.RepoVersion,
		})
	}
	return pkgbuilds, nil
}

func movePackagesLive(fullRepo string) error {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Work, waitingDir, fullRepo)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	march := strings.Join(strings.Split(fullRepo, "-")[1:], "-")
	repo := strings.Split(fullRepo, "-")[0]

	pkgFiles, err := filepath.Glob(filepath.Join(conf.Basedir.Work, waitingDir, fullRepo, "*.pkg.tar.zst"))
	if err != nil {
		return err
	}

	toAdd := make([]*ProtoPackage, 0)
	debugPkgs := 0

	for _, file := range pkgFiles {
		pkg := Package(file)
		dbPkg, err := pkg.DBPackageIsolated(march, dbpackage.Repository(repo), db)
		if err != nil {
			if strings.HasSuffix(pkg.Name(), "-debug") {
				mkErr := os.MkdirAll(filepath.Join(conf.Basedir.Debug, march), 0o755)
				if mkErr != nil {
					return fmt.Errorf("unable to create folder for debug-packages: %w", mkErr)
				}
				forPackage := strings.TrimSuffix(pkg.Name(), "-debug")
				log.Debugf("[MOVE] Found debug package for package %s: %s", forPackage, pkg.Name())
				debugPkgs++

				if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, march, filepath.Base(file))); err == nil {
					log.Warningf("[MOVE] Existing debug infos for %s, skipping: %s", forPackage,
						filepath.Join(conf.Basedir.Debug, march, filepath.Base(file)))
				} else {
					err = os.Rename(file, filepath.Join(conf.Basedir.Debug, march, filepath.Base(file)))
					if err != nil {
						return err
					}
					_ = os.Remove(file + ".sig")
					continue
				}
			}

			log.Warningf("[MOVE] Deleting package %s: %v", pkg.Name(), err)
			_ = os.Remove(file)
			_ = os.Remove(file + ".sig")
			continue
		}

		err = os.Rename(file, filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)))
		if err != nil {
			return err
		}
		err = os.Rename(file+".sig", filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)+".sig"))
		if err != nil {
			return err
		}

		toAdd = append(toAdd, &ProtoPackage{
			DBPackage: dbPkg,
			Pkgbase:   dbPkg.Pkgbase,
			PkgFiles:  []string{filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file))},
			Version:   pkg.Version(),
			March:     march,
		})
	}

	if len(toAdd) > 0 {
		log.Infof("[%s] Adding %d (%d with debug) packages", fullRepo, len(toAdd), debugPkgs)
		buildManager.repoAdd[fullRepo] <- toAdd
	}
	return nil
}

func packages2slice(pkgs any) []string {
	switch v := pkgs.(type) {
	case []srcinfo.Package:
		var sPkgs []string
		for _, p := range v {
			sPkgs = append(sPkgs, p.Pkgname)
		}

		return sPkgs
	case []srcinfo.ArchString:
		var sPkgs []string
		for _, p := range v {
			sPkgs = append(sPkgs, p.Value)
		}

		return sPkgs
	default:
		return []string{}
	}
}

func constructVersion(pkgver, pkgrel, epoch string) string {
	if epoch == "" {
		return pkgver + "-" + pkgrel
	}
	return epoch + ":" + pkgver + "-" + pkgrel
}

func initALPM(root, dbpath string) (*alpm.Handle, error) {
	h, err := alpm.Initialize(root, dbpath)
	if err != nil {
		return nil, err
	}

	PacmanConfig, _, err := paconf.ParseFile(filepath.Join(root, "/etc/pacman.conf"))
	if err != nil {
		return nil, err
	}

	for _, repo := range PacmanConfig.Repos {
		db, err := h.RegisterSyncDB(repo.Name, 0)
		if err != nil {
			return nil, err
		}
		db.SetServers(repo.Servers)

		if len(repo.Usage) == 0 {
			db.SetUsage(alpm.UsageAll)
		}
		for _, usage := range repo.Usage {
			switch usage {
			case "Sync":
				db.SetUsage(alpm.UsageSync)
			case "Search":
				db.SetUsage(alpm.UsageSearch)
			case "Install":
				db.SetUsage(alpm.UsageInstall)
			case "Upgrade":
				db.SetUsage(alpm.UsageUpgrade)
			case "All":
				db.SetUsage(alpm.UsageAll)
			}
		}
	}

	return h, nil
}

func setupChroot() error {
	_, err := os.Stat(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot))
	switch {
	case err == nil:
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), //nolint:gosec
			"pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error updating chroot: %w\n%s", err, string(res))
		}
	case os.IsNotExist(err):
		err = os.MkdirAll(filepath.Join(conf.Basedir.Work, chrootDir), 0o755)
		if err != nil {
			return err
		}
		cmd := exec.Command("mkarchroot", "-C", pacmanConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error creating chroot: %w\n%s", err, string(res))
		}
	default:
		return err
	}
	return nil
}

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
	log.Debugf("[HK/%s] checking existing package-files", fullRepo)
	dbPackages, err := db.DbPackage.Query().Where(
		dbpackage.And(
			dbpackage.RepositoryEQ(dbpackage.Repository(repo)),
			dbpackage.March(march),
		)).All(context.Background())
	if err != nil {
		return err
	}

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
			var existingSplits []string
			var missingSplits []string
			for _, splitPkg := range dbPkg.Packages {
				pkgFile := filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch,
					splitPkg+"-"+dbPkg.RepoVersion+"-"+conf.Arch+".pkg.tar.zst")
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
				dbpackage.And(
					dbpackage.Pkgbase(pkg.Pkgbase),
					dbpackage.March(pkg.March),
					dbpackage.StatusEQ(dbpackage.StatusFailed),
					dbpackage.LtoNotIn(dbpackage.LtoAutoDisabled, dbpackage.LtoDisabled),
				)).ClearHash().SetStatus(dbpackage.StatusQueued).SetLto(dbpackage.LtoAutoDisabled).Save(context.Background())
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

func syncMarchs() error {
	files, err := os.ReadDir(conf.Basedir.Repo)
	if err != nil {
		return err
	}

	var eRepos []string
	for _, file := range files {
		if file.Name() != "." && file.Name() != logDir && file.Name() != makepkgDir && file.IsDir() {
			eRepos = append(eRepos, file.Name())
		}
	}

	flagConfigRaw, err := os.ReadFile(flagConfig)
	if err != nil {
		return err
	}
	var flagCfg map[string]any
	err = yaml.Unmarshal(flagConfigRaw, &flagCfg)
	if err != nil {
		return err
	}

	for _, march := range conf.March {
		err := setupMakepkg(march, flagCfg)
		if err != nil {
			log.Fatalf("Can't generate makepkg for %s: %v", march, err)
		}

		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan []*ProtoPackage, conf.Build.Worker)
			buildManager.repoPurge[fRepo] = make(chan []*ProtoPackage, 10000) //nolint:gomnd
			go buildManager.repoWorker(fRepo)

			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch)); os.IsNotExist(err) {
				log.Debugf("Creating path %s", filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))
				err = os.MkdirAll(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch), 0o755)
				if err != nil {
					return err
				}
			}

			if i := Find(eRepos, fRepo); i != -1 {
				eRepos = append(eRepos[:i], eRepos[i+1:]...)
			}
		}
	}

	log.Infof("Repos: %s", repos)

	for _, repo := range eRepos {
		log.Infof("Removing old repo %s", repo)
		err = os.RemoveAll(filepath.Join(conf.Basedir.Repo, repo))
		if err != nil {
			return err
		}
	}
	return nil
}

func replaceStringsFromMap(str string, replace map[string]string) string {
	for k, v := range replace {
		str = strings.ReplaceAll(str, k, v)
	}

	return str
}

func parseFlagSubSection(list any, res []string, replaceMap map[string]string) []string {
	for _, cEntry := range list.([]any) {
		switch ce := cEntry.(type) {
		case map[any]any:
			for k, v := range ce {
				if v == nil {
					res = append(res[:Find(res, k.(string))], res[Find(res, k.(string))+1:]...)
				} else if s, ok := v.(string); ok {
					Replace(res, k.(string), replaceStringsFromMap(s, replaceMap))
				} else {
					log.Warningf("malformated flag-config: unable to handle %v:%v", replaceStringsFromMap(k.(string), replaceMap), v)
				}
			}
		case string:
			res = append(res, replaceStringsFromMap(ce, replaceMap))
		default:
			log.Warningf("malformated flag-config: unable to handle %v (%T)", cEntry, cEntry)
		}
	}

	return res
}

func parseFlagSection(section any, makepkgConf, march string) (string, error) {
	replaceMap := map[string]string{"$level$": march[len(march)-2:], "$march$": march, "$buildproc$": strconv.Itoa(conf.Build.Makej)}

	if ct, ok := section.(map[any]any); ok {
		for subSec, subMap := range ct {
			varsReg := reVar.FindAllStringSubmatch(makepkgConf, -1)
			if varsReg == nil {
				return "", fmt.Errorf("no match in config found")
			}

			var flags []string
			var orgMatch []string
			for _, match := range varsReg {
				if strings.ToLower(match[1]) == subSec.(string) {
					flags = strings.Split(reEnvClean.ReplaceAllString(match[3], " "), " ")
					orgMatch = match
				}
			}

			if _, ok := subMap.(string); ok && len(orgMatch) > 0 {
				makepkgConf = strings.ReplaceAll(makepkgConf, orgMatch[0], fmt.Sprintf("\n%s=%s%s%s",
					strings.ToUpper(subSec.(string)), orgMatch[2], replaceStringsFromMap(subMap.(string), replaceMap), orgMatch[4]))
				continue
			}

			if len(orgMatch) == 0 {
				// no match found, assume env var and append it
				log.Debugf("no match found for %s:%v, appending", subSec, subMap)
				makepkgConf += fmt.Sprintf("\nexport %s=%s", strings.ToUpper(subSec.(string)), replaceStringsFromMap(subMap.(string), replaceMap))
				continue
			}

			log.Debugf("original %s: %v (%d)", subSec, flags, len(flags))
			flags = parseFlagSubSection(subMap, flags, replaceMap)
			log.Debugf("new %s: %v (%d)", subSec, flags, len(flags))

			makepkgConf = strings.ReplaceAll(makepkgConf, orgMatch[0], fmt.Sprintf(`%s=%s%s%s`, orgMatch[1],
				orgMatch[2], strings.Join(flags, " "), orgMatch[4]))
		}
	}

	return makepkgConf, nil
}

//goland:noinspection SpellCheckingInspection
func setupMakepkg(march string, flags map[string]any) error {
	lMakepkg := filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkg, march))
	lMakepkgLTO := filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkgLTO, march))

	err := os.MkdirAll(filepath.Join(conf.Basedir.Work, makepkgDir), 0o755)
	if err != nil {
		return err
	}
	t, err := os.ReadFile(makepkgConf)
	if err != nil {
		return err
	}
	makepkgStr := string(t)

	makepkgStr, err = parseFlagSection(flags["common"], makepkgStr, march)
	if err != nil {
		return err
	}

	// write non-lto makepkg
	err = os.WriteFile(lMakepkgLTO, []byte(makepkgStr), 0o644) //nolint:gosec
	if err != nil {
		return err
	}

	makepkgStr, err = parseFlagSection(flags["lto"], makepkgStr, march)
	if err != nil {
		return err
	}

	// write makepkg
	err = os.WriteFile(lMakepkg, []byte(makepkgStr), 0o644) //nolint:gosec
	if err != nil {
		return err
	}

	return nil
}

func Contains(s any, str string) bool {
	switch v := s.(type) {
	case []string:
		if i := Find(v, str); i != -1 {
			return true
		}
	case []srcinfo.ArchString:
		var n []string
		for _, as := range v {
			n = append(n, as.Value)
		}

		if i := Find(n, str); i != -1 {
			return true
		}
	default:
		return false
	}

	return false
}

func Find[T comparable](arr []T, match T) int {
	for i, v := range arr {
		if v == match {
			return i
		}
	}

	return -1
}

func Unique[T comparable](arr []T) []T {
	occurred := map[T]bool{}
	var result []T
	for e := range arr {
		if !occurred[arr[e]] {
			occurred[arr[e]] = true
			result = append(result, arr[e])
		}
	}

	return result
}

func Replace[T comparable](arr []T, replace, with T) []T {
	for i, v := range arr {
		if v == replace {
			arr[i] = with
		}
	}

	return arr
}

func Glob(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}
	return Globs(strings.Split(pattern, "**")).Expand()
}

func (globs Globs) Expand() ([]string, error) {
	var matches = []string{""}
	for _, glob := range globs {
		var hits []string
		var hitMap = map[string]bool{}
		for _, match := range matches {
			paths, err := filepath.Glob(match + glob)
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				err = filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return fs.SkipDir
					}
					if _, ok := hitMap[path]; !ok {
						hits = append(hits, path)
						hitMap[path] = true
					}
					return nil
				})
				if err != nil {
					return nil, err
				}
			}
		}
		matches = hits
	}

	if globs == nil && len(matches) > 0 && matches[0] == "" {
		matches = matches[1:]
	}

	return matches, nil
}

func TotalMemory() uint64 {
	sinfo := new(syscall.Sysinfo_t)
	err := syscall.Sysinfo(sinfo)
	if err != nil {
		return 0
	}

	return sinfo.Totalram * uint64(sinfo.Unit)
}
