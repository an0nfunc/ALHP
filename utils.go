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
	"io"
	"io/fs"
	"lukechampine.com/blake3"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
)

var (
	reMarch         = regexp.MustCompile(`(-march=)(.+?) `)
	rePkgRel        = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgSource     = regexp.MustCompile(`(?msU)^source.*=.*\((.+)\)$`)
	rePkgSum        = regexp.MustCompile(`(?msU)^sha256sums.*=.*\((.+)\)$`)
	rePkgFile       = regexp.MustCompile(`^(.+)(?:-.+){2}-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	reLdError       = regexp.MustCompile(`(?mi).*collect2: error: ld returned (\d+) exit status.*`)
	reDownloadError = regexp.MustCompile(`(?m)^error: could not rename .+$`)
	rePortError     = regexp.MustCompile(`(?m)^OSError: \[Errno 98] Address already in use$`)
	reSigError      = regexp.MustCompile(`(?m)^error: .*: signature from .* is invalid$`)
)

type BuildManager struct {
	build          map[string]chan *ProtoPackage
	parse          chan *ProtoPackage
	repoPurge      map[string]chan []*ProtoPackage
	repoAdd        map[string]chan []*ProtoPackage
	exit           bool
	buildWG        sync.WaitGroup
	parseWG        sync.WaitGroup
	repoWG         sync.WaitGroup
	buildProcesses []*os.Process
	buildProcMutex sync.RWMutex
	alpmMutex      sync.RWMutex
}

type Conf struct {
	Arch         string
	Repos, March []string
	Svn2git      map[string]string
	Basedir      struct {
		Repo, Work, Debug string
	}
	Db struct {
		Driver    string
		ConnectTo string `yaml:"connect_to"`
	}
	Build struct {
		Worker int
		Makej  int
		Checks bool
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
	err := os.WriteFile(filepath.Join(conf.Basedir.Repo, lastUpdate), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644)
	if err != nil {
		return err
	}
	return nil
}

func statusId2string(s dbpackage.Status) string {
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
	case dbpackage.StatusBuilding:
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

	hash := blake3.New(32, nil)
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

func cleanBuildDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		err = os.RemoveAll(dir)
		if err != nil {
			return err
		}
	}

	return nil
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

	for _, file := range pkgFiles {
		pkg := Package(file)
		dbPkg, err := pkg.DBPackageIsolated(march, dbpackage.Repository(repo), db)
		if err != nil {
			if strings.HasSuffix(pkg.Name(), "-debug") {
				mkErr := os.MkdirAll(filepath.Join(conf.Basedir.Debug, march), 0755)
				if mkErr != nil {
					return fmt.Errorf("unable to create folder for debug-packages: %w", mkErr)
				}
				forPackage := strings.TrimSuffix(pkg.Name(), "-debug")
				log.Infof("[MOVE] Found debug package for package %s: %s", forPackage, pkg.Name())

				if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, march, filepath.Base(file))); err == nil {
					log.Warningf("[MOVE] Existing debug infos for %s, skipping: %s", forPackage, filepath.Join(conf.Basedir.Debug, march, filepath.Base(file)))
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
			DbPackage: dbPkg,
			Pkgbase:   dbPkg.Pkgbase,
			PkgFiles:  []string{filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file))},
			Version:   pkg.Version(),
			March:     march,
		})
	}

	if len(toAdd) > 0 {
		log.Infof("[%s] Adding %d packages", fullRepo, len(toAdd))
		buildManager.repoAdd[fullRepo] <- toAdd
	}
	return nil
}

func packages2slice(pkgs interface{}) []string {
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

func constructVersion(pkgver string, pkgrel string, epoch string) string {
	if epoch == "" {
		return pkgver + "-" + pkgrel
	}
	return epoch + ":" + pkgver + "-" + pkgrel
}

func initALPM(root string, dbpath string) (*alpm.Handle, error) {
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
	if _, err := os.Stat(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("Unable to update chroot: %w\n%s", err, string(res))
		}
	} else if os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Join(conf.Basedir.Work, chrootDir), 0755)
		if err != nil {
			return err
		}

		cmd := exec.Command("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("Unable to create chroot: %w\n%s", err, string(res))
		}
	} else {
		return err
	}
	return nil
}

func housekeeping(repo string, march string, wg *sync.WaitGroup) error {
	defer wg.Done()
	fullRepo := repo + "-" + march
	log.Debugf("[%s] Start housekeeping", fullRepo)
	packages, err := Glob(filepath.Join(conf.Basedir.Repo, fullRepo, "/**/*.pkg.tar.zst"))
	if err != nil {
		return err
	}

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
			log.Warningf("[HK] Problem fetching package from db for %s: %v", path, err)
			continue
		}

		pkg := &ProtoPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      mPackage.Repo(),
			FullRepo:  mPackage.FullRepo(),
			DbPackage: dbPkg,
			March:     mPackage.MArch(),
			Arch:      mPackage.Arch(),
		}

		var upstream string
		switch pkg.DbPackage.Repository {
		case dbpackage.RepositoryCore, dbpackage.RepositoryExtra:
			upstream = "upstream-core-extra"
		case dbpackage.RepositoryCommunity:
			upstream = "upstream-community"
		}
		pkg.Pkgbuild = filepath.Join(conf.Basedir.Work, upstreamDir, upstream, dbPkg.Pkgbase, "repos", pkg.DbPackage.Repository.String()+"-"+conf.Arch, "PKGBUILD")

		// check if package is still part of repo
		dbs, err := alpmHandle.SyncDBs()
		if err != nil {
			return err
		}
		buildManager.alpmMutex.Lock()
		pkgResolved, err := dbs.FindSatisfier(dbPkg.Packages[0])
		buildManager.alpmMutex.Unlock()
		if err != nil || pkgResolved.DB().Name() != pkg.DbPackage.Repository.String() || pkgResolved.DB().Name() != pkg.Repo.String() || pkgResolved.Architecture() != pkg.Arch {
			// package not found on mirror/db -> not part of any repo anymore
			log.Infof("[HK/%s/%s] not included in repo", pkg.FullRepo, pkg.Pkgbase)
			buildManager.repoPurge[pkg.FullRepo] <- []*ProtoPackage{pkg}
			err = db.DbPackage.DeleteOne(pkg.DbPackage).Exec(context.Background())
			if err != nil {
				return err
			}
			continue
		}

		if pkg.DbPackage.LastVerified.Before(pkg.DbPackage.BuildTimeStart) {
			err := pkg.DbPackage.Update().SetLastVerified(time.Now().UTC()).Exec(context.Background())
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
			pkg.DbPackage, err = pkg.DbPackage.Update().SetRepoVersion(repoVer).ClearHash().Save(context.Background())
			if err != nil {
				return err
			}
		}
	}

	// check all packages from db for existence
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
			DbPackage: dbPkg,
		}

		if !pkg.isAvailable(alpmHandle) {
			log.Infof("[HK/%s/%s] not found on mirror, removing", pkg.FullRepo, pkg.Pkgbase)
			err = db.DbPackage.DeleteOne(dbPkg).Exec(context.Background())
			if err != nil {
				log.Errorf("[HK] Error deleting package %s: %v", dbPkg.Pkgbase, err)
			}
			continue
		}

		if dbPkg.Status == dbpackage.StatusLatest && dbPkg.RepoVersion != "" {
			var existingSplits []string
			var missingSplits []string
			for _, splitPkg := range dbPkg.Packages {
				pkgFile := filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch,
					splitPkg+"-"+dbPkg.RepoVersion+"-"+conf.Arch+".pkg.tar.zst")
				if _, err := os.Stat(pkgFile); os.IsNotExist(err) {
					missingSplits = append(missingSplits, splitPkg)
				} else if err != nil {
					log.Warningf("[HK] error reading package-file %s: %v", splitPkg, err)
				} else {
					existingSplits = append(existingSplits, pkgFile)
				}
			}

			if len(missingSplits) > 0 {
				log.Infof("[HK] missing split-package(s) %s for pkgbase %s", missingSplits, dbPkg.Pkgbase)
				pkg.DbPackage, err = pkg.DbPackage.Update().ClearRepoVersion().ClearHash().SetStatus(dbpackage.StatusQueued).Save(context.Background())
				if err != nil {
					return err
				}

				pkg := &ProtoPackage{
					FullRepo:  fullRepo,
					PkgFiles:  existingSplits,
					March:     march,
					DbPackage: dbPkg,
				}
				buildManager.repoPurge[fullRepo] <- []*ProtoPackage{pkg}
			}
		}
	}

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

		if rePortError.Match(logContent) || reSigError.Match(logContent) || reDownloadError.Match(logContent) {
			rows, err := db.DbPackage.Update().Where(dbpackage.And(dbpackage.Pkgbase(pkg.Pkgbase), dbpackage.March(pkg.March),
				dbpackage.StatusEQ(dbpackage.StatusFailed))).ClearHash().SetStatus(dbpackage.StatusQueued).Save(context.Background())
			if err != nil {
				return err
			}

			if rows > 0 {
				log.Infof("[HK/%s/%s] fixable build-error detected, requeueing package (%d)", pkg.March, pkg.Pkgbase, rows)
			}
		} else if reLdError.Match(logContent) {
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
		if file.Name() != "." && file.Name() != logDir && file.IsDir() {
			eRepos = append(eRepos, file.Name())
		}
	}

	for _, march := range conf.March {
		err := setupMakepkg(march)
		if err != nil {
			log.Fatalf("Can't generate makepkg for %s: %v", march, err)
		}

		buildManager.build[march] = make(chan *ProtoPackage, 10000)
		for i := 0; i < conf.Build.Worker; i++ {
			go buildManager.buildWorker(i, march)
		}

		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan []*ProtoPackage, conf.Build.Worker)
			buildManager.repoPurge[fRepo] = make(chan []*ProtoPackage, 10000)
			go buildManager.repoWorker(fRepo)

			if _, err := os.Stat(filepath.Join(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))); os.IsNotExist(err) {
				log.Debugf("Creating path %s", filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))
				err = os.MkdirAll(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch), 0755)
				if err != nil {
					return err
				}
			}

			if i := find(eRepos, fRepo); i != -1 {
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

//goland:noinspection SpellCheckingInspection
func setupMakepkg(march string) error {
	lMakepkg := filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkg, march))
	lMakepkgLTO := filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkgLTO, march))

	err := os.MkdirAll(filepath.Join(conf.Basedir.Work, makepkgDir), 0755)
	if err != nil {
		return err
	}
	t, err := os.ReadFile(makepkgConf)
	if err != nil {
		return err
	}
	makepkgStr := string(t)

	makepkgStr = strings.ReplaceAll(makepkgStr, "-mtune=generic", "")
	if !conf.Build.Checks {
		makepkgStr = strings.ReplaceAll(makepkgStr, " check ", " !check ")
	}
	makepkgStr = strings.ReplaceAll(makepkgStr, " color ", " !color ")
	// Add align-functions=32, see https://github.com/InBetweenNames/gentooLTO/issues/164 for more
	makepkgStr = strings.ReplaceAll(makepkgStr, "-O2", "-O3 -falign-functions=32")
	makepkgStr = strings.ReplaceAll(makepkgStr, "#MAKEFLAGS=\"-j2\"", "MAKEFLAGS=\"-j"+strconv.Itoa(conf.Build.Makej)+"\"")
	makepkgStr = reMarch.ReplaceAllString(makepkgStr, "${1}"+march)
	makepkgStr = strings.ReplaceAll(makepkgStr, "#PACKAGER=\"John Doe <john@doe.com>\"", "PACKAGER=\"ALHP "+march+" <alhp@harting.dev>\"")

	// write makepkg
	err = os.WriteFile(lMakepkg, []byte(makepkgStr), 0644)
	if err != nil {
		return err
	}

	// Remove LTO. Since lto is enabled pre default in devtools since 20211129-1, remove it.
	// See https://git.harting.dev/anonfunc/ALHP.GO/issues/52 for more
	makepkgStr = strings.ReplaceAll(makepkgStr, "lto", "!lto")
	// Remove align-functions=32, which is enabled because of LTO and not needed without
	makepkgStr = strings.ReplaceAll(makepkgStr, "-falign-functions=32", "")

	// write non-lto makepkg
	err = os.WriteFile(lMakepkgLTO, []byte(makepkgStr), 0644)
	if err != nil {
		return err
	}

	return nil
}

func contains(s interface{}, str string) bool {
	switch v := s.(type) {
	case []string:
		if i := find(v, str); i != -1 {
			return true
		}
	case []srcinfo.ArchString:
		var n []string
		for _, as := range v {
			n = append(n, as.Value)
		}

		if i := find(n, str); i != -1 {
			return true
		}
	default:
		return false
	}

	return false
}

func find(s []string, str string) int {
	for i, v := range s {
		if v == str {
			return i
		}
	}

	return -1
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func(source *os.File) {
		_ = source.Close()
	}(source)

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer func(destination *os.File) {
		_ = destination.Close()
	}(destination)
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
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
