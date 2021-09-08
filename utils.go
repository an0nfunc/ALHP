package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
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
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	SKIPPED        = iota
	FAILED         = iota
	BUILD          = iota
	QUEUED         = iota
	BUILDING       = iota
	LATEST         = iota
	UNKNOWN        = iota
	pacmanConf     = "/usr/share/devtools/pacman-extra.conf"
	makepkgConf    = "/usr/share/devtools/makepkg-x86_64.conf"
	logDir         = "logs"
	pristineChroot = "root"
)

type BuildPackage struct {
	Pkgbase  string
	Pkgbuild string
	Srcinfo  *srcinfo.Srcinfo
	PkgFiles []string
	Repo     string
	March    string
	FullRepo string
	Version  string
	Hash     string
}

type BuildManager struct {
	build          chan *BuildPackage
	parse          chan *BuildPackage
	repoPurge      map[string]chan *BuildPackage
	repoAdd        map[string]chan *BuildPackage
	exit           bool
	buildWG        sync.WaitGroup
	parseWG        sync.WaitGroup
	repoWG         sync.WaitGroup
	failedMutex    sync.RWMutex
	buildProcesses []*os.Process
	buildProcMutex sync.RWMutex
	alpmMutex      sync.RWMutex
}

type Conf struct {
	Arch         string
	Repos, March []string
	Svn2git      map[string]string
	Basedir      struct {
		Repo, Chroot, Makepkg, Upstream, Db string
	}
	Build struct {
		Worker int
		Makej  int
	}
	Logging struct {
		Level string
	}
	Status struct {
		Class struct {
			Skipped, Queued, Latest, Failed, Signing, Building, Unknown string
		}
	}
	Blacklist struct {
		Packages []string
		Repo     []string
	}
}

type Globs []string

type MultiplePKGBUILDError struct {
	error
}
type UnableToSatisfyError struct {
	error
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func b3sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		check(file.Close())
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

func statusId2string(status int) (string, string) {
	switch status {
	case SKIPPED:
		return "SKIPPED", "table-" + conf.Status.Class.Skipped
	case QUEUED:
		return "QUEUED", "table-" + conf.Status.Class.Queued
	case LATEST:
		return "LATEST", "table-" + conf.Status.Class.Latest
	case FAILED:
		return "FAILED", "table-" + conf.Status.Class.Failed
	case BUILD:
		return "SIGNING", "table-" + conf.Status.Class.Signing
	case BUILDING:
		return "BUILDING", "table-" + conf.Status.Class.Building
	default:
		return "UNKNOWN", "table-" + conf.Status.Class.Unknown
	}
}

func getVersionFromRepo(pkg *BuildPackage) string {
	findPkgFiles(pkg)

	if len(pkg.PkgFiles) == 0 {
		return ""
	}

	fNameSplit := strings.Split(pkg.PkgFiles[0], "-")
	return fNameSplit[len(fNameSplit)-3] + "-" + fNameSplit[len(fNameSplit)-2]
}

func gitClean(pkg *BuildPackage) {
	cmd := exec.Command("sudo", "git_clean.sh", filepath.Dir(pkg.Pkgbuild))
	res, err := cmd.CombinedOutput()
	if err != nil {
		log.Warningf("git clean failed with %v:\n%s", err, res)
	} else {
		log.Debug(string(res))
	}
}

func increasePkgRel(pkg *BuildPackage) error {
	f, err := os.OpenFile(pkg.Pkgbuild, os.O_RDWR, os.ModePerm)
	if err != nil {
		return err
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)

	fStr, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	nStr := rePkgRel.ReplaceAllLiteralString(string(fStr), "pkgrel="+pkg.Srcinfo.Pkgrel+".1")
	_, err = f.Seek(0, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err != nil {
		return err
	}

	_, err = f.WriteString(nStr)
	if err != nil {
		return err
	}

	pkg.Version = pkg.Version + ".1"
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

func importKeys(pkg *BuildPackage) error {
	if pkg.Srcinfo.ValidPGPKeys != nil {
		args := []string{"--keyserver", "keyserver.ubuntu.com", "--recv-keys"}
		args = append(args, pkg.Srcinfo.ValidPGPKeys...)
		cmd := exec.Command("gpg", args...)
		_, err := cmd.CombinedOutput()

		return err
	}
	return nil
}

func constructVersion(pkgver string, pkgrel string, epoch string) string {
	if epoch == "" {
		return pkgver + "-" + pkgrel
	} else {
		return epoch + ":" + pkgver + "-" + pkgrel
	}
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

func getSVN2GITVersion(pkg *BuildPackage) (string, error) {
	if pkg.Pkgbuild == "" && pkg.Pkgbase == "" {
		return "", fmt.Errorf("invalid arguments")
	}

	// upstream/upstream-core-extra/extra-cmake-modules/repos/extra-any/PKGBUILD
	pkgBuilds, _ := Glob(filepath.Join(conf.Basedir.Upstream, "**/"+pkg.Pkgbase+"/repos/*/PKGBUILD"))

	var fPkgbuilds []string
	for _, pkgbuild := range pkgBuilds {
		sPkgbuild := strings.Split(pkgbuild, "/")
		repo := sPkgbuild[len(sPkgbuild)-2]

		if repo == "trunk" || containsSubStr(repo, conf.Blacklist.Repo) {
			continue
		}

		if !contains(fPkgbuilds, pkgbuild) {
			fPkgbuilds = append(fPkgbuilds, pkgbuild)
		}
	}

	if len(fPkgbuilds) > 1 {
		return "", MultiplePKGBUILDError{fmt.Errorf("%s: multiple PKGBUILD found: %s", pkg.Pkgbase, fPkgbuilds)}
	} else if len(fPkgbuilds) == 0 {
		return "", fmt.Errorf("%s: no matching PKGBUILD found (searched: %s, canidates: %s)", pkg.Pkgbase, filepath.Join(conf.Basedir.Upstream, "**/"+pkg.Pkgbase+"/repos/*/PKGBUILD"), pkgBuilds)
	}

	cmd := exec.Command("sh", "-c", "cd "+filepath.Dir(fPkgbuilds[0])+"&&"+"makepkg --printsrcinfo")
	res, err := cmd.Output()
	if err != nil {
		return "", err
	}

	info, err := srcinfo.Parse(string(res))
	if err != nil {
		return "", err
	}

	return constructVersion(info.Pkgver, info.Pkgrel, info.Epoch), nil
}

func isPkgFailed(pkg *BuildPackage) bool {
	buildManager.failedMutex.Lock()
	defer buildManager.failedMutex.Unlock()

	file, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, pkg.FullRepo+"_failed.txt"), os.O_RDWR|os.O_CREATE|os.O_SYNC, os.ModePerm)
	check(err)
	defer func(file *os.File) {
		check(file.Close())
	}(file)

	failed := false
	var newContent []string
	scanner := bufio.NewScanner(file)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		splitPkg := strings.Split(line, "==")

		if splitPkg[0] == pkg.Pkgbase {
			found = true
			pkgVer := constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)

			// try to build new versions of previously failed packages
			if alpm.VerCmp(splitPkg[1], pkgVer) < 0 {
				failed = false
			} else {
				failed = true
				newContent = append(newContent, line+"\n")
			}
		} else {
			newContent = append(newContent, line+"\n")
		}
	}
	check(scanner.Err())

	if found {
		sort.Strings(newContent)

		_, err = file.Seek(0, 0)
		check(err)
		check(file.Truncate(0))
		_, err = file.WriteString(strings.Join(newContent, ""))
		check(err)
	}

	return failed
}

func setupChroot() {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Chroot, pristineChroot)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Chroot, pristineChroot), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			log.Fatalf("[NSPAWN] Unable to update chroot: %v\n%s", err, string(res))
		}
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(conf.Basedir.Chroot, os.ModePerm)
		check(err)

		cmd := exec.Command("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Chroot, pristineChroot), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			log.Fatalf("[MKCHROOT] Unable to create chroot: %v\n%s", err, string(res))
		}
	} else {
		check(err)
	}
}

func findPkgFiles(pkg *BuildPackage) {
	pkgs, err := os.ReadDir(filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch))
	check(err)

	var fPkg []string
	for _, file := range pkgs {
		if !file.IsDir() && !strings.HasSuffix(file.Name(), ".sig") {
			matches := rePkgFile.FindStringSubmatch(file.Name())

			var realPkgs []string
			for _, realPkg := range pkg.Srcinfo.Packages {
				realPkgs = append(realPkgs, realPkg.Pkgname)
			}

			if len(matches) > 1 && contains(realPkgs, matches[1]) {
				fPkg = append(fPkg, filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, file.Name()))
			}
		}
	}

	pkg.PkgFiles = fPkg
}

func getDbPackage(pkg *BuildPackage) *ent.DbPackage {
	dbLock.Lock()
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.Pkgbase(pkg.Pkgbase)).Only(context.Background())
	if err != nil {
		dbPkg = db.DbPackage.Create().SetPkgbase(pkg.Pkgbase).SetMarch(pkg.March).SetPackages(packages2slice(pkg.Srcinfo.Packages)).SetRepository(pkg.Repo).SaveX(context.Background())
	}
	dbLock.Unlock()

	return dbPkg
}

func syncMarchs() {
	files, err := os.ReadDir(conf.Basedir.Repo)
	check(err)

	var eRepos []string
	for _, file := range files {
		if file.Name() != "." && file.Name() != logDir && file.IsDir() {
			eRepos = append(eRepos, file.Name())
		}
	}

	for _, march := range conf.March {
		setupMakepkg(march)
		for _, repo := range conf.Repos {
			tRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, tRepo)
			buildManager.repoAdd[tRepo] = make(chan *BuildPackage, conf.Build.Worker)
			buildManager.repoPurge[tRepo] = make(chan *BuildPackage, 10000)
			go buildManager.repoWorker(tRepo)

			if _, err := os.Stat(filepath.Join(filepath.Join(conf.Basedir.Repo, tRepo, "os", conf.Arch))); os.IsNotExist(err) {
				log.Debugf("Creating path %s", filepath.Join(conf.Basedir.Repo, tRepo, "os", conf.Arch))
				check(os.MkdirAll(filepath.Join(conf.Basedir.Repo, tRepo, "os", conf.Arch), os.ModePerm))
			}

			if i := find(eRepos, tRepo); i != -1 {
				eRepos = append(eRepos[:i], eRepos[i+1:]...)
			}
		}
	}

	log.Infof("Repos: %s", repos)

	for _, repo := range eRepos {
		log.Infof("Removing old repo %s", repo)
		check(os.RemoveAll(filepath.Join(conf.Basedir.Repo, repo)))
	}
}

//goland:noinspection SpellCheckingInspection
func setupMakepkg(march string) {
	lMakepkg := filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf("makepkg-%s.conf", march))

	check(os.MkdirAll(conf.Basedir.Makepkg, os.ModePerm))
	t, err := os.ReadFile(makepkgConf)
	check(err)
	makepkgStr := string(t)

	makepkgStr = strings.ReplaceAll(makepkgStr, "-mtune=generic", "")
	makepkgStr = strings.ReplaceAll(makepkgStr, "-O2", "-O3")
	makepkgStr = strings.ReplaceAll(makepkgStr, " check ", " !check ")
	makepkgStr = strings.ReplaceAll(makepkgStr, " color ", " !color ")
	makepkgStr = strings.ReplaceAll(makepkgStr, "#MAKEFLAGS=\"-j2\"", "MAKEFLAGS=\"-j"+strconv.Itoa(conf.Build.Makej)+"\"")
	makepkgStr = reMarch.ReplaceAllString(makepkgStr, "${1}"+march)

	check(os.WriteFile(lMakepkg, []byte(makepkgStr), os.ModePerm))
}

func isMirrorLatest(h *alpm.Handle, buildPkg *BuildPackage) (bool, alpm.IPackage, string, error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false, nil, "", err
	}

	allDepends := buildPkg.Srcinfo.Depends
	allDepends = append(allDepends, buildPkg.Srcinfo.MakeDepends...)

	for _, dep := range allDepends {
		buildManager.alpmMutex.Lock()
		pkg, err := dbs.FindSatisfier(dep.Value)
		buildManager.alpmMutex.Unlock()
		if err != nil {
			return false, nil, "", UnableToSatisfyError{err}
		}

		svn2gitVer, err := getSVN2GITVersion(&BuildPackage{
			Pkgbase: pkg.Base(),
		})
		if err != nil {
			return false, nil, "", err
		}

		if svn2gitVer != "" && alpm.VerCmp(svn2gitVer, pkg.Version()) > 0 {
			return false, pkg, svn2gitVer, nil
		}
	}

	return true, nil, "", nil
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
		check(source.Close())
	}(source)

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer func(destination *os.File) {
		check(destination.Close())
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
