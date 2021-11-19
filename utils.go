package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
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
	lastUpdate     = "lastupdate"
)

type BuildPackage struct {
	Pkgbase  string
	Pkgbuild string
	Srcinfo  *srcinfo.Srcinfo
	PkgFiles []string
	Repo     dbpackage.Repository
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
	buildProcesses []*os.Process
	buildProcMutex sync.RWMutex
	alpmMutex      sync.RWMutex
}

type Conf struct {
	Arch         string
	Repos, March []string
	Svn2git      map[string]string
	Basedir      struct {
		Repo, Chroot, Makepkg, Upstream string
	}
	Db struct {
		Driver    string
		ConnectTo string `yaml:"connect_to"`
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
		LTO      []string `yaml:"lto"`
	}
}

type Globs []string
type PKGFile string

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

func updateLastUpdated() {
	check(os.WriteFile(filepath.Join(conf.Basedir.Repo, lastUpdate), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644))
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

func statusId2string(s dbpackage.Status) (string, string) {
	switch s {
	case dbpackage.StatusSkipped:
		return "SKIPPED", "table-" + conf.Status.Class.Skipped
	case dbpackage.StatusQueued:
		return "QUEUED", "table-" + conf.Status.Class.Queued
	case dbpackage.StatusLatest:
		return "LATEST", "table-" + conf.Status.Class.Latest
	case dbpackage.StatusFailed:
		return "FAILED", "table-" + conf.Status.Class.Failed
	case dbpackage.StatusSigning:
		return "SIGNING", "table-" + conf.Status.Class.Signing
	case dbpackage.StatusBuilding:
		return "BUILDING", "table-" + conf.Status.Class.Building
	default:
		return "UNKNOWN", "table-" + conf.Status.Class.Unknown
	}
}

func (p *BuildPackage) repoVersion() (string, error) {
	err := p.findPkgFiles()
	if err != nil {
		return "", err
	}

	if len(p.PkgFiles) == 0 {
		return "", fmt.Errorf("not found")
	}

	fNameSplit := strings.Split(p.PkgFiles[0], "-")
	return fNameSplit[len(fNameSplit)-3] + "-" + fNameSplit[len(fNameSplit)-2], nil
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

func (p *BuildPackage) increasePkgRel() error {
	f, err := os.OpenFile(p.Pkgbuild, os.O_RDWR, 0644)
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

	nStr := rePkgRel.ReplaceAllLiteralString(string(fStr), "pkgrel="+p.Srcinfo.Pkgrel+".1")
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

	p.Version += ".1"
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

func (p *BuildPackage) SVN2GITVersion(h *alpm.Handle) (string, error) {
	if p.Pkgbuild == "" && p.Pkgbase == "" {
		return "", fmt.Errorf("invalid arguments")
	}

	// upstream/upstream-core-extra/extra-cmake-modules/repos/extra-any/PKGBUILD
	pkgBuilds, _ := Glob(filepath.Join(conf.Basedir.Upstream, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"))

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
		log.Infof("%s: multiple PKGBUILD found, try resolving from mirror", p.Pkgbase)
		dbs, err := h.SyncDBs()
		if err != nil {
			return "", err
		}

		iPackage, err := dbs.FindSatisfier(p.Pkgbase)
		if err != nil {
			return "", err
		}

	pkgloop:
		for _, pkgbuild := range fPkgbuilds {
			repo := strings.Split(filepath.Base(filepath.Dir(pkgbuild)), "-")[0]
			upstreamA := strings.Split(filepath.Dir(pkgbuild), "/")
			upstream := upstreamA[len(upstreamA)-4]

			switch upstream {
			case "upstream-core-extra":
				if iPackage.DB().Name() == repo && (repo == "extra" || repo == "core") {
					fPkgbuilds = []string{pkgbuild}
					break pkgloop
				}
			case "upstream-community":
				if iPackage.DB().Name() == repo && repo == "community" {
					fPkgbuilds = []string{pkgbuild}
					break pkgloop
				}
			}
		}

		if len(fPkgbuilds) > 1 {
			return "", MultiplePKGBUILDError{fmt.Errorf("%s: multiple PKGBUILD found: %s", p.Pkgbase, fPkgbuilds)}
		}
		log.Infof("%s: resolving successful: MirrorRepo=%s; PKGBUILD chosen: %s", p.Pkgbase, iPackage.DB().Name(), fPkgbuilds[0])
	} else if len(fPkgbuilds) == 0 {
		return "", fmt.Errorf("%s: no matching PKGBUILD found (searched: %s, canidates: %s)", p.Pkgbase, filepath.Join(conf.Basedir.Upstream, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"), pkgBuilds)
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

func isPkgFailed(pkg *BuildPackage, dbPkg *ent.DbPackage) bool {
	if dbPkg.Version == "" {
		return false
	}

	if err := pkg.genSrcinfo(); err != nil {
		return false
	}

	if pkg.Version == "" {
		pkg.Version = constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)
	}

	if alpm.VerCmp(dbPkg.Version, pkg.Version) < 0 {
		return false
	} else {
		return dbPkg.Status == dbpackage.StatusFailed
	}
}

func (p *BuildPackage) genSrcinfo() error {
	if p.Srcinfo != nil {
		return nil
	}

	cmd := exec.Command("sh", "-c", "cd "+filepath.Dir(p.Pkgbuild)+"&&"+"makepkg --printsrcinfo")
	res, err := cmd.Output()
	if err != nil {
		return err
	}

	info, err := srcinfo.Parse(string(res))
	if err != nil {
		return err
	}

	p.Srcinfo = info
	return nil
}

func setupChroot() error {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Chroot, pristineChroot)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Chroot, pristineChroot), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("Unable to update chroot: %v\n%s", err, string(res))
		}
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(conf.Basedir.Chroot, 0755)
		check(err)

		cmd := exec.Command("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Chroot, pristineChroot), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("Unable to create chroot: %v\n%s", err, string(res))
		}
	} else {
		return err
	}
	return nil
}

func (path PKGFile) DBPackage() (*ent.DbPackage, error) {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	pkgname := strings.Join(fNameSplit[:len(fNameSplit)-3], "-")

	dbPkgs, err := db.DbPackage.Query().Where(dbpackage.PackagesNotNil()).All(context.Background())
	if err != nil {
		switch err.(type) {
		case *ent.NotFoundError:
			log.Debugf("Not found in database: %s", pkgname)
			return nil, fmt.Errorf("package not found in DB: %s", pkgname)
		default:
			return nil, err
		}
	} else if len(dbPkgs) == 0 {
		return nil, fmt.Errorf("package not found in DB: %s", pkgname)
	} else {
		for _, dbPkg := range dbPkgs {
			if contains(dbPkg.Packages, pkgname) {
				return dbPkg, nil
			}
		}
	}

	return nil, fmt.Errorf("package not found in DB: %s", pkgname)
}

func (path PKGFile) isSignatureValid() (bool, error) {
	cmd := exec.Command("gpg", "--verify", string(path)+".sig")
	res, err := cmd.CombinedOutput()
	log.Debug(string(res))
	if cmd.ProcessState.ExitCode() == 2 || cmd.ProcessState.ExitCode() == 1 {
		return false, nil
	} else if cmd.ProcessState.ExitCode() == 0 {
		return true, nil
	} else if err != nil {
		return false, err
	}

	return false, nil
}

func housekeeping(repo string, wg *sync.WaitGroup) error {
	defer wg.Done()
	log.Debugf("[%s] Start housekeeping", repo)
	packages, err := Glob(filepath.Join(conf.Basedir.Repo, repo, "/**/*.pkg.tar.zst"))
	if err != nil {
		return err
	}

	for _, path := range packages {
		pkgfile := PKGFile(path)
		dbPkg, err := pkgfile.DBPackage()
		if err != nil {
			log.Warningf("[HK/%s] Unable to find entry for %s in db: %v", repo, filepath.Base(path), err)
			// TODO: remove orphan file not tracked by db (WTF kmod-debug!)
			continue
		}

		pkg := &BuildPackage{
			Pkgbase:  dbPkg.Pkgbase,
			Repo:     dbPkg.Repository,
			FullRepo: dbPkg.Repository.String() + "-" + dbPkg.March,
		}

		var upstream string
		switch dbPkg.Repository {
		case dbpackage.RepositoryCore, dbpackage.RepositoryExtra:
			upstream = "upstream-core-extra"
		case dbpackage.RepositoryCommunity:
			upstream = "upstream-community"
		}

		pkg.Pkgbuild = filepath.Join(conf.Basedir.Upstream, upstream, dbPkg.Pkgbase, "repos", dbPkg.Repository.String()+"-"+conf.Arch, "PKGBUILD")
		if err = pkg.genSrcinfo(); err != nil {
			log.Warningf("[HK/%s/%s] failed to gen sourceinfo: %v", repo, pkg.Pkgbase, err)
			continue
		}

		// check if pkg signature is valid
		valid, err := pkgfile.isSignatureValid()
		if err != nil {
			return err
		}
		if !valid {
			log.Infof("[HK/%s/%s] invalid package signature", pkg.FullRepo, pkg.Pkgbase)
			buildManager.repoPurge[pkg.FullRepo] <- pkg
			continue
		}

		// compare db-version with repo version
		repoVer, err := pkg.repoVersion()
		if err != nil {
			log.Infof("[HK/%s/%s] package not present on disk", pkg.FullRepo, pkg.Pkgbase)
			// error means package was not found -> delete version & hash from db so rebuild can happen
			err := dbPkg.Update().ClearHash().ClearRepoVersion().Exec(context.Background())
			if err != nil {
				return err
			}
		} else if alpm.VerCmp(repoVer, dbPkg.RepoVersion) != 0 {
			log.Infof("[HK/%s/%s] update %s->%s in db", pkg.FullRepo, pkg.Pkgbase, dbPkg.RepoVersion, repoVer)
			dbPkg, err = dbPkg.Update().SetRepoVersion(repoVer).Save(context.Background())
			if err != nil {
				return err
			}
		}

		// TODO: check split packages

		// check if package is still part of repo
		dbs, err := alpmHandle.SyncDBs()
		if err != nil {
			return err
		}
		pkgResolved, err := dbs.FindSatisfier(pkg.Srcinfo.Packages[0].Pkgname)
		if err != nil || pkgResolved.DB().Name() != dbPkg.Repository.String() {
			// package not found on mirror/db -> not part of any repo anymore
			log.Infof("[HK/%s/%s] not part of repo", pkg.FullRepo, pkg.Pkgbase)
			buildManager.repoPurge[pkg.FullRepo] <- pkg
			err = db.DbPackage.DeleteOne(dbPkg).Exec(context.Background())
			if err != nil {
				return err
			}
			continue
		}
	}

	return nil
}

func (p *BuildPackage) findPkgFiles() error {
	pkgs, err := os.ReadDir(filepath.Join(conf.Basedir.Repo, p.FullRepo, "os", conf.Arch))
	if err != nil {
		return err
	}

	var realPkgs []string
	for _, realPkg := range p.Srcinfo.Packages {
		realPkgs = append(realPkgs, realPkg.Pkgname)
	}

	var fPkg []string
	for _, file := range pkgs {
		if !file.IsDir() && !strings.HasSuffix(file.Name(), ".sig") {
			matches := rePkgFile.FindStringSubmatch(file.Name())

			if len(matches) > 1 && contains(realPkgs, matches[1]) {
				fPkg = append(fPkg, filepath.Join(conf.Basedir.Repo, p.FullRepo, "os", conf.Arch, file.Name()))
			}
		}
	}

	p.PkgFiles = fPkg
	return nil
}

func (p *BuildPackage) toDbPackage(create bool) *ent.DbPackage {
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.Pkgbase(p.Pkgbase)).Only(context.Background())
	if err != nil && create {
		dbPkg = db.DbPackage.Create().SetPkgbase(p.Pkgbase).SetMarch(p.March).SetPackages(packages2slice(p.Srcinfo.Packages)).SetRepository(p.Repo).SaveX(context.Background())
	}

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
		err := setupMakepkg(march)
		if err != nil {
			log.Errorf("Can't generate makepkg for %s: %v", march, err)
		}
		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan *BuildPackage, conf.Build.Worker)
			buildManager.repoPurge[fRepo] = make(chan *BuildPackage, 10000)
			go buildManager.repoWorker(fRepo)

			if _, err := os.Stat(filepath.Join(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))); os.IsNotExist(err) {
				log.Debugf("Creating path %s", filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))
				check(os.MkdirAll(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch), 0755))
			}

			if i := find(eRepos, fRepo); i != -1 {
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
func setupMakepkg(march string) error {
	lMakepkg := filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf("makepkg-%s.conf", march))
	lMakepkgLTO := filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf("makepkg-%s-lto.conf", march))

	err := os.MkdirAll(conf.Basedir.Makepkg, 0755)
	if err != nil {
		return err
	}
	t, err := os.ReadFile(makepkgConf)
	if err != nil {
		return err
	}
	makepkgStr := string(t)

	makepkgStr = strings.ReplaceAll(makepkgStr, "-mtune=generic", "")
	makepkgStr = strings.ReplaceAll(makepkgStr, " check ", " !check ")
	makepkgStr = strings.ReplaceAll(makepkgStr, " color ", " !color ")
	makepkgStr = strings.ReplaceAll(makepkgStr, "-O2", "-O3")
	makepkgStr = strings.ReplaceAll(makepkgStr, "#MAKEFLAGS=\"-j2\"", "MAKEFLAGS=\"-j"+strconv.Itoa(conf.Build.Makej)+"\"")
	makepkgStr = reMarch.ReplaceAllString(makepkgStr, "${1}"+march)

	// write non-lto makepkg
	err = os.WriteFile(lMakepkg, []byte(makepkgStr), 0644)
	if err != nil {
		return err
	}

	// Add LTO. Since (lto) not in devtools yet, add it instead.
	// See https://git.harting.dev/anonfunc/ALHP.GO/issues/52 for more
	makepkgStr = strings.ReplaceAll(makepkgStr, "!lto", "")
	makepkgStr = strings.ReplaceAll(makepkgStr, "!debug", "!debug lto")
	// Add align-functions=32, see https://github.com/InBetweenNames/gentooLTO/issues/164 for more
	makepkgStr = strings.ReplaceAll(makepkgStr, "-O3", "-O3 -falign-functions=32")

	// write lto makepkg
	err = os.WriteFile(lMakepkgLTO, []byte(makepkgStr), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (p *BuildPackage) isMirrorLatest(h *alpm.Handle) (bool, alpm.IPackage, string, error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false, nil, "", err
	}

	allDepends := p.Srcinfo.Depends
	allDepends = append(allDepends, p.Srcinfo.MakeDepends...)

	for _, dep := range allDepends {
		buildManager.alpmMutex.Lock()
		pkg, err := dbs.FindSatisfier(dep.Value)
		buildManager.alpmMutex.Unlock()
		if err != nil {
			return false, nil, "", UnableToSatisfyError{err}
		}

		svn2gitVer, err := (&BuildPackage{
			Pkgbase: pkg.Base(),
		}).SVN2GITVersion(h)
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
