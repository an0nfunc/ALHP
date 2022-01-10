package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	paconf "github.com/Morganamilo/go-pacmanconf"
	"github.com/Morganamilo/go-srcinfo"
	log "github.com/sirupsen/logrus"
	"io"
	"io/fs"
	"lukechampine.com/blake3"
	"net/http"
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

type BuildPackage struct {
	Pkgbase   string
	Pkgbuild  string
	Srcinfo   *srcinfo.Srcinfo
	PkgFiles  []string
	Repo      dbpackage.Repository
	March     string
	FullRepo  string
	Version   string
	Hash      string
	DbPackage *ent.DbPackage
}

type BuildManager struct {
	build          map[string]chan *BuildPackage
	parse          chan *BuildPackage
	repoPurge      map[string]chan []*BuildPackage
	repoAdd        map[string]chan []*BuildPackage
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
		Repo, Work string
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
type Package string
type PKGBUILD string

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

func (p PKGBUILD) FullRepo() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-2]
}

func (p PKGBUILD) Repo() string {
	return strings.Split(p.FullRepo(), "-")[0]
}

func (p PKGBUILD) PkgBase() string {
	sPkgbuild := strings.Split(string(p), string(filepath.Separator))
	return sPkgbuild[len(sPkgbuild)-4]
}

func updateLastUpdated() {
	check(os.WriteFile(filepath.Join(conf.Basedir.Repo, lastUpdate), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644))
}

func (path Package) Name() string {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	return strings.Join(fNameSplit[:len(fNameSplit)-3], "-")
}

func (path Package) MArch() string {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return strings.Join(strings.Split(splitPath[len(splitPath)-4], "-")[1:], "-")
}

func (path Package) Repo() dbpackage.Repository {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return dbpackage.Repository(strings.Split(splitPath[len(splitPath)-4], "-")[0])
}

func (path Package) FullRepo() string {
	splitPath := strings.Split(string(path), string(filepath.Separator))
	return splitPath[len(splitPath)-4]
}

func (path Package) Version() string {
	fNameSplit := strings.Split(filepath.Base(string(path)), "-")
	return strings.Join(fNameSplit[len(fNameSplit)-3:len(fNameSplit)-1], "-")
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

func cleanBuildDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		err = os.RemoveAll(dir)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *BuildPackage) setupBuildDir() (string, error) {
	buildDir := filepath.Join(conf.Basedir.Work, buildDir, p.March, p.Pkgbase+"-"+p.Version)

	err := cleanBuildDir(buildDir)
	if err != nil {
		return "", fmt.Errorf("removing old builddir failed: %v", err)
	}

	err = os.MkdirAll(buildDir, 0755)
	if err != nil {
		return "", err
	}

	files, err := filepath.Glob(filepath.Join(filepath.Dir(p.Pkgbuild), "*"))
	if err != nil {
		return "", err
	}

	for _, file := range files {
		_, err = copyFile(file, filepath.Join(buildDir, filepath.Base(file)))
		if err != nil {
			return "", err
		}
	}

	p.Pkgbuild = filepath.Join(buildDir, "PKGBUILD")
	return buildDir, nil
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

func (p *BuildPackage) increasePkgRel(buildNo int) error {
	if p.Srcinfo == nil {
		err := p.genSrcinfo()
		if err != nil {
			return fmt.Errorf("error generating srcinfo: %v", err)
		}
	}

	if p.Version == "" {
		p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
	}

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

	nStr := rePkgRel.ReplaceAllLiteralString(string(fStr), "pkgrel="+p.Srcinfo.Pkgrel+"."+strconv.Itoa(buildNo))
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

	p.Version += "." + strconv.Itoa(buildNo)
	return nil
}

func (p *BuildPackage) prepareKernelPatches() error {
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

	// choose best suited patch based on kernel version
	var curVer string
	for k := range conf.KernelPatches {
		if k == p.Pkgbase {
			curVer = k
			break
		}
		if alpm.VerCmp(p.Srcinfo.Pkgver, k) >= 0 && alpm.VerCmp(k, curVer) >= 0 {
			curVer = k
		}
	}

	newPKGBUILD := string(fStr)
	if conf.KernelPatches[curVer] == "none" {
		return fmt.Errorf("no patch available")
	} else if conf.KernelPatches[curVer] == "skip" {
		log.Debugf("[KP] skipped patching for %s", p.Pkgbase)
	} else {
		log.Debugf("[KP] choose patch %s for kernel %s", curVer, p.Srcinfo.Pkgver)

		// add patch to source-array
		orgSource := rePkgSource.FindStringSubmatch(newPKGBUILD)
		if orgSource == nil || len(orgSource) < 1 {
			return fmt.Errorf("no source=() found")
		}

		sources := strings.Split(orgSource[1], "\n")
		sources = append(sources, fmt.Sprintf("\"%s\"", conf.KernelPatches[curVer]))

		newPKGBUILD = rePkgSource.ReplaceAllLiteralString(newPKGBUILD, fmt.Sprintf("source=(%s)", strings.Join(sources, "\n")))

		// add patch sha256 to sha256sums-array (yes, hardcoded to sha256)
		// TODO: support all sums that makepkg also supports
		// get sum
		resp, err := http.Get(conf.KernelPatches[curVer])
		if err != nil || resp.StatusCode != 200 {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, resp.Body)
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		if err != nil {
			return err
		}

		orgSums := rePkgSum.FindStringSubmatch(newPKGBUILD)
		if orgSums == nil || len(orgSums) < 1 {
			return fmt.Errorf("no sha256sums=() found")
		}

		sums := strings.Split(orgSums[1], "\n")
		sums = append(sums, fmt.Sprintf("'%s'", hex.EncodeToString(h.Sum(nil))))

		newPKGBUILD = rePkgSum.ReplaceAllLiteralString(newPKGBUILD, fmt.Sprintf("sha256sums=(\n%s\n)", strings.Join(sums, "\n")))
	}

	// enable config option
	switch {
	case strings.Contains(p.March, "v4"):
		newPKGBUILD = strings.Replace(newPKGBUILD, "make olddefconfig\n", "echo CONFIG_GENERIC_CPU4=y >> .config\nmake olddefconfig\n", 1)
	case strings.Contains(p.March, "v3"):
		newPKGBUILD = strings.Replace(newPKGBUILD, "make olddefconfig\n", "echo CONFIG_GENERIC_CPU3=y >> .config\nmake olddefconfig\n", 1)
	case strings.Contains(p.March, "v2"):
		newPKGBUILD = strings.Replace(newPKGBUILD, "make olddefconfig\n", "echo CONFIG_GENERIC_CPU2=y >> .config\nmake olddefconfig\n", 1)
	}

	// empty file before writing
	_, err = f.Seek(0, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err != nil {
		return err
	}

	_, err = f.WriteString(newPKGBUILD)
	if err != nil {
		return err
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

	toAdd := make([]*BuildPackage, 0)

	for _, file := range pkgFiles {
		pkg := Package(file)
		dbpkg, err := pkg.DBPackageIsolated(march, dbpackage.Repository(repo))
		if err != nil {
			log.Errorf("[MOVE] Deleting package %s: %v", pkg.Name(), err)
			_ = os.Remove(file)
			_ = os.Remove(file + ".sig")
		}

		err = os.Rename(file, filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)))
		if err != nil {
			return err
		}
		err = os.Rename(file+".sig", filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)+".sig"))
		if err != nil {
			return err
		}

		toAdd = append(toAdd, &BuildPackage{
			DbPackage: dbpkg,
			Pkgbase:   dbpkg.Pkgbase,
			PkgFiles:  []string{filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file))},
			Version:   pkg.Version(),
		})
	}

	log.Infof("[%s] Adding %d packages", fullRepo, len(toAdd))

	buildManager.repoAdd[fullRepo] <- toAdd
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

func (p *BuildPackage) importKeys() error {
	if p.Srcinfo.ValidPGPKeys != nil {
		args := []string{"--keyserver", "keyserver.ubuntu.com", "--recv-keys"}
		args = append(args, p.Srcinfo.ValidPGPKeys...)
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

func (p *BuildPackage) isAvailable(h *alpm.Handle) bool {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false
	}

	buildManager.alpmMutex.Lock()
	var pkg alpm.IPackage
	if p.Srcinfo != nil {
		pkg, err = dbs.FindSatisfier(p.Srcinfo.Packages[0].Pkgname)
	} else {
		pkg, err = dbs.FindSatisfier(p.DbPackage.Packages[0])
	}
	buildManager.alpmMutex.Unlock()
	if err != nil {
		return false
	}

	if pkg.DB().Name() != p.Repo.String() {
		return false
	}

	return true
}

func (p *BuildPackage) SVN2GITVersion(h *alpm.Handle) (string, error) {
	if p.Pkgbuild == "" && p.Pkgbase == "" {
		return "", fmt.Errorf("invalid arguments")
	}

	// upstream/upstream-core-extra/extra-cmake-modules/repos/extra-any/PKGBUILD
	pkgBuilds, _ := Glob(filepath.Join(conf.Basedir.Work, upstreamDir, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"))

	var fPkgbuilds []string
	for _, pkgbuild := range pkgBuilds {
		mPkgbuild := PKGBUILD(pkgbuild)
		if mPkgbuild.FullRepo() == "trunk" || containsSubStr(mPkgbuild.FullRepo(), conf.Blacklist.Repo) {
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

		buildManager.alpmMutex.Lock()
		iPackage, err := dbs.FindSatisfier(p.Pkgbase)
		buildManager.alpmMutex.Unlock()
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
		return "", fmt.Errorf("%s: no matching PKGBUILD found (searched: %s, canidates: %s)", p.Pkgbase, filepath.Join(conf.Basedir.Work, upstreamDir, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"), pkgBuilds)
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
	if pkg.DbPackage.Version == "" {
		return false
	}

	if err := pkg.genSrcinfo(); err != nil {
		return false
	}

	if pkg.Version == "" {
		pkg.Version = constructVersion(pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel, pkg.Srcinfo.Epoch)
	}

	if alpm.VerCmp(pkg.DbPackage.Version, pkg.Version) < 0 {
		return false
	} else {
		return pkg.DbPackage.Status == dbpackage.StatusFailed
	}
}

func (p *BuildPackage) genSrcinfo() error {
	if p.Srcinfo != nil {
		return nil
	}

	cmd := exec.Command("sh", "-c", "cd "+filepath.Dir(p.Pkgbuild)+"&&"+"makepkg --printsrcinfo -p "+filepath.Base(p.Pkgbuild))
	res, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("makepkg exit non-zero (PKGBUILD: %s): %v (%s)", p.Pkgbuild, err, string(res))
	}

	info, err := srcinfo.Parse(string(res))
	if err != nil {
		return err
	}

	p.Srcinfo = info
	return nil
}

func setupChroot() error {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("Unable to update chroot: %v\n%s", err, string(res))
		}
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(filepath.Join(conf.Basedir.Work, chrootDir), 0755)
		check(err)

		cmd := exec.Command("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "base-devel")
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

func (path *Package) DBPackage() (*ent.DbPackage, error) {
	return path.DBPackageIsolated(path.MArch(), path.Repo())
}

func (path *Package) DBPackageIsolated(march string, repo dbpackage.Repository) (*ent.DbPackage, error) {
	dbPkg, err := db.DbPackage.Query().Where(func(s *sql.Selector) {
		s.Where(
			sql.And(
				sqljson.ValueContains(dbpackage.FieldPackages, path.Name()),
				sql.EQ(dbpackage.FieldMarch, march),
				sql.EQ(dbpackage.FieldRepository, repo)),
		)
	}).Only(context.Background())
	if err != nil {
		switch err.(type) {
		case *ent.NotFoundError:
			log.Debugf("Not found in database: %s", path.Name())
			return nil, fmt.Errorf("package not found in DB: %s", path.Name())
		default:
			return nil, err
		}
	}
	return dbPkg, nil
}

func (path Package) hasValidSignature() (bool, error) {
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
		mPackage := Package(path)

		dbPkg, err := mPackage.DBPackage()
		if err != nil {
			log.Infof("[HK/%s] removing orphan %s", repo, filepath.Base(path))
			pkg := &BuildPackage{
				FullRepo: mPackage.FullRepo(),
				PkgFiles: []string{path},
				March:    mPackage.MArch(),
			}
			buildManager.repoPurge[pkg.FullRepo] <- []*BuildPackage{pkg}
			continue
		}

		pkg := &BuildPackage{
			Pkgbase:   dbPkg.Pkgbase,
			Repo:      mPackage.Repo(),
			FullRepo:  mPackage.FullRepo(),
			DbPackage: dbPkg,
			March:     mPackage.MArch(),
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
		if err != nil || pkgResolved.DB().Name() != pkg.DbPackage.Repository.String() || pkgResolved.DB().Name() != pkg.Repo.String() {
			// package not found on mirror/db -> not part of any repo anymore
			log.Infof("[HK/%s/%s] not included in repo", pkg.FullRepo, pkg.Pkgbase)
			buildManager.repoPurge[pkg.FullRepo] <- []*BuildPackage{pkg}
			err = db.DbPackage.DeleteOne(pkg.DbPackage).Exec(context.Background())
			if err != nil {
				return err
			}
			continue
		}

		// check if pkg signature is valid
		valid, err := mPackage.hasValidSignature()
		if err != nil {
			return err
		}
		if !valid {
			log.Infof("[HK/%s/%s] invalid package signature", pkg.FullRepo, pkg.Pkgbase)
			buildManager.repoPurge[pkg.FullRepo] <- []*BuildPackage{pkg}
			continue
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

		// TODO: check split packages
	}

	// check all dbpackages for existence
	dbpackages, err := db.DbPackage.Query().All(context.Background())
	if err != nil {
		return err
	}

	for _, dbpkg := range dbpackages {
		pkg := &BuildPackage{
			Pkgbase:   dbpkg.Pkgbase,
			Repo:      dbpkg.Repository,
			March:     dbpkg.March,
			FullRepo:  dbpkg.Repository.String() + "-" + dbpkg.March,
			DbPackage: dbpkg,
		}

		if !pkg.isAvailable(alpmHandle) {
			log.Infof("[HK/%s/%s] not found on mirror, removing", pkg.FullRepo, pkg.Pkgbase)
			err = db.DbPackage.DeleteOne(dbpkg).Exec(context.Background())
			if err != nil {
				return err
			}
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
	for _, realPkg := range p.DbPackage.Packages {
		realPkgs = append(realPkgs, realPkg)
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

func (p *BuildPackage) toDbPackage(create bool) {
	if p.DbPackage != nil {
		return
	}

	dbPkg, err := db.DbPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March), dbpackage.RepositoryEQ(p.Repo))).Only(context.Background())
	if err != nil && create {
		dbPkg = db.DbPackage.Create().SetPkgbase(p.Pkgbase).SetMarch(p.March).SetPackages(packages2slice(p.Srcinfo.Packages)).SetRepository(p.Repo).SaveX(context.Background())
	}

	p.DbPackage = dbPkg
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
			log.Fatalf("Can't generate makepkg for %s: %v", march, err)
		}

		buildManager.build[march] = make(chan *BuildPackage, 10000)
		for i := 0; i < conf.Build.Worker; i++ {
			go buildManager.buildWorker(i, march)
		}

		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan []*BuildPackage, conf.Build.Worker)
			buildManager.repoPurge[fRepo] = make(chan []*BuildPackage, 10000)
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
