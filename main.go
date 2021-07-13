package main

import (
	"ALHP.go/ent"
	"ALHP.go/ent/dbpackage"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"github.com/yargevad/filepathx"
	"gopkg.in/yaml.v2"
	"html/template"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
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
	pacmanConf    = "/usr/share/devtools/pacman-extra.conf"
	makepkgConf   = "/usr/share/devtools/makepkg-x86_64.conf"
	logDir        = "logs"
	orgChrootName = "root"
)

const (
	SKIPPED  = iota
	FAILED   = iota
	BUILD    = iota
	QUEUED   = iota
	BUILDING = iota
	LATEST   = iota
)

var (
	conf         = Conf{}
	repos        []string
	reMarch      = regexp.MustCompile(`(-march=)(.+?) `)
	rePkgRel     = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile    = regexp.MustCompile(`^(.*)-.*-.*-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	buildManager BuildManager
	db           *ent.Client
	dbLock       sync.RWMutex
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
}

type Conf struct {
	Arch                    string
	Repos, March, Blacklist []string
	Svn2git                 map[string]string
	Basedir                 struct {
		Repo, Chroot, Makepkg, Upstream, Db string
	}
	Build struct {
		Worker int
		Makej  int
	}
	Logging struct {
		Level string
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
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

func importKeys(pkg *BuildPackage) {
	if pkg.Srcinfo.ValidPGPKeys != nil {
		args := []string{"--keyserver", "keyserver.ubuntu.com", "--recv-keys"}
		args = append(args, pkg.Srcinfo.ValidPGPKeys...)
		cmd := exec.Command("gpg", args...)
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))

		if err != nil {
			log.Warningf("Unable to import keys: %s", string(res))
		}
	}
}

func packages2string(pkgs []srcinfo.Package) []string {
	var sPkgs []string
	for _, p := range pkgs {
		sPkgs = append(sPkgs, p.Pkgname)
	}

	return sPkgs
}

func increasePkgRel(pkg *BuildPackage) {
	f, err := os.OpenFile(pkg.Pkgbuild, os.O_RDWR, os.ModePerm)
	check(err)
	defer func(f *os.File) {
		check(f.Close())
	}(f)

	fStr, err := io.ReadAll(f)
	check(err)

	nStr := rePkgRel.ReplaceAllLiteralString(string(fStr), "pkgrel="+pkg.Srcinfo.Pkgrel+".1")
	_, err = f.Seek(0, 0)
	check(err)
	check(f.Truncate(0))

	_, err = f.WriteString(nStr)
	check(err)

	pkg.Version = pkg.Version + ".1"
}

func gitClean(pkg *BuildPackage) {
	cmd := exec.Command("sudo", "git_clean.sh", filepath.Dir(pkg.Pkgbuild))
	res, err := cmd.CombinedOutput()
	if err != nil {
		log.Warningf("git clean failed with %v:\n%s", err, res)
	} else {
		log.Debug(string(res))
	}
	check(err)
}

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
			dbPkg.Update().SetStatus(BUILDING).SaveX(context.Background())
			dbLock.Unlock()

			importKeys(pkg)
			increasePkgRel(pkg)
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

				if pkg.Srcinfo.Epoch != "" {
					_, err := f.WriteString(fmt.Sprintf("%s==%s:%s-%s\n", pkg.Pkgbase, pkg.Srcinfo.Epoch, pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel))
					check(err)
				} else {
					_, err := f.WriteString(fmt.Sprintf("%s==%s-%s\n", pkg.Pkgbase, pkg.Srcinfo.Pkgver, pkg.Srcinfo.Pkgrel))
					check(err)
				}
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
			dbPkg.Update().SetStatus(BUILD).SetBuildTime(time.Now()).SetBuildDuration(uint64(time.Now().Sub(start).Milliseconds())).SaveX(context.Background())
			dbLock.Unlock()

			log.Infof("[%s/%s] Build successful (%s)", pkg.FullRepo, pkg.Pkgbase, time.Now().Sub(start))
			b.repoAdd[pkg.FullRepo] <- pkg

			gitClean(pkg)
		}
	}
}

func getDbPackage(pkg *BuildPackage) *ent.DbPackage {
	dbLock.Lock()
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.Pkgbase(pkg.Pkgbase)).Only(context.Background())
	if err != nil {
		dbPkg = db.DbPackage.Create().SetPkgbase(pkg.Pkgbase).SetMarch(pkg.March).SetPackages(packages2string(pkg.Srcinfo.Packages)).SetRepository(pkg.Repo).SaveX(context.Background())
	}
	dbLock.Unlock()

	return dbPkg
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
			if pkg.Srcinfo.Epoch == "" {
				pkg.Version = pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			} else {
				pkg.Version = pkg.Srcinfo.Epoch + ":" + pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			}

			dbPkg := getDbPackage(pkg)
			dbLock.Lock()
			dbPkg = dbPkg.Update().SetUpdated(time.Now()).SetVersion(pkg.Version).SaveX(context.Background())
			dbLock.Unlock()

			skipping := false
			if contains(info.Arch, "any") {
				log.Infof("Skipped %s: any-Package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("arch = any").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if contains(conf.Blacklist, info.Pkgbase) {
				log.Infof("Skipped %s: blacklisted package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("blacklisted").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if contains(info.MakeDepends, "ghc") || contains(info.MakeDepends, "haskell-ghc") || contains(info.Depends, "ghc") || contains(info.Depends, "haskell-ghc") {
				// Skip Haskell packages for now, as we are facing linking problems with them,
				// most likely caused by not having a dependency tree implemented yet and building at random.
				// https://git.harting.dev/anonfunc/ALHP.GO/issues/11
				log.Infof("Skipped %s: haskell package", info.Pkgbase)
				dbLock.Lock()
				dbPkg = dbPkg.Update().SetStatus(SKIPPED).SetSkipReason("blacklisted (haskell)").SaveX(context.Background())
				dbLock.Unlock()
				skipping = true
			} else if isPkgFailed(pkg) {
				log.Infof("Skipped %s: failed build", info.Pkgbase)
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

			dbLock.Lock()
			dbPkg = dbPkg.Update().SetStatus(QUEUED).SaveX(context.Background())
			dbLock.Unlock()

			b.parseWG.Done()
			b.build <- pkg
		}
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

func getVersionFromRepo(pkg *BuildPackage) string {
	findPkgFiles(pkg)

	if len(pkg.PkgFiles) == 0 {
		return ""
	}

	fNameSplit := strings.Split(pkg.PkgFiles[0], "-")
	return fNameSplit[len(fNameSplit)-3] + "-" + fNameSplit[len(fNameSplit)-2]
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
	for scanner.Scan() {
		line := scanner.Text()
		splitPkg := strings.Split(line, "==")

		if splitPkg[0] == pkg.Pkgbase {
			var pkgVer string
			if pkg.Srcinfo.Epoch == "" {
				pkgVer = pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			} else {
				pkgVer = pkg.Srcinfo.Epoch + ":" + pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			}

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
	sort.Strings(newContent)

	_, err = file.Seek(0, 0)
	check(err)
	check(file.Truncate(0))
	_, err = file.WriteString(strings.Join(newContent, ""))
	check(err)

	return failed
}

func statusId2string(status int) (string, string) {
	switch status {
	case SKIPPED:
		return "SKIPPED", "table-secondary"
	case QUEUED:
		return "QUEUED", "table-warning"
	case LATEST:
		return "LATEST", "table-primary"
	case FAILED:
		return "FAILED", "table-danger"
	case BUILD:
		return "SIGNING", "table-success"
	case BUILDING:
		return "BUILDING", "table-info"
	default:
		return "UNKNOWN", "table-dark"
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
		March []March
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

					addRepo.Packages = append(addRepo.Packages, addPkg)
				}
				addMarch.Repos = append(addMarch.Repos, addRepo)
			}
			gen.March = append(gen.March, addMarch)
		}

		statusTpl, err := template.ParseFiles("tpl/status.html")
		check(err)

		f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, "status.html"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
		check(statusTpl.Execute(f, gen))
		check(f.Close())

		time.Sleep(time.Minute)
	}
}

func setupChroot() {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Chroot, orgChrootName)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := exec.Command("arch-nspawn", filepath.Join(conf.Basedir.Chroot, orgChrootName), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		check(err)
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(conf.Basedir.Chroot, os.ModePerm)
		check(err)

		cmd := exec.Command("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Chroot, orgChrootName), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		check(err)
	} else {
		check(err)
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
		setupChroot()

		pkgBuilds, err := filepathx.Glob(filepath.Join(conf.Basedir.Upstream, "/**/PKGBUILD"))
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

			if repo == "trunk" || !contains(conf.Repos, strings.Split(repo, "-")[0]) || strings.Contains(repo, "i686") || strings.Contains(repo, "testing") || strings.Contains(repo, "staging") {
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

	db, err = ent.Open("sqlite3", "file:"+conf.Basedir.Db+"?_fk=1&cache=shared")
	if err != nil {
		log.Panicf("Failed to open database %s: %v", conf.Basedir.Db, err)
	}
	defer func(dbSQLite *ent.Client) {
		check(dbSQLite.Close())
	}(db)

	if err := db.Schema.Create(context.Background()); err != nil {
		log.Panicf("Automigrate failed: %v", err)
	}

	err = os.MkdirAll(conf.Basedir.Repo, os.ModePerm)
	check(err)

	buildManager = BuildManager{
		build:     make(chan *BuildPackage, 10000),
		parse:     make(chan *BuildPackage, 10000),
		repoPurge: make(map[string]chan *BuildPackage),
		repoAdd:   make(map[string]chan *BuildPackage),
		exit:      false,
	}

	setupChroot()
	syncMarchs()

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
}
