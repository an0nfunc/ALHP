package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"github.com/yargevad/filepathx"
	"gopkg.in/yaml.v2"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
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

var (
	conf         = Conf{}
	repos        []string
	reMarch      = regexp.MustCompile(`(-march=)(.+?) `)
	rePkgRel     = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile    = regexp.MustCompile(`^(.*)-.*-.*-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	buildManager BuildManager
)

type BuildPackage struct {
	Pkgbase  string
	Pkgbuild string
	Srcinfo  *srcinfo.Srcinfo
	PkgFiles []string
	Repo     string
	March    string
	FullRepo string
}

type BuildManager struct {
	toBuild        chan *BuildPackage
	toParse        chan *BuildPackage
	toPurge        chan *BuildPackage
	toRepoAdd      chan *BuildPackage
	exit           bool
	buildWG        sync.WaitGroup
	parseWG        sync.WaitGroup
	failedMutex    sync.RWMutex
	buildProcesses []*os.Process
	buildProcMutex sync.RWMutex
	stats          struct {
		fullyBuild int
		eligible   int
	}
}

type Conf struct {
	Arch                    string
	Repos, March, Blacklist []string
	Svn2git                 map[string]string
	Basedir                 struct {
		Repo, Chroot, Makepkg, Upstream string
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

func contains(s []string, str string) bool {
	if i := find(s, str); i != -1 {
		return true
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
		cmd := backgroundCmd("gpg", args...)
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))

		if err != nil {
			log.Warningf("Unable to import keys: %s", string(res))
		}
	}
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
}

func gitClean(pkg *BuildPackage) {
	cmd := backgroundCmd("sudo", "git_clean.sh", filepath.Dir(pkg.Pkgbuild))
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
		case pkg := <-b.toBuild:
			if b.exit {
				log.Infof("Worker %d exited...", id)
				return
			} else {
				b.buildWG.Add(1)
			}

			start := time.Now()

			log.Infof("[%s/%s] Build starting", pkg.FullRepo, pkg.Pkgbase)

			importKeys(pkg)
			increasePkgRel(pkg)
			pkg.PkgFiles = []string{}

			cmd := backgroundCmd("sh", "-c",
				"cd "+filepath.Dir(pkg.Pkgbuild)+"&&makechrootpkg -c -D "+conf.Basedir.Makepkg+" -l worker-"+strconv.Itoa(id)+" -r "+conf.Basedir.Chroot+" -- "+
					"--config "+filepath.Join(conf.Basedir.Makepkg, fmt.Sprintf("makepkg-%s.conf", pkg.March)))
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			check(cmd.Start())

			b.buildProcMutex.Lock()
			b.buildProcesses = append(b.buildProcesses, cmd.Process)
			b.buildProcMutex.Unlock()

			err := cmd.Wait()

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
				f, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, pkg.FullRepo+"_failed.txt"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, os.ModePerm)
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
				cmd = backgroundCmd("gpg", "--batch", "--detach-sign", file)
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
			b.toRepoAdd <- pkg

			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log")); err == nil {
				check(os.Remove(filepath.Join(conf.Basedir.Repo, "logs", pkg.Pkgbase+".log")))
			}

			gitClean(pkg)
			log.Infof("[%s/%s] Build successful (%s)", pkg.FullRepo, pkg.Pkgbase, time.Now().Sub(start))
		}
	}
}

func (b *BuildManager) parseWorker() {
	for {
		if b.exit {
			return
		}
		select {
		case pkg := <-b.toParse:
			cmd := backgroundCmd("sh", "-c", "cd "+filepath.Dir(pkg.Pkgbuild)+"&&"+"makepkg --printsrcinfo")
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

			if contains(info.Arch, "any") || contains(conf.Blacklist, info.Pkgbase) {
				log.Infof("Skipped %s: blacklisted or any-Package", info.Pkgbase)
				b.toPurge <- pkg
				b.parseWG.Done()
				continue
			}

			if isPkgFailed(pkg) {
				log.Infof("Skipped %s: failed build", info.Pkgbase)
				b.toPurge <- pkg
				b.parseWG.Done()
				continue
			}

			var pkgVer string
			if pkg.Srcinfo.Epoch == "" {
				pkgVer = pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			} else {
				pkgVer = pkg.Srcinfo.Epoch + ":" + pkg.Srcinfo.Pkgver + "-" + pkg.Srcinfo.Pkgrel
			}

			repoVer := getVersionFromRepo(pkg)
			if repoVer != "" && alpm.VerCmp(repoVer, pkgVer) > 0 {
				log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", info.Pkgbase, pkgVer, repoVer)
				b.stats.fullyBuild++
				b.parseWG.Done()
				continue
			}

			b.stats.eligible++
			b.parseWG.Done()
			b.toBuild <- pkg
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

	file, err := os.OpenFile(filepath.Join(conf.Basedir.Repo, pkg.FullRepo+"_failed.txt"), os.O_RDWR|os.O_CREATE, os.ModePerm)
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

func setupChroot() {
	if _, err := os.Stat(filepath.Join(conf.Basedir.Chroot, orgChrootName)); err == nil {
		//goland:noinspection SpellCheckingInspection
		cmd := backgroundCmd("arch-nspawn", filepath.Join(conf.Basedir.Chroot, orgChrootName), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		check(err)
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(conf.Basedir.Chroot, os.ModePerm)
		check(err)

		cmd := backgroundCmd("mkarchroot", "-C", pacmanConf, filepath.Join(conf.Basedir.Chroot, orgChrootName), "base-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		check(err)
	} else {
		check(err)
	}
}

func (b *BuildManager) repoWorker() {
	for {
		select {
		case pkg := <-b.toRepoAdd:
			args := []string{"-s", "-v", "-p", "-n", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"}
			args = append(args, pkg.PkgFiles...)
			cmd := backgroundCmd("repo-add", args...)
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil {
				log.Panicf("%v while repo-add: %s", err, string(res))
			}

			cmd = backgroundCmd("paccache",
				"-rc", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch),
				"-k", "1")
			res, err = cmd.CombinedOutput()
			log.Debug(string(res))
			check(err)
			b.buildWG.Done()
		case pkg := <-b.toPurge:
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

			args := []string{"-s", "-v", filepath.Join(conf.Basedir.Repo, pkg.FullRepo, "os", conf.Arch, pkg.FullRepo) + ".db.tar.xz"}
			args = append(args, realPkgs...)
			cmd := backgroundCmd("repo-remove", args...)
			res, err := cmd.CombinedOutput()
			log.Debug(string(res))
			if err != nil && cmd.ProcessState.ExitCode() == 1 {
				log.Debugf("Deleteing package %s failed: Package not found in database", pkg.Pkgbase)
				continue
			}

			for _, file := range pkg.PkgFiles {
				check(os.Remove(file))
				check(os.Remove(file + ".sig"))
			}
		}
	}
}

func backgroundCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		// Pgid:    0,
	}

	return cmd
}

func (b *BuildManager) syncWorker() {
	check(os.MkdirAll(conf.Basedir.Upstream, os.ModePerm))

	for i := 0; i < conf.Build.Worker; i++ {
		go b.buildWorker(i)
		go b.parseWorker()
	}

	for {
		b.buildWG.Wait()
		for gitDir, gitURL := range conf.Svn2git {
			gitPath := filepath.Join(conf.Basedir.Upstream, gitDir)

			if _, err := os.Stat(gitPath); os.IsNotExist(err) {
				cmd := backgroundCmd("git", "clone", "--depth=1", gitURL, gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)
			} else if err == nil {
				cmd := backgroundCmd("sudo", "git_clean.sh", gitPath)
				res, err := cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)

				cmd = backgroundCmd("sh", "-c", "cd "+gitPath+" && git reset --hard")
				res, err = cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)

				cmd = backgroundCmd("sh", "-c", "cd "+gitPath+" && git pull")
				res, err = cmd.CombinedOutput()
				log.Debug(string(res))
				check(err)
			}
		}

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
				b.toParse <- &BuildPackage{
					Pkgbuild: pkgbuild,
					Pkgbase:  sPkgbuild[len(sPkgbuild)-4],
					Repo:     strings.Split(repo, "-")[0],
					March:    march,
					FullRepo: strings.Split(repo, "-")[0] + "-" + march,
				}
			}
		}

		b.parseWG.Wait()
		log.Infof("Processed source-repos. %d packages elegible to be build, %d already fully build. Covering %f of offical-repo (buildable) packages.", b.stats.eligible, b.stats.fullyBuild, b.stats.fullyBuild/b.stats.eligible)
		b.stats.fullyBuild = 0
		b.stats.eligible = 0
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

	err = os.MkdirAll(conf.Basedir.Repo, os.ModePerm)
	check(err)

	buildManager = BuildManager{
		toBuild:     make(chan *BuildPackage, 10000),
		toParse:     make(chan *BuildPackage, 10000),
		toPurge:     make(chan *BuildPackage, conf.Build.Worker),
		toRepoAdd:   make(chan *BuildPackage, conf.Build.Worker),
		exit:        false,
		buildWG:     sync.WaitGroup{},
		failedMutex: sync.RWMutex{},
	}

	setupChroot()
	syncMarchs()

	go buildManager.repoWorker()
	go buildManager.syncWorker()

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
}
