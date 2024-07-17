package main

import (
	"errors"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	paconf "github.com/Morganamilo/go-pacmanconf"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/c2h5oh/datasize"
	"github.com/gobwas/glob"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strconv"
	"strings"
	"time"
)

const (
	pacmanConf     = "/usr/share/devtools/pacman.conf.d/multilib.conf"
	makepkgConf    = "/usr/share/devtools/makepkg.conf.d/x86_64.conf"
	logDir         = "logs"
	pristineChroot = "root"
	buildDir       = "build"
	lastUpdate     = "lastupdate"
	stateDir       = "state"
	chrootDir      = "chroot"
	makepkgDir     = "makepkg"
	waitingDir     = "to_be_moved"
	makepkgLTO     = "makepkg-%s-non-lto.conf"
	makepkg        = "makepkg-%s.conf"
	flagConfig     = "flags.yaml"
)

var (
	reVar                   = regexp.MustCompile(`(?mU)^#?[^\S\r\n]*(\w+)[^\S\r\n]*=[^\S\r\n]*([("])([^)"]*)([)"])[^\S\r\n]*$`)
	reEnvClean              = regexp.MustCompile(`(?m) ([\s\\]+) `)
	rePkgRel                = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile               = regexp.MustCompile(`^(.+)(?:-.+){2}-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	reLdError               = regexp.MustCompile(`(?mi).*collect2: error: ld returned (\d+) exit status.*`)
	reDownloadError         = regexp.MustCompile(`(?m)^error: could not rename .+$`)
	reDownloadError2        = regexp.MustCompile(`(?m)^error: failed retrieving file '.+' from .*: The requested URL returned error: .+$`)
	rePortError             = regexp.MustCompile(`(?m)^OSError: \x5bErrno 98\x5d Address already in use$`)
	reSigError              = regexp.MustCompile(`(?m)^error: .*: signature from .* is invalid$`)
	reRustLTOError          = regexp.MustCompile(`(?m)^error: options \x60-C (.+)\x60 and \x60-C lto\x60 are incompatible$`)
	reReplaceSinglePlus     = regexp.MustCompile(`(?m)([a-zA-Z0-9]+)\+([a-zA-Z]+)`)
	reReplaceRemainingPlus  = regexp.MustCompile(`(?m)\+`)
	reReplaceSpecialChars   = regexp.MustCompile(`(?m)[^a-zA-Z0-9_\-.]`)
	reReplaceUnderscore     = regexp.MustCompile(`(?m)[_\-]{2,}`)
	reReplaceTree           = regexp.MustCompile(`(?m)^tree$`)
	reReplacePacsiftWarning = regexp.MustCompile(`(?m)^warning:.*\n*`)
)

type Conf struct {
	Arch         string
	Repos, March []string
	StateRepo    string `yaml:"state_repo"`
	Basedir      struct {
		Repo, Work, Debug string
	}
	DB struct {
		Driver    string
		ConnectTo string `yaml:"connect_to"`
	} `yaml:"db"`
	Build struct {
		Makej       int
		Checks      bool
		MemoryLimit datasize.ByteSize `yaml:"memory_limit"`
	}
	Logging struct {
		Level string
	}
	Blacklist struct {
		Packages, Repo []string
		LTO            []string `yaml:"lto"`
	}
	Housekeeping struct {
		Interval string
	}
	MaxCloneRetries uint64 `yaml:"max_clone_retries"`
}

type Globs []string

type MultipleStateFilesError struct {
	error
}
type UnableToSatisfyError struct {
	error
}

type StateInfo struct {
	Pkgbase string
	PkgVer  string
	TagVer  string
	TagRev  string
}

func updateLastUpdated() error {
	err := os.WriteFile(filepath.Join(conf.Basedir.Repo, lastUpdate), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644) //nolint:gosec
	if err != nil {
		return err
	}
	return nil
}

func cleanBuildDir(dir, chrootDir string) error {
	if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
		rmCmd := exec.Command("sudo", "rm_chroot.py", dir)
		_, err := rmCmd.CombinedOutput()
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

func pkgList2MaxMem(pkgList []*ProtoPackage) datasize.ByteSize {
	var sum uint64
	for _, pkg := range pkgList {
		if pkg.DBPackage.MaxRss != nil {
			sum += uint64(*pkg.DBPackage.MaxRss)
		}
	}

	// multiply by Kibibyte here, since rusage is in kb
	// https://man.archlinux.org/man/core/man-pages/getrusage.2.en#ru_maxrss
	return datasize.ByteSize(sum) * datasize.KB
}

func stateFileMeta(stateFile string) (repo string, subRepo *string, arch string, err error) {
	nameSplit := strings.Split(filepath.Base(filepath.Dir(stateFile)), "-")
	if len(nameSplit) < 2 {
		err = errors.New("error getting metainfo")
		return
	}

	repo = nameSplit[0]
	if len(nameSplit) == 3 {
		subRepo = &nameSplit[1]
		arch = nameSplit[2]
	} else {
		arch = nameSplit[1]
	}
	return
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
				log.Debugf("[MOVE] found debug package for package %s: %s", forPackage, pkg.Name())
				debugPkgs++

				if _, err := os.Stat(filepath.Join(conf.Basedir.Debug, march, filepath.Base(file))); err == nil {
					log.Warningf("[MOVE] overwrite existing debug infos for %s: %s", forPackage,
						filepath.Join(conf.Basedir.Debug, march, filepath.Base(file)))
				}

				err = Copy(file, filepath.Join(conf.Basedir.Debug, march, filepath.Base(file)))
				if err != nil {
					return err
				}
				_ = os.Remove(file)
				_ = os.Remove(file + ".sig")
				continue
			}

			log.Warningf("[MOVE] deleting package %s: %v", pkg.Name(), err)
			_ = os.Remove(file)
			_ = os.Remove(file + ".sig")
			continue
		}

		rawState, err := os.ReadFile(filepath.Join(conf.Basedir.Work, stateDir, dbPkg.Repository.String()+"-"+conf.Arch, dbPkg.Pkgbase))
		if err != nil {
			log.Warningf("[MOVE] state not found for %s->%s: %v", fullRepo, dbPkg.Pkgbase, err)
			_ = os.Remove(file)
			_ = os.Remove(file + ".sig")
			continue
		}

		state, err := parseState(string(rawState))
		if err != nil {
			log.Warningf("[MOVE] error parsing state file for %s->%s: %v", fullRepo, dbPkg.Pkgbase, err)
			_ = os.Remove(file)
			_ = os.Remove(file + ".sig")
			continue
		}

		err = Copy(file, filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)))
		if err != nil {
			return err
		}
		_ = os.Remove(file)
		err = Copy(file+".sig", filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file)+".sig"))
		if err != nil {
			return err
		}
		_ = os.Remove(file + ".sig")

		toAdd = append(toAdd, &ProtoPackage{
			DBPackage: dbPkg,
			PkgFiles:  []string{filepath.Join(conf.Basedir.Repo, fullRepo, "os", conf.Arch, filepath.Base(file))},
			Version:   pkg.Version(),
			March:     march,
			State:     state,
		})
	}

	if len(toAdd) > 0 {
		log.Infof("[%s] adding %d (%d with debug) packages", fullRepo, len(toAdd), debugPkgs)
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

	pacmanConfig, _, err := paconf.ParseFile(pacmanConf)
	if err != nil {
		return nil, err
	}

	for _, repo := range pacmanConfig.Repos {
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
		cmd := exec.Command("arch-nspawn", "-C", pacmanConf, filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), //nolint:gosec
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
		cmd := exec.Command("mkarchroot", "-C", pacmanConf, "-M", makepkgConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "base-devel", "multilib-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error creating chroot: %w\n%s", err, string(res))
		}

		cmd = exec.Command("sudo", "cp", pacmanConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "etc/pacman.conf"))
		res, err = cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error copying pacman.conf to chroot: %w\n%s", err, string(res))
		}
	default:
		return err
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
			log.Fatalf("error generating makepkg for %s: %v", march, err)
		}

		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan []*ProtoPackage, 1000)
			buildManager.repoPurge[fRepo] = make(chan []*ProtoPackage, 1000)
			go buildManager.repoWorker(fRepo)

			if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch)); os.IsNotExist(err) {
				log.Debugf("creating path %s", filepath.Join(conf.Basedir.Repo, fRepo, "os", conf.Arch))
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

	log.Infof("repos: %s", repos)

	for _, repo := range eRepos {
		log.Infof("removing old repo %s", repo)
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
				return "", errors.New("no match in config found")
			}

			var flags []string
			var orgMatch []string
			for _, match := range varsReg {
				if strings.ToLower(match[1]) == subSec.(string) {
					if subSec.(string) == "ldflags" {
						flags = strings.Split(reEnvClean.ReplaceAllString(match[3], ","), ",")
					} else {
						flags = strings.Split(reEnvClean.ReplaceAllString(match[3], " "), " ")
					}
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
				if strings.Contains(subMap.(string), " ") {
					makepkgConf += fmt.Sprintf("\nexport %s=%q", strings.ToUpper(subSec.(string)), replaceStringsFromMap(subMap.(string), replaceMap))
					continue
				}
				makepkgConf += fmt.Sprintf("\nexport %s=%s", strings.ToUpper(subSec.(string)), replaceStringsFromMap(subMap.(string), replaceMap))
				continue
			}

			log.Debugf("original %s: %v (%d)", subSec, flags, len(flags))
			flags = parseFlagSubSection(subMap, flags, replaceMap)
			log.Debugf("new %s: %v (%d)", subSec, flags, len(flags))

			if subSec.(string) == "ldflags" {
				makepkgConf = strings.ReplaceAll(makepkgConf, orgMatch[0], fmt.Sprintf(`%s=%s%s%s`, orgMatch[1],
					orgMatch[2], strings.Join(flags, ","), orgMatch[4]))
			} else {
				makepkgConf = strings.ReplaceAll(makepkgConf, orgMatch[0], fmt.Sprintf(`%s=%s%s%s`, orgMatch[1],
					orgMatch[2], strings.Join(flags, " "), orgMatch[4]))
			}
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

func parseState(state string) (*StateInfo, error) {
	ss := strings.Split(state, " ")
	if len(ss) != 4 {
		return nil, errors.New("invalid state file")
	}

	return &StateInfo{
		Pkgbase: ss[0],
		PkgVer:  ss[1],
		TagVer:  ss[2],
		TagRev:  strings.Trim(ss[3], "\n"),
	}, nil
}

func ContainsPkg(pkgs []*ProtoPackage, pkg *ProtoPackage, repoSensitive bool) bool {
	for _, tPkg := range pkgs {
		if tPkg.PkgbaseEquals(pkg, repoSensitive) {
			return true
		}
	}

	return false
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
	for _, g := range globs {
		var hits []string
		var hitMap = map[string]bool{}
		for _, match := range matches {
			paths, err := filepath.Glob(match + g)
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				err = filepath.WalkDir(path, func(path string, _ os.DirEntry, err error) error {
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

func MatchGlobList(target string, globs []string) (bool, error) {
	for _, lGlob := range globs {
		tGlob, err := glob.Compile(lGlob)
		if err != nil {
			return false, fmt.Errorf("failed to compile glob %s: %w", lGlob, err)
		}
		if tGlob.Match(target) {
			return true, nil
		}
	}
	return false, nil
}

func Copy(srcPath, dstPath string) (err error) {
	r, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func(r *os.File) {
		_ = r.Close()
	}(r)

	w, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	defer func() {
		if c := w.Close(); err == nil {
			err = c
		}
	}()

	_, err = io.Copy(w, r)
	return err
}
