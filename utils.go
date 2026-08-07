package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	paconf "github.com/Morganamilo/go-pacmanconf"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/c2h5oh/datasize"
	"github.com/gobwas/glob"
	"github.com/prometheus/procfs"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	pacmanConf     = "/usr/share/devtools/pacman.conf.d/multilib.conf"
	makepkgConf    = "/usr/share/devtools/makepkg.conf.d/x86_64.conf"
	makepkgConfExt = "/etc/makepkg.conf.d"
	logDir         = "logs"
	pristineChroot = "root"
	buildDir       = "build"
	lastUpdate     = "lastupdate"
	repoLock       = "repo.lck"
	stateDir       = "state"
	chrootDir      = "chroot"
	makepkgDir     = "makepkg"
	waitingDir     = "to_be_moved"
	makepkgLTO     = "makepkg-%s-non-lto.conf"
	makepkg        = "makepkg-%s.conf"
	flagConfig     = "flags.yaml"
	rmChrootBin    = "/usr/local/bin/rm_chroot.py"
)

var (
	// upstream metadata that ends up in filesystem paths and root-run command
	// arguments; see checkMetaName
	reValidMeta            = regexp.MustCompile(`^[A-Za-z0-9._+:~@-]+$`)
	reVar                  = regexp.MustCompile(`(?mU)^#?[^\S\r\n]*(\w+)[^\S\r\n]*=[^\S\r\n]*([("])([^)"]*)([)"])[^\S\r\n]*$`)
	reEnvClean             = regexp.MustCompile(`(?m) ([\s\\]+) `)
	rePkgRel               = regexp.MustCompile(`(?m)^pkgrel\s*=\s*(.+)$`)
	rePkgFile              = regexp.MustCompile(`^(.+)(?:-.+){2}-(?:x86_64|any)\.pkg\.tar\.zst(?:\.sig)*$`)
	reLdError              = regexp.MustCompile(`(?mi).*collect2: error: ld returned (\d+) exit status.*`)
	reDownloadError        = regexp.MustCompile(`(?m)^error: could not rename .+$`)
	reDownloadError2       = regexp.MustCompile(`(?m)^error: failed retrieving file '.+' from .*: The requested URL returned error: .+$`)
	rePortError            = regexp.MustCompile(`(?m)^OSError: \x5bErrno 98\x5d Address already in use$`)
	reSigError             = regexp.MustCompile(`(?m)^error: .*: signature from .* is invalid$`)
	reRustLTOError         = regexp.MustCompile(`(?m)^error: options \x60-C (.+)\x60 and \x60-C lto\x60 are incompatible$`)
	reReplaceSinglePlus    = regexp.MustCompile(`(?m)([a-zA-Z0-9]+)\+([a-zA-Z]+)`)
	reReplaceRemainingPlus = regexp.MustCompile(`(?m)\+`)
	reReplaceSpecialChars  = regexp.MustCompile(`(?m)[^a-zA-Z0-9_\-.]`)
	reReplaceUnderscore    = regexp.MustCompile(`(?m)[_\-]{2,}`)
	reReplaceTree          = regexp.MustCompile(`(?m)^tree$`)
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
		MemoryLimit datasize.ByteSize `yaml:"memory_limit"`
		// StallTimeout is how long a build may produce neither output nor CPU work
		// before it is killed. time.ParseDuration string, "0" disables.
		StallTimeout string `yaml:"stall_timeout"`
		// Timeout is an absolute wall-clock cap per build, a backstop for hangs that
		// keep burning CPU. time.ParseDuration string, "0" (the default) disables.
		Timeout string `yaml:"timeout"`
		// NetworkIsolation runs each build in its own network namespace via the
		// alhp-netns helper. A pointer because nil must mean enabled: config is
		// unmarshaled into a nil *Conf at startup, where an absent key would leave a
		// plain bool false, but into the existing non-nil one on SIGUSR1 reload,
		// where yaml merges rather than zeroes. The two sites would disagree.
		NetworkIsolation *bool `yaml:"network_isolation"`
	}
	Logging struct {
		Level string
	}
	Blacklist struct {
		Packages, Repo []string
		LTO            []string `yaml:"lto"`
	}
	Housekeeping struct {
		Interval                 string
		SignatureRecheckInterval string `yaml:"signature_recheck_interval"`
	}
	MaxCloneRetries uint64 `yaml:"max_clone_retries"`
	Metrics         struct {
		Port uint32
	}
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

// lockRepoShared keeps the mirror push from snapshotting the repo mid-mutation.
//
// repo-add lands the db and its detached signature as two separate renames and
// unlinks the .db/.db.sig symlinks in between, so an rsync reading across that
// window copies a db and a signature from different generations. The pair then
// fails verification for everyone pulling it, and because nothing vanished rsync
// exits 0, leaving nothing downstream able to detect it.
//
// Held shared on purpose: mutations for different repos touch different db files
// and never conflict with each other, they only need excluding while the mirror
// holds this file exclusively for the few milliseconds it reflink-copies the db
// set aside. A lock that cannot be taken is logged and ignored rather than
// stalling builds, which leaves the pre-existing race as the worst case.
//
// The Flock call is not ctx-interruptible and runs after repoWG.Add, so an
// exclusive holder that never releases would stall shutdown until the unit's
// TimeoutStopSec. That is bounded in practice because the mirror only holds it
// across a local reflink copy, never across its network transfer.
func lockRepoShared() *os.File {
	path := filepath.Join(conf.Basedir.Work, repoLock)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		log.Warningf("unable to open repo lock %s: %v", path, err)
		return nil
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		log.Warningf("unable to lock repo lock %s: %v", path, err)
		_ = f.Close()
		return nil
	}
	return f
}

// unlockRepo releases a lock taken by lockRepoShared. Closing the descriptor drops
// the flock, so a nil file (lock never acquired) is a no-op.
func unlockRepo(f *os.File) {
	if f == nil {
		return
	}
	_ = f.Close()
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
		rmCmd := exec.Command(sudoBin, rmChrootBin, dir)
		_, err := rmCmd.CombinedOutput()
		if err != nil {
			return err
		}
	}

	if chrootDir != "" {
		if stat, err := os.Stat(chrootDir); err == nil && stat.IsDir() {
			rmCmd := exec.Command(sudoBin, rmChrootBin, chrootDir)
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

// pkgList2MaxMem sums the recorded peak RSS of the given builds. Callers must hold
// buildingLock: it reads the maxRSS snapshot taken at admission, not DBPackage,
// which the build goroutines reassign as they run.
func pkgList2MaxMem(pkgList []*ProtoPackage) datasize.ByteSize {
	var sum uint64
	for _, pkg := range pkgList {
		if pkg.maxRSS != nil {
			sum += uint64(*pkg.maxRSS) //nolint:gosec
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

func movePackagesLive(ctx context.Context, fullRepo string) error {
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
		dbPkg, err := pkg.DBPackageIsolated(ctx, march, dbpackage.Repository(repo), db)
		if err != nil {
			if pkg.IsDebug() {
				mkErr := os.MkdirAll(filepath.Join(conf.Basedir.Debug, march), 0o755)
				if mkErr != nil {
					return fmt.Errorf("unable to create folder for debug-packages: %w", mkErr)
				}
				forPackage := strings.TrimSuffix(pkg.Name(), debugSuffix)
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
		sPkgs := make([]string, 0, len(v))
		for i := range v {
			sPkgs = append(sPkgs, v[i].Pkgname)
		}

		return sPkgs
	case []srcinfo.ArchString:
		sPkgs := make([]string, 0, len(v))
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

// driftToMain reports whether a package must be built from the packaging repo's
// main branch instead of the ref state.git pins.
//
// syncVer is what upstream actually publishes, stateVer what state.git records,
// repoVer what we published ourselves (empty when we never built it). Drift is
// state.git lagging upstream, so only syncVer against stateVer decides it:
// comparing against repoVer instead would call every ordinary update drift, since
// we are behind upstream by definition until we build it, and main carries tags
// upstream staged for testing or staging but never released.
//
// repoVer gates the rebuild rather than defining drift. Once we have caught up
// with upstream there is nothing left to chase, which is what stops a stale state
// file from re-triggering a build every cycle.
func driftToMain(syncVer, stateVer, repoVer string) bool {
	if alpm.VerCmp(syncVer, stateVer) <= 0 {
		return false
	}
	return repoVer == "" || alpm.VerCmp(syncVer, repoVer) > 0
}

// aheadOfUpstream reports whether ver is a version no upstream repo carries,
// which is what a build from main looks like when it picked up a tag staged for
// testing or staging.
//
// Being ahead of stateVer alone is a legitimate drift rebuild, and being ahead of
// syncVer alone is just building before the mirror synced. Both together mean
// nothing upstream has this version, and its dependencies may not be installable.
func aheadOfUpstream(ver, stateVer, syncVer string) bool {
	return alpm.VerCmp(ver, stateVer) > 0 && alpm.VerCmp(ver, syncVer) > 0
}

// upstreamVersion strips the build number increasePkgRel appends to pkgrel,
// recovering the upstream version a published artifact was built from.
//
// RepoVersion is the only durable record of what we published, but it carries
// that build number, and "1.0-1.1" outranks its own upstream "1.0-1": fed to
// aheadOfUpstream unstripped it would match every package we ever built.
//
// The build number is always the last dot-separated component of pkgrel, so the
// search is anchored after the last dash; stripping the last dot of the whole
// string would turn a plain "1.2.3-1" into "1.2". When upstream's own pkgrel
// carries a dot, the result lands below the real version rather than above it,
// which misses a purge rather than causing a wrong one.
func upstreamVersion(repoVer string) string {
	dash := strings.LastIndex(repoVer, "-")
	if dash < 0 {
		return repoVer
	}
	pkgrel := repoVer[dash+1:]
	dot := strings.LastIndex(pkgrel, ".")
	if dot < 0 {
		return repoVer
	}
	return repoVer[:dash+1] + pkgrel[:dot]
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

func setupChroot(ctx context.Context) error {
	_, err := os.Stat(filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot))
	switch {
	case err == nil:
		cmd := exec.CommandContext(ctx, "arch-nspawn", "-C", pacmanConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "pacman", "-Syuu", "--noconfirm")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error updating chroot: %w: %s", err, string(res))
		}
	case os.IsNotExist(err):
		err = os.MkdirAll(filepath.Join(conf.Basedir.Work, chrootDir), 0o755)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "mkarchroot", "-C", pacmanConf, "-M", makepkgConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot), "base-devel", "multilib-devel")
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error creating chroot: %w: %s", err, string(res))
		}

		// copy pacman.conf into pristine chroot to enable multilib
		cmd = exec.CommandContext(ctx, sudoBin, "/usr/bin/cp", pacmanConf, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "etc/pacman.conf"))
		res, err = cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error copying pacman.conf to chroot: %w: %s", err, string(res))
		}

		// remove makepkg conf extension, they are covered by our custom makepkg
		cmd = exec.CommandContext(ctx, sudoBin, rmChrootBin, //nolint:gosec
			filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot, "etc/makepkg.conf.d"))
		res, err = cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return fmt.Errorf("error removing makepkg.conf.d from chroot: %w: %s", err, string(res))
		}
	default:
		return err
	}
	return nil
}

func syncMarchs(ctx context.Context) error {
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

	var startWorkers []string
	for _, march := range conf.March {
		err := setupMakepkg(march, flagCfg)
		if err != nil {
			log.Fatalf("error generating makepkg for %s: %v", march, err)
		}

		for _, repo := range conf.Repos {
			fRepo := fmt.Sprintf("%s-%s", repo, march)
			repos = append(repos, fRepo)
			buildManager.repoAdd[fRepo] = make(chan []*ProtoPackage, repoChanBuffer)
			buildManager.repoPurge[fRepo] = make(chan []*ProtoPackage, repoChanBuffer)
			buildManager.repoFix[fRepo] = make(chan repoDBFix, repoChanBuffer)
			// workers are started once every channel exists: repoWorker selects
			// on all three maps, and writing them while one runs races it
			startWorkers = append(startWorkers, fRepo)

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

	for _, fRepo := range startWorkers {
		go buildManager.repoWorker(ctx, fRepo)
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
				log.Debugf("replace %s with %s", orgMatch[0], fmt.Sprintf("\n%s=%s%s%s",
					strings.ToUpper(subSec.(string)), orgMatch[2], replaceStringsFromMap(subMap.(string), replaceMap), orgMatch[4]))
				makepkgConf = strings.ReplaceAll(makepkgConf, orgMatch[0], fmt.Sprintf("\n%s=%s%s%s",
					strings.ToUpper(subSec.(string)), orgMatch[2], replaceStringsFromMap(subMap.(string), replaceMap), orgMatch[4]))
				continue
			}

			if len(orgMatch) == 0 {
				// no match found, assume env var and append it
				log.Debugf("no match found for %s:%v, appending", subSec, subMap)
				switch sm := subMap.(type) {
				case string:
					if strings.Contains(sm, " ") {
						makepkgConf += fmt.Sprintf("\nexport %s=%q", strings.ToUpper(subSec.(string)), replaceStringsFromMap(sm, replaceMap))
						continue
					}
					makepkgConf += fmt.Sprintf("\nexport %s=%s", strings.ToUpper(subSec.(string)), replaceStringsFromMap(sm, replaceMap))
					continue
				case []string:
					makepkgConf += fmt.Sprintf("\nexport %s=%q", strings.ToUpper(subSec.(string)), replaceStringsFromMap(strings.Join(sm, " "), replaceMap)) //nolint:lll
					continue
				}
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
	makepkgStrBuilder := new(strings.Builder)
	makepkgStrBuilder.Write(t)

	// read makepkg conf.d
	makepkgConfExt, err := Glob(filepath.Join(makepkgConfExt, "*.conf"))
	if err != nil {
		return err
	}

	for _, makepkgExt := range makepkgConfExt {
		ext, err := os.ReadFile(makepkgExt)
		if err != nil {
			return err
		}
		makepkgStrBuilder.Write(ext)
	}

	makepkgStr := makepkgStrBuilder.String()

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

// checkMetaName rejects package metadata that must never reach a filesystem path
// or a command argument. Everything here is upstream-controlled: state files come
// from state.git and versions from a .SRCINFO fetched over HTTP, neither of which
// ALHP can vouch for. The build directory is named after these, and that name is
// passed to helpers that run as root, so the character set has to be constrained
// here rather than trusted downstream.
//
// The allowlist is deliberately narrower than makepkg's own lint, which rejects
// only whitespace, "/", ":", "-" and non-ASCII in pkgver.
func checkMetaName(kind, value string) error {
	if value == "" {
		return fmt.Errorf("empty %s: %w", kind, ErrInvalidMeta)
	}
	if !reValidMeta.MatchString(value) {
		return fmt.Errorf("refusing %s %q: contains characters outside [A-Za-z0-9._+:~@-]: %w",
			kind, value, ErrInvalidMeta)
	}
	// "." and ".." would escape or alias the directory they name
	if strings.Trim(value, ".") == "" {
		return fmt.Errorf("refusing %s %q: %w", kind, value, ErrInvalidMeta)
	}

	return nil
}

func parseState(state string) (*StateInfo, error) {
	ss := strings.Split(state, " ")
	if len(ss) != 4 {
		return nil, errors.New("invalid state file")
	}

	si := &StateInfo{
		Pkgbase: ss[0],
		PkgVer:  ss[1],
		TagVer:  ss[2],
		TagRev:  strings.Trim(ss[3], "\n"),
	}

	for kind, value := range map[string]string{
		"pkgbase": si.Pkgbase, "pkgver": si.PkgVer, "tagver": si.TagVer, "tagrev": si.TagRev,
	} {
		if err := checkMetaName(kind, value); err != nil {
			return nil, err
		}
	}

	return si, nil
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

func MatchGlobList(target string, globs []string) bool {
	for _, lGlob := range globs {
		tGlob, err := glob.Compile(lGlob)
		if err != nil {
			log.Warningf("failed to compile glob %s: %v", lGlob, err)
			return false
		}
		if tGlob.Match(target) {
			return true
		}
	}
	return false
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

func downloadSRCINFO(pkg, tag string) (*srcinfo.Srcinfo, error) {
	resp, err := http.Get(fmt.Sprintf(
		"https://gitlab.archlinux.org/archlinux/packaging/packages/%s/-/raw/%s/.SRCINFO", pkg, tag),
	)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	bResp, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	nSrcInfo, err := srcinfo.Parse(string(bResp))
	if err != nil {
		return nil, err
	}
	return nSrcInfo, nil
}

func getDescendantPIDs(rootPID int) ([]int, error) {
	// children is keyed by parent so the walk below is O(processes) instead of
	// re-scanning every process once per descendant found
	children := map[int][]int{}
	var descendants []int

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range procEntries {
		if !entry.IsDir() || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		statusPath := filepath.Join("/proc", pidStr, "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) == 2 {
					ppid, _ := strconv.Atoi(fields[1])
					children[ppid] = append(children[ppid], pid)
				}
			}
		}
	}

	// copied rather than aliased: the walk appends to queue, which would otherwise
	// write into the map's own backing array
	queue := append([]int(nil), children[rootPID]...)
	for len(queue) > 0 {
		pid := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		descendants = append(descendants, pid)
		queue = append(queue, children[pid]...)
	}

	return descendants, nil
}

type MemStats struct {
	RSS  int64
	Swap int64
}

func getMemoryStats(pid int) (MemStats, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return MemStats{}, err
	}

	stats := MemStats{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				stats.RSS = kb
			}
		}
		if strings.HasPrefix(line, "VmSwap:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				stats.Swap = kb
			}
		}
	}

	return stats, nil
}

// clockTick is the kernel's USER_HZ, the unit of the CPU times in /proc/<pid>/stat.
// Linux hardcodes this to 100 on every supported architecture. procfs knows the same
// value but only exposes it for a process' own time, not for its reaped children.
const clockTick = 100

// getCPUTime returns the CPU time consumed by pid, including the time of the children
// it has already reaped. Counting reaped children is what keeps the sum over a process
// tree non-decreasing as build steps come and go: when a process is reaped its time
// moves into its parent's cutime/cstime rather than disappearing.
func getCPUTime(pid int) (time.Duration, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return 0, err
	}

	stat, err := proc.Stat()
	if err != nil {
		return 0, err
	}

	ticks := int64(stat.UTime) + int64(stat.STime) + int64(stat.CUTime) + int64(stat.CSTime) //nolint:gosec
	return time.Duration(ticks) * time.Second / clockTick, nil
}

// sampleProcessTree sums memory (RSS+swap, in kB) and CPU time over rootPID and all
// its descendants.
func sampleProcessTree(rootPID int) (memory int64, cpu time.Duration) {
	memory, cpu = sampleProcess(rootPID)

	descendants, err := getDescendantPIDs(rootPID)
	if err != nil {
		log.Errorf("failed to get descendants: %v", err)
	}

	for _, pid := range descendants {
		dMemory, dCPU := sampleProcess(pid)
		memory += dMemory
		cpu += dCPU
	}

	return memory, cpu
}

// sampleProcess reads one process' memory and CPU time, treating a process that
// vanished mid-sample as contributing nothing.
func sampleProcess(pid int) (memory int64, cpu time.Duration) {
	if stats, err := getMemoryStats(pid); err == nil {
		memory = stats.RSS + stats.Swap
	}

	if t, err := getCPUTime(pid); err == nil {
		cpu = t
	}

	return memory, cpu
}
