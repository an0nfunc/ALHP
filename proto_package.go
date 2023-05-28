package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/c2h5oh/datasize"
	"github.com/google/uuid"
	"github.com/otiai10/copy"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ProtoPackage struct {
	Pkgbase   string
	Srcinfo   *srcinfo.Srcinfo
	Arch      string
	PkgFiles  []string
	Repo      dbpackage.Repository
	March     string
	FullRepo  string
	Version   string
	DBPackage *ent.DBPackage
	Pkgbuild  string
	State     *StateInfo
}

var (
	ErrorNotEligible = errors.New("package is not eligible")
)

func (p *ProtoPackage) isEligible(ctx context.Context) bool {
	skipping := false
	switch {
	case p.Arch == "any":
		log.Debugf("skipped %s: any-package", p.Pkgbase)
		p.DBPackage.SkipReason = "arch = any"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case Contains(conf.Blacklist.Packages, p.Pkgbase):
		log.Debugf("skipped %s: blacklisted package", p.Pkgbase)
		p.DBPackage.SkipReason = "blacklisted"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.DBPackage.MaxRss != nil && datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB > conf.Build.MemoryLimit:
		log.Debugf("skipped %s: memory limit exceeded (%s)", p.Pkgbase, datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB)
		p.DBPackage.SkipReason = "memory limit exceeded"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.isPkgFailed():
		log.Debugf("skipped %s: failed build", p.Pkgbase)
		skipping = true
	}

	if skipping {
		p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).SetStatus(p.DBPackage.Status).
			SetSkipReason(p.DBPackage.SkipReason).SetTagRev(p.State.TagRev).SaveX(ctx)
		return false
	} else {
		p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).SaveX(ctx)
	}

	if Contains(conf.Blacklist.LTO, p.Pkgbase) && p.DBPackage.Lto != dbpackage.LtoDisabled {
		p.DBPackage = p.DBPackage.Update().SetLto(dbpackage.LtoDisabled).SaveX(ctx)
	}

	repoVer, err := p.repoVersion()
	if err != nil {
		p.DBPackage = p.DBPackage.Update().ClearRepoVersion().SaveX(ctx)
	} else if err == nil && alpm.VerCmp(repoVer, p.Version) > 0 {
		log.Debugf("skipped %s: version in repo higher than in PKGBUILD (%s < %s)", p.Pkgbase, p.Version, repoVer)
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetTagRev(p.State.TagRev).SaveX(ctx)
		return false
	}

	return true
}

func (p *ProtoPackage) build(ctx context.Context) (time.Duration, error) {
	start := time.Now().UTC()
	chroot := "build_" + uuid.New().String()

	buildFolder, err := p.setupBuildDir()
	if err != nil {
		return time.Since(start), fmt.Errorf("error setting up build folder: %w", err)
	}
	defer func() {
		chroot := chroot
		log.Debugf("removing chroot %s", chroot)
		err := cleanBuildDir(buildFolder, filepath.Join(conf.Basedir.Work, chrootDir, chroot))
		if err != nil {
			log.Errorf("error removing builddir/chroot %s/%s: %v", buildDir, chroot, err)
		}
	}()

	err = p.genSrcinfo()
	if err != nil {
		return time.Since(start), fmt.Errorf("error generating srcinfo: %w", err)
	}
	p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
	p.DBPackage = p.DBPackage.Update().SetPackages(packages2slice(p.Srcinfo.Packages)).SaveX(ctx)

	// skip haskell packages, since they cannot be optimized currently (no -O3 & march has no effect as far as I know)
	if Contains(p.Srcinfo.MakeDepends, "ghc") || Contains(p.Srcinfo.MakeDepends, "haskell-ghc") ||
		Contains(p.Srcinfo.Depends, "ghc") || Contains(p.Srcinfo.Depends, "haskell-ghc") {
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("haskell").SetTagRev(p.State.TagRev).SaveX(ctx)
		buildManager.repoPurge[p.FullRepo] <- []*ProtoPackage{p}
		return time.Since(start), ErrorNotEligible
	}

	isLatest, local, syncVersion, err := p.isMirrorLatest(alpmHandle)
	if err != nil {
		switch err.(type) {
		default:
			return time.Since(start), fmt.Errorf("error solving deps: %w", err)
		case MultipleStateFilesError:
			log.Infof("skipped %s: multiple PKGBUILDs for dependency found: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(ctx)
			return time.Since(start), err
		case UnableToSatisfyError:
			log.Infof("skipped %s: unable to resolve dependencies: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(ctx)
			return time.Since(start), err
		}
	}

	if !isLatest {
		if local != nil {
			log.Infof("delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)",
				p.Srcinfo.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
			p.DBPackage.Update().SetStatus(dbpackage.StatusDelayed).
				SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).ExecX(ctx)

			// Returning an error here causes the package to be purged.
			// Purge delayed packages in case delay is caused by inconsistencies in state.
			// Worst case would be clients downloading a package update twice, once from their official mirror,
			// and then after build from ALHP. Best case we prevent a not buildable package from staying in the repos
			// in an outdated version.
			if time.Since(local.BuildDate()).Hours() >= 48 && p.DBPackage.RepoVersion != "" {
				return time.Since(start), errors.New("overdue package waiting")
			}
		} else {
			log.Infof("delayed %s: not all dependencies are up to date or resolvable", p.Srcinfo.Pkgbase)
			p.DBPackage.Update().SetStatus(dbpackage.StatusDelayed).SetSkipReason("waiting for mirror").ExecX(ctx)
		}

		return time.Since(start), ErrorNotEligible
	}

	log.Infof("[P] build starting: %s->%s->%s", p.FullRepo, p.Pkgbase, p.Version)

	p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusBuilding).ClearSkipReason().SaveX(ctx)

	err = p.importKeys()
	if err != nil {
		log.Warningf("[P] failed to import pgp keys for %s->%s->%s: %v", p.FullRepo, p.Pkgbase, p.Version, err)
	}

	buildNo := 1
	versionSlice := strings.Split(p.DBPackage.LastVersionBuild, ".")
	if strings.Join(versionSlice[:len(versionSlice)-1], ".") == p.Version {
		buildNo, err = strconv.Atoi(versionSlice[len(versionSlice)-1])
		if err != nil {
			return time.Since(start), fmt.Errorf("error while reading buildNo from pkgrel: %w", err)
		}
		buildNo++
	}

	err = p.increasePkgRel(buildNo)
	if err != nil {
		return time.Since(start), fmt.Errorf("error while increasing pkgrel: %w", err)
	}

	p.PkgFiles = []string{}

	// default to LTO
	makepkgFile := makepkg
	if p.DBPackage.Lto == dbpackage.LtoDisabled || p.DBPackage.Lto == dbpackage.LtoAutoDisabled {
		// use non-lto makepkg.conf if LTO is blacklisted for this package
		makepkgFile = makepkgLTO
	}
	cmd := exec.CommandContext(ctx, "makechrootpkg", "-c", "-D", filepath.Join(conf.Basedir.Work, makepkgDir), //nolint:gosec
		"-l", chroot, "-r", filepath.Join(conf.Basedir.Work, chrootDir), "--", "-m", "--noprogressbar", "--config",
		filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkgFile, p.March)))
	cmd.Dir = filepath.Dir(p.Pkgbuild)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Start()
	if err != nil {
		return time.Since(start), fmt.Errorf("error starting build: %w", err)
	}

	err = cmd.Wait()

	Rusage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		log.Panicf("Rusage is not of type *syscall.Rusage, are we running on unix-like?")
	}

	if err != nil {
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}

		if p.DBPackage.Lto != dbpackage.LtoAutoDisabled && p.DBPackage.Lto != dbpackage.LtoDisabled &&
			(reLdError.MatchString(out.String()) || reRustLTOError.MatchString(out.String())) {
			p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).SetSkipReason("non-LTO rebuild").SetLto(dbpackage.LtoAutoDisabled).ExecX(ctx)
			return time.Since(start), fmt.Errorf("ld/lto-incomp error detected, LTO disabled")
		}

		if reDownloadError.MatchString(out.String()) || reDownloadError2.MatchString(out.String()) ||
			rePortError.MatchString(out.String()) || reSigError.MatchString(out.String()) {
			p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).ExecX(ctx)
			return time.Since(start), fmt.Errorf("known builderror detected")
		}

		err = os.MkdirAll(filepath.Join(conf.Basedir.Repo, logDir, p.March), 0o755)
		if err != nil {
			return time.Since(start), fmt.Errorf("error creating logdir: %w", err)
		}
		err = os.WriteFile(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log"), out.Bytes(), 0o644) //nolint:gosec
		if err != nil {
			return time.Since(start), fmt.Errorf("error warting to logdir: %w", err)
		}

		p.DBPackage.Update().
			SetStatus(dbpackage.StatusFailed).
			ClearSkipReason().
			SetBuildTimeStart(start).
			ClearMaxRss().
			ClearLastVersionBuild().
			ClearIoOut().
			ClearIoIn().
			ClearUTime().
			ClearSTime().
			SetTagRev(p.State.TagRev).
			ExecX(ctx)
		return time.Since(start), fmt.Errorf("build failed: exit code %d", cmd.ProcessState.ExitCode())
	}

	pkgFiles, err := filepath.Glob(filepath.Join(filepath.Dir(p.Pkgbuild), "*.pkg.tar.zst"))
	if err != nil {
		return time.Since(start), fmt.Errorf("error scanning builddir for artifacts: %w", err)
	}

	if len(pkgFiles) == 0 {
		return time.Since(start), fmt.Errorf("no build-artifacts found")
	}

	for _, file := range pkgFiles {
		cmd = exec.Command("gpg", "--batch", "--detach-sign", file)
		res, err := cmd.CombinedOutput()
		if err != nil {
			return time.Since(start), fmt.Errorf("error while signing artifact: %w (%s)", err, string(res))
		}
	}

	copyFiles, err := filepath.Glob(filepath.Join(filepath.Dir(p.Pkgbuild), "*.pkg.tar.zst*"))
	if err != nil {
		return time.Since(start), fmt.Errorf("error scanning builddir for artifacts: %w", err)
	}

	holdingDir := filepath.Join(conf.Basedir.Work, waitingDir, p.FullRepo)
	for _, file := range copyFiles {
		err = os.MkdirAll(holdingDir, 0o755)
		if err != nil {
			return time.Since(start), fmt.Errorf("error creating %s: %w", holdingDir, err)
		}
		err = copy.Copy(file, filepath.Join(holdingDir, filepath.Base(file)))
		if err != nil {
			return time.Since(start), fmt.Errorf("error while copying file to %s: %w", filepath.Join(holdingDir, filepath.Base(file)), err)
		}

		if filepath.Ext(file) != ".sig" {
			p.PkgFiles = append(p.PkgFiles, filepath.Join(holdingDir, filepath.Base(file)))
		}
	}

	if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log")); err == nil {
		err := os.Remove(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log"))
		if err != nil {
			return time.Since(start), fmt.Errorf("error removing log: %w", err)
		}
	}

	updatePkg := p.DBPackage.Update().
		SetStatus(dbpackage.StatusBuild).
		SetLto(dbpackage.LtoEnabled).
		SetBuildTimeStart(start).
		SetLastVersionBuild(p.Version).
		SetTagRev(p.State.TagRev).
		SetMaxRss(Rusage.Maxrss).
		SetIoOut(Rusage.Oublock).
		SetIoIn(Rusage.Inblock).
		SetUTime(Rusage.Utime.Sec).
		SetSTime(Rusage.Stime.Sec)

	if p.DBPackage.Lto != dbpackage.LtoDisabled && p.DBPackage.Lto != dbpackage.LtoAutoDisabled {
		updatePkg.SetLto(dbpackage.LtoEnabled)
	}

	updatePkg.ExecX(ctx)

	return time.Since(start), nil
}

func (p *ProtoPackage) setupBuildDir() (string, error) {
	buildDir := filepath.Join(conf.Basedir.Work, buildDir, p.March, p.Pkgbase+"-"+p.Version)

	err := cleanBuildDir(buildDir, "")
	if err != nil {
		return "", fmt.Errorf("removing old builddir failed: %w", err)
	}

	err = os.MkdirAll(buildDir, 0o755)
	if err != nil {
		return "", err
	}

	gitlabPath := reReplaceSinglePlus.ReplaceAllString(p.Pkgbase, "$1-$2")
	gitlabPath = reReplaceRemainingPlus.ReplaceAllString(gitlabPath, "plus")
	gitlabPath = reReplaceSpecialChars.ReplaceAllString(gitlabPath, "-")
	gitlabPath = reReplaceUnderscore.ReplaceAllString(gitlabPath, "-")
	gitlabPath = reReplaceTree.ReplaceAllString(gitlabPath, "unix-tree")

	gr := retry.NewFibonacci(10 * time.Second)
	gr = retry.WithMaxRetries(conf.MaxCloneRetries, gr)

	if err := retry.Do(context.Background(), gr, func(ctx context.Context) error {
		cmd := exec.Command("git", "clone", "--depth", "1", "--branch", p.State.TagVer,
			fmt.Sprintf("https://gitlab.archlinux.org/archlinux/packaging/packages/%s.git", gitlabPath), buildDir)
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return retry.RetryableError(err)
		}
		return nil
	}); err != nil {
		return "", err
	}
	p.Pkgbuild = filepath.Join(buildDir, "PKGBUILD")

	return buildDir, nil
}

func (p *ProtoPackage) repoVersion() (string, error) {
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

func (p *ProtoPackage) increasePkgRel(buildNo int) error {
	if p.Srcinfo == nil {
		err := p.genSrcinfo()
		if err != nil {
			return fmt.Errorf("error generating srcinfo: %w", err)
		}
	}

	if p.Version == "" {
		p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
	}

	f, err := os.OpenFile(p.Pkgbuild, os.O_RDWR, 0o644)
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

func (p *ProtoPackage) importKeys() error {
	if p.Srcinfo == nil {
		err := p.genSrcinfo()
		if err != nil {
			return fmt.Errorf("error generating srcinfo: %w", err)
		}
	}

	if p.Srcinfo.ValidPGPKeys != nil {
		args := []string{"--keyserver", "keyserver.ubuntu.com", "--recv-keys"}
		args = append(args, p.Srcinfo.ValidPGPKeys...)
		cmd := exec.Command("gpg", args...)
		_, err := cmd.CombinedOutput()

		return err
	}
	return nil
}

func (p *ProtoPackage) isAvailable(h *alpm.Handle) bool {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false
	}

	buildManager.alpmMutex.Lock()
	var pkg alpm.IPackage
	if p.Srcinfo != nil {
		pkg, err = dbs.FindSatisfier(p.Srcinfo.Packages[0].Pkgname)
	} else if p.DBPackage != nil && len(p.DBPackage.Packages) > 0 {
		pkg, err = dbs.FindSatisfier(p.DBPackage.Packages[0])
	} else {
		cmd := exec.Command("unbuffer", "pacsift", "--exact", "--base="+p.Pkgbase, "--repo="+p.Repo.String())
		var res []byte
		res, err = cmd.CombinedOutput()
		if err != nil {
			log.Warningf("error getting packages from pacsift for %s: %v", p.Pkgbase, err)
			buildManager.alpmMutex.Unlock()
			return false
		} else if len(res) == 0 {
			buildManager.alpmMutex.Unlock()
			return false
		}

		if len(strings.Split(strings.TrimSpace(string(res)), "\n")) > 0 {
			pacsiftLines := strings.Split(strings.TrimSpace(string(res)), "\n")

			var splitPkgs []string
			for _, line := range pacsiftLines {
				splitPkgs = append(splitPkgs, strings.Split(line, "/")[1])
			}

			if p.DBPackage != nil {
				p.DBPackage = p.DBPackage.Update().SetPackages(splitPkgs).SaveX(context.Background())
			}
			pkg, err = dbs.FindSatisfier(splitPkgs[0])
		} else {
			log.Warningf("error getting packages from pacsift for %s", p.Pkgbase)
			buildManager.alpmMutex.Unlock()
			return false
		}
	}
	buildManager.alpmMutex.Unlock()
	if err != nil {
		log.Debugf("error resolving %s: %v", p.Pkgbase, err)
		return false
	}

	if pkg.DB().Name() != p.Repo.String() || pkg.Base() != p.Pkgbase {
		log.Debugf("%s: repo (%s!=%s) or pkgbase (%s!=%s) does not match", p.Pkgbase, pkg.DB().Name(), p.Repo.String(), pkg.Base(), p.Pkgbase)
		return false
	}

	if p.Srcinfo != nil && (!Contains(p.Srcinfo.Arch, pkg.Architecture()) || p.Srcinfo.Pkgbase != pkg.Base()) {
		log.Debugf("%s: arch (%s!=%s) or pkgbase (%s!=%s) does not match", p.Pkgbase, p.Srcinfo.Arch[0],
			pkg.Architecture(), pkg.Base(), p.Pkgbase)
		return false
	}

	return true
}

func (p *ProtoPackage) GitVersion(h *alpm.Handle) (string, error) {
	if p.Pkgbase == "" {
		return "", fmt.Errorf("invalid arguments")
	}

	stateFiles, _ := Glob(filepath.Join(conf.Basedir.Work, stateDir, "**/"+p.Pkgbase))

	var fStateFiles []string
	for _, stateFile := range stateFiles {
		_, subRepo, _, err := stateFileMeta(stateFile)
		if err != nil {
			continue
		}

		if subRepo != nil {
			continue
		}

		if !Contains(fStateFiles, stateFile) {
			fStateFiles = append(fStateFiles, stateFile)
		}
	}

	if len(fStateFiles) > 1 {
		log.Infof("%s: multiple statefiles found, try resolving from mirror", p.Pkgbase)
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
		for _, stateFile := range fStateFiles {
			repo, _, _, err := stateFileMeta(stateFile)
			if err != nil {
				continue
			}

			if iPackage.DB().Name() == repo {
				fStateFiles = []string{stateFile}
				break pkgloop
			}
		}

		if len(fStateFiles) > 1 {
			return "", MultipleStateFilesError{fmt.Errorf("%s: multiple statefiles found: %s", p.Pkgbase, fStateFiles)}
		}
		log.Infof("%s: resolving successful: MirrorRepo=%s; statefile chosen: %s", p.Pkgbase, iPackage.DB().Name(), fStateFiles[0])
	} else if len(fStateFiles) == 0 {
		return "", fmt.Errorf("%s: no matching statefile found (searched: %s, canidates: %s)", p.Pkgbase,
			filepath.Join(conf.Basedir.Work, stateDir, "**/"+p.Pkgbase), stateFiles)
	}

	rawState, err := os.ReadFile(fStateFiles[0])
	if err != nil {
		return "", fmt.Errorf("error reading statefile %s: %w", fStateFiles[0], err)
	}
	state, err := parseState(string(rawState))
	if err != nil {
		return "", fmt.Errorf("error parsing statefile: %w", err)
	}

	return state.PkgVer, nil
}

func (p *ProtoPackage) isPkgFailed() bool {
	if p.DBPackage.Version == "" {
		return false
	}

	if alpm.VerCmp(p.DBPackage.Version, p.Version) < 0 {
		return false
	}
	return p.DBPackage.Status == dbpackage.StatusFailed
}

func (p *ProtoPackage) genSrcinfo() error {
	if p.Srcinfo != nil {
		return nil
	}

	cmd := exec.Command("makepkg", "--printsrcinfo", "-p", filepath.Base(p.Pkgbuild))
	cmd.Dir = filepath.Dir(p.Pkgbuild)
	res, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("makepkg exit non-zero (PKGBUILD: %s): %w (%s)", p.Pkgbuild, err, string(res))
	}

	info, err := srcinfo.Parse(string(res))
	if err != nil {
		return err
	}
	p.Srcinfo = info

	return nil
}

func (p *ProtoPackage) findPkgFiles() error {
	pkgs, err := os.ReadDir(filepath.Join(conf.Basedir.Repo, p.FullRepo, "os", conf.Arch))
	if err != nil {
		return err
	}

	if p.DBPackage == nil && p.Srcinfo == nil {
		return fmt.Errorf("unable to find pkgfiles without dbpkg or srcinfo present")
	}

	var realPkgs []string
	if p.DBPackage != nil {
		realPkgs = append(realPkgs, p.DBPackage.Packages...)
	} else {
		for _, realPkg := range p.Srcinfo.Packages {
			realPkgs = append(realPkgs, realPkg.Pkgname)
		}
	}

	var fPkg []string
	for _, file := range pkgs {
		if !file.IsDir() && !strings.HasSuffix(file.Name(), ".sig") {
			matches := rePkgFile.FindStringSubmatch(file.Name())

			if len(matches) > 1 && Contains(realPkgs, matches[1]) {
				fPkg = append(fPkg, filepath.Join(conf.Basedir.Repo, p.FullRepo, "os", conf.Arch, file.Name()))
			}
		}
	}

	p.PkgFiles = fPkg
	return nil
}

func (p *ProtoPackage) toDBPackage(create bool) error {
	if p.DBPackage != nil {
		return nil
	}

	dbPkg, err := db.DBPackage.Query().Where(
		dbpackage.Pkgbase(p.Pkgbase),
		dbpackage.March(p.March),
		dbpackage.RepositoryEQ(p.Repo),
	).Only(context.Background())
	if err != nil && ent.IsNotFound(err) && create {
		dbPkg = db.DBPackage.Create().
			SetPkgbase(p.Pkgbase).
			SetMarch(p.March).
			SetRepository(p.Repo).
			SaveX(context.Background())
	} else if err != nil && !ent.IsNotFound(err) {
		return err
	}

	p.DBPackage = dbPkg
	return nil
}

func (p *ProtoPackage) exists() (bool, error) {
	dbPkg, err := db.DBPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March))).Exist(context.Background())
	if err != nil {
		return false, err
	}

	return dbPkg, nil
}

func (p *ProtoPackage) isMirrorLatest(h *alpm.Handle) (latest bool, foundPkg alpm.IPackage, version string, err error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false, nil, "", err
	}

	allDepends := p.Srcinfo.Depends
	allDepends = append(allDepends, p.Srcinfo.MakeDepends...)
	// add gcc to dependents, since we can't know for sure if its in use
	// prevents issues like #111
	allDepends = append(allDepends, srcinfo.ArchString{
		Arch:  "x86_64",
		Value: "gcc",
	})

	for _, dep := range allDepends {
		buildManager.alpmMutex.Lock()
		pkg, err := dbs.FindSatisfier(dep.Value)
		buildManager.alpmMutex.Unlock()
		if err != nil {
			return false, nil, "", UnableToSatisfyError{err}
		}

		svn2gitVer, err := (&ProtoPackage{
			Pkgbase: pkg.Base(),
			March:   p.March,
		}).GitVersion(h)
		if err != nil {
			return false, nil, "", err
		} else if svn2gitVer == "" {
			return false, nil, "", fmt.Errorf("no svn2git version")
		}

		if alpm.VerCmp(svn2gitVer, pkg.Version()) > 0 {
			return false, pkg, svn2gitVer, nil
		}
	}

	return true, nil, "", nil
}

func (p *ProtoPackage) PkgbaseEquals(p2 *ProtoPackage, marchSensitive bool) bool {
	return (marchSensitive && (p.Pkgbase == p2.Pkgbase && p.FullRepo == p2.FullRepo)) || (!marchSensitive && p.Pkgbase == p2.Pkgbase)
}
