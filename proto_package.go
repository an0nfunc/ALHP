package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"git.harting.dev/ALHP/ALHP.GO/ent"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/google/uuid"
	"github.com/otiai10/copy"
	log "github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ProtoPackage struct {
	Pkgbase   string
	Pkgbuild  string
	Srcinfo   *srcinfo.Srcinfo
	Arch      string
	PkgFiles  []string
	Repo      dbpackage.Repository
	March     string
	FullRepo  string
	Version   string
	Hash      string
	DbPackage *ent.DbPackage
}

func (p *ProtoPackage) isEligible(ctx context.Context) (bool, error) {
	if err := p.genSrcinfo(); err != nil {
		return false, fmt.Errorf("error generating SRCINFO: %w", err)
	}
	p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)

	if !p.isAvailable(alpmHandle) {
		log.Debugf("[%s/%s] Not available on mirror, skipping build", p.FullRepo, p.Pkgbase)
		return false, nil
	}

	p.toDbPackage(true)
	skipping := false
	if Contains(p.Srcinfo.Arch, "any") {
		log.Debugf("Skipped %s: any-Package", p.Srcinfo.Pkgbase)
		p.DbPackage.SkipReason = "arch = any"
		p.DbPackage.Status = dbpackage.StatusSkipped
		skipping = true
	} else if Contains(conf.Blacklist.Packages, p.Srcinfo.Pkgbase) {
		log.Debugf("Skipped %s: blacklisted package", p.Srcinfo.Pkgbase)
		p.DbPackage.SkipReason = "blacklisted"
		p.DbPackage.Status = dbpackage.StatusSkipped
		skipping = true
	} else if Contains(p.Srcinfo.MakeDepends, "ghc") || Contains(p.Srcinfo.MakeDepends, "haskell-ghc") ||
		Contains(p.Srcinfo.Depends, "ghc") || Contains(p.Srcinfo.Depends, "haskell-ghc") {
		// Skip Haskell packages for now, as we are facing linking problems with them,
		// most likely caused by not having a dependency check implemented yet and building at random.
		// https://git.harting.dev/anonfunc/ALHP.GO/issues/11
		log.Debugf("Skipped %s: haskell package", p.Srcinfo.Pkgbase)
		p.DbPackage.SkipReason = "blacklisted (haskell)"
		p.DbPackage.Status = dbpackage.StatusSkipped
		skipping = true
	} else if p.isPkgFailed() {
		log.Debugf("Skipped %s: failed build", p.Srcinfo.Pkgbase)
		skipping = true
	}

	if skipping {
		p.DbPackage = p.DbPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).
			SetPackages(packages2slice(p.Srcinfo.Packages)).SetStatus(p.DbPackage.Status).
			SetSkipReason(p.DbPackage.SkipReason).SetHash(p.Hash).SaveX(ctx)
		return false, nil
	} else {
		p.DbPackage = p.DbPackage.Update().SetUpdated(time.Now()).SetPackages(packages2slice(p.Srcinfo.Packages)).SetVersion(p.Version).SaveX(ctx)
	}

	if Contains(conf.Blacklist.LTO, p.Pkgbase) {
		p.DbPackage = p.DbPackage.Update().SetLto(dbpackage.LtoDisabled).SaveX(ctx)
	}

	repoVer, err := p.repoVersion()
	if err != nil {
		p.DbPackage = p.DbPackage.Update().ClearRepoVersion().SaveX(ctx)
	} else if err == nil && alpm.VerCmp(repoVer, p.Version) > 0 {
		log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", p.Srcinfo.Pkgbase, p.Version, repoVer)
		p.DbPackage = p.DbPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetHash(p.Hash).SaveX(ctx)
		return false, nil
	}

	isLatest, local, syncVersion, err := p.isMirrorLatest(alpmHandle)
	if err != nil {
		switch err.(type) {
		default:
			return false, fmt.Errorf("error solving deps: %w", err)
		case MultiplePKGBUILDError:
			log.Infof("Skipped %s: Multiple PKGBUILDs for dependency found: %v", p.Srcinfo.Pkgbase, err)
			p.DbPackage = p.DbPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(ctx)
			return false, err
		case UnableToSatisfyError:
			log.Infof("Skipped %s: unable to resolve dependencies: %v", p.Srcinfo.Pkgbase, err)
			p.DbPackage = p.DbPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(ctx)
			return false, err
		}
	}

	p.DbPackage = p.DbPackage.Update().SetStatus(dbpackage.StatusQueued).SaveX(ctx)

	if !isLatest {
		if local != nil {
			log.Infof("Delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)", p.Srcinfo.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
			p.DbPackage.Update().SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).ExecX(ctx)
		} else {
			log.Infof("Delayed %s: not all dependencies are up to date or resolvable", p.Srcinfo.Pkgbase)
			p.DbPackage.Update().SetSkipReason("waiting for mirror").ExecX(ctx)
		}

		// Purge delayed packages in case delay is caused by inconsistencies in svn2git.
		// Worst case would be clients downloading a package update twice, once from their official mirror,
		// and then after build from ALHP. Best case we prevent a not buildable package from staying in the repos
		// in an outdated version.
		return false, nil
	}

	return true, nil
}

func (p *ProtoPackage) build(ctx context.Context) (time.Duration, error) {
	// Sleep randomly here to add some delay, avoiding two pacman instances trying to download the same package,
	// which leads to errors when it's trying to remove the same temporary download file.
	// This can be removed as soon as we can pass separate cache locations to makechrootpkg.
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Duration(rand.Float32()*60) * time.Second)
	start := time.Now().UTC()
	workerId := uuid.New()
	chroot := "build_" + workerId.String()

	log.Infof("[%s/%s/%s] Build starting", p.FullRepo, p.Pkgbase, p.Version)

	p.toDbPackage(true)
	p.DbPackage = p.DbPackage.Update().SetStatus(dbpackage.StatusBuilding).ClearSkipReason().SaveX(ctx)

	err := p.importKeys()
	if err != nil {
		log.Warningf("[%s/%s/%s] Failed to import pgp keys: %v", p.FullRepo, p.Pkgbase, p.Version, err)
	}

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

	buildNo := 1
	versionSlice := strings.Split(p.DbPackage.LastVersionBuild, ".")
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

	if Contains(conf.KernelToPatch, p.Pkgbase) {
		err = p.prepareKernelPatches()
		if err != nil {
			p.DbPackage.Update().SetStatus(dbpackage.StatusFailed).SetSkipReason("failed to apply patch").SetHash(p.Hash).ExecX(ctx)
			return time.Since(start), fmt.Errorf("error modifying PKGBUILD for kernel patch: %w", err)
		}
	}

	p.PkgFiles = []string{}

	// default to LTO
	makepkgFile := makepkg
	if p.DbPackage.Lto == dbpackage.LtoDisabled || p.DbPackage.Lto == dbpackage.LtoAutoDisabled {
		// use non-lto makepkg.conf if LTO is blacklisted for this package
		makepkgFile = makepkgLTO
	}
	cmd := exec.CommandContext(ctx, "makechrootpkg", "-c", "-D", filepath.Join(conf.Basedir.Work, makepkgDir), "-l", chroot, "-r", filepath.Join(conf.Basedir.Work, chrootDir), "--",
		"-m", "--noprogressbar", "--config", filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkgFile, p.March)))
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
		log.Fatalf("Rusage is not of type *syscall.Rusage, are we running on unix-like?")
	}

	if err != nil {
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}

		if p.DbPackage.Lto != dbpackage.LtoAutoDisabled && p.DbPackage.Lto != dbpackage.LtoDisabled && reLdError.Match(out.Bytes()) {
			p.DbPackage.Update().SetStatus(dbpackage.StatusQueued).SetSkipReason("non-LTO rebuild").SetLto(dbpackage.LtoAutoDisabled).ExecX(ctx)
			return time.Since(start), fmt.Errorf("ld error detected, LTO disabled")
		}

		if reDownloadError.Match(out.Bytes()) || rePortError.Match(out.Bytes()) || reSigError.Match(out.Bytes()) {
			p.DbPackage.Update().SetStatus(dbpackage.StatusQueued).ExecX(ctx)
			return time.Since(start), fmt.Errorf("known builderror detected")
		}

		err = os.MkdirAll(filepath.Join(conf.Basedir.Repo, logDir, p.March), 0755)
		if err != nil {
			return time.Since(start), fmt.Errorf("error creating logdir: %w", err)
		}
		err = os.WriteFile(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log"), out.Bytes(), 0644)
		if err != nil {
			return time.Since(start), fmt.Errorf("error warting to logdir: %w", err)
		}

		p.DbPackage.Update().
			SetStatus(dbpackage.StatusFailed).
			ClearSkipReason().
			SetBuildTimeStart(start).
			SetMaxRss(Rusage.Maxrss).
			SetIoOut(Rusage.Oublock).
			SetIoIn(Rusage.Inblock).
			SetUTime(Rusage.Utime.Sec).
			SetSTime(Rusage.Stime.Sec).
			SetHash(p.Hash).
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
		err = os.MkdirAll(holdingDir, 0755)
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

	if p.DbPackage.Lto != dbpackage.LtoDisabled && p.DbPackage.Lto != dbpackage.LtoAutoDisabled {
		p.DbPackage.Update().
			SetStatus(dbpackage.StatusBuild).
			SetLto(dbpackage.LtoEnabled).
			SetBuildTimeStart(start).
			SetLastVersionBuild(p.Version).
			SetHash(p.Hash).
			SetMaxRss(Rusage.Maxrss).
			SetIoOut(Rusage.Oublock).
			SetIoIn(Rusage.Inblock).
			SetUTime(Rusage.Utime.Sec).
			SetSTime(Rusage.Stime.Sec).
			ExecX(ctx)
	} else {
		p.DbPackage.Update().
			SetStatus(dbpackage.StatusBuild).
			SetBuildTimeStart(start).
			SetLastVersionBuild(p.Version).
			SetMaxRss(Rusage.Maxrss).
			SetIoOut(Rusage.Oublock).
			SetIoIn(Rusage.Inblock).
			SetUTime(Rusage.Utime.Sec).
			SetSTime(Rusage.Stime.Sec).
			SetHash(p.Hash).ExecX(ctx)
	}

	return time.Since(start), nil
}

func (p *ProtoPackage) Priority() float64 {
	if p.DbPackage == nil {
		return 0
	}

	if p.DbPackage.STime == nil || p.DbPackage.UTime == nil {
		return 0
	} else {
		return float64(*p.DbPackage.STime + *p.DbPackage.UTime)
	}
}

func (p *ProtoPackage) setupBuildDir() (string, error) {
	buildDir := filepath.Join(conf.Basedir.Work, buildDir, p.March, p.Pkgbase+"-"+p.Version)

	err := cleanBuildDir(buildDir, "")
	if err != nil {
		return "", fmt.Errorf("removing old builddir failed: %w", err)
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
		err = copy.Copy(file, filepath.Join(buildDir, filepath.Base(file)))
		if err != nil {
			return "", err
		}
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

func (p *ProtoPackage) prepareKernelPatches() error {
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

func (p *ProtoPackage) importKeys() error {
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
	} else {
		pkg, err = dbs.FindSatisfier(p.DbPackage.Packages[0])
	}
	buildManager.alpmMutex.Unlock()
	if err != nil {
		return false
	}

	if pkg.DB().Name() != p.Repo.String() || pkg.Base() != p.Pkgbase {
		return false
	}

	if p.Srcinfo != nil && (p.Srcinfo.Arch[0] != pkg.Architecture() || p.Srcinfo.Pkgbase != pkg.Base()) {
		return false
	}

	return true
}

func (p *ProtoPackage) SVN2GITVersion(h *alpm.Handle) (string, error) {
	if p.Pkgbuild == "" && p.Pkgbase == "" {
		return "", fmt.Errorf("invalid arguments")
	}

	pkgBuilds, _ := Glob(filepath.Join(conf.Basedir.Work, upstreamDir, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"))

	var fPkgbuilds []string
	for _, pkgbuild := range pkgBuilds {
		mPkgbuild := PKGBUILD(pkgbuild)
		if mPkgbuild.FullRepo() == "trunk" || containsSubStr(mPkgbuild.FullRepo(), conf.Blacklist.Repo) {
			continue
		}

		if !Contains(fPkgbuilds, pkgbuild) {
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

	cmd := exec.Command("makepkg", "--printsrcinfo")
	cmd.Dir = filepath.Dir(fPkgbuilds[0])
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

func (p *ProtoPackage) isPkgFailed() bool {
	if p.DbPackage.Version == "" {
		return false
	}

	if err := p.genSrcinfo(); err != nil {
		return false
	}

	if p.Version == "" {
		p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
	}

	if alpm.VerCmp(p.DbPackage.Version, p.Version) < 0 {
		return false
	}
	return p.DbPackage.Status == dbpackage.StatusFailed
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

	if p.DbPackage == nil && p.Srcinfo == nil {
		return fmt.Errorf("unable to find pkgfiles without dbpkg or srcinfo present")
	}

	var realPkgs []string
	if p.DbPackage != nil {
		for _, realPkg := range p.DbPackage.Packages {
			realPkgs = append(realPkgs, realPkg)
		}
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

func (p *ProtoPackage) toDbPackage(create bool) {
	if p.DbPackage != nil {
		return
	}

	dbPkg, err := db.DbPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March), dbpackage.RepositoryEQ(p.Repo))).Only(context.Background())
	if err != nil && create {
		dbPkg = db.DbPackage.Create().SetPkgbase(p.Pkgbase).SetMarch(p.March).SetPackages(packages2slice(p.Srcinfo.Packages)).SetRepository(p.Repo).SaveX(context.Background())
	}

	p.DbPackage = dbPkg
}

func (p ProtoPackage) exists() (bool, error) {
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March))).Exist(context.Background())
	if err != nil {
		return false, err
	}

	return dbPkg, nil
}

func (p *ProtoPackage) isMirrorLatest(h *alpm.Handle) (bool, alpm.IPackage, string, error) {
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
		}).SVN2GITVersion(h)
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
