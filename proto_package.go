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
	Pkgbuild  string
	Srcinfo   *srcinfo.Srcinfo
	Arch      string
	PkgFiles  []string
	Repo      dbpackage.Repository
	March     string
	FullRepo  string
	Version   string
	Hash      string
	DBPackage *ent.DbPackage
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

	p.toDBPackage(true)
	skipping := false
	switch {
	case Contains(p.Srcinfo.Arch, "any"):
		log.Debugf("Skipped %s: any-Package", p.Srcinfo.Pkgbase)
		p.DBPackage.SkipReason = "arch = any"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case Contains(conf.Blacklist.Packages, p.Srcinfo.Pkgbase):
		log.Debugf("Skipped %s: blacklisted package", p.Srcinfo.Pkgbase)
		p.DBPackage.SkipReason = "blacklisted"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case Contains(p.Srcinfo.MakeDepends, "ghc") || Contains(p.Srcinfo.MakeDepends, "haskell-ghc") ||
		Contains(p.Srcinfo.Depends, "ghc") || Contains(p.Srcinfo.Depends, "haskell-ghc"):
		log.Debugf("Skipped %s: haskell package", p.Srcinfo.Pkgbase)
		p.DBPackage.SkipReason = "blacklisted (haskell)"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.DBPackage.MaxRss != nil && datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB > conf.Build.MemoryLimit:
		log.Debugf("Skipped %s: memory limit exceeded (%s)", p.Srcinfo.Pkgbase, datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB)
		p.DBPackage.SkipReason = "memory limit exceeded"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.isPkgFailed():
		log.Debugf("Skipped %s: failed build", p.Srcinfo.Pkgbase)
		skipping = true
	}

	if skipping {
		p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).
			SetPackages(packages2slice(p.Srcinfo.Packages)).SetStatus(p.DBPackage.Status).
			SetSkipReason(p.DBPackage.SkipReason).SetHash(p.Hash).SaveX(ctx)
		return false, nil
	} else {
		p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetPackages(packages2slice(p.Srcinfo.Packages)).SetVersion(p.Version).SaveX(ctx)
	}

	if Contains(conf.Blacklist.LTO, p.Pkgbase) {
		p.DBPackage = p.DBPackage.Update().SetLto(dbpackage.LtoDisabled).SaveX(ctx)
	}

	repoVer, err := p.repoVersion()
	if err != nil {
		p.DBPackage = p.DBPackage.Update().ClearRepoVersion().SaveX(ctx)
	} else if err == nil && alpm.VerCmp(repoVer, p.Version) > 0 {
		log.Debugf("Skipped %s: Version in repo higher than in PKGBUILD (%s < %s)", p.Srcinfo.Pkgbase, p.Version, repoVer)
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetHash(p.Hash).SaveX(ctx)
		return false, nil
	}

	isLatest, local, syncVersion, err := p.isMirrorLatest(alpmHandle)
	if err != nil {
		switch err.(type) {
		default:
			return false, fmt.Errorf("error solving deps: %w", err)
		case MultiplePKGBUILDError:
			log.Infof("Skipped %s: Multiple PKGBUILDs for dependency found: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(ctx)
			return false, err
		case UnableToSatisfyError:
			log.Infof("Skipped %s: unable to resolve dependencies: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(ctx)
			return false, err
		}
	}

	p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).SaveX(ctx)

	if !isLatest {
		if local != nil {
			log.Infof("Delayed %s: not all dependencies are up to date (local: %s==%s, sync: %s==%s)",
				p.Srcinfo.Pkgbase, local.Name(), local.Version(), local.Name(), syncVersion)
			p.DBPackage.Update().SetStatus(dbpackage.StatusDelayed).
				SetSkipReason(fmt.Sprintf("waiting for %s==%s", local.Name(), syncVersion)).ExecX(ctx)

			// Returning an error here causes the package to be purged.
			// Purge delayed packages in case delay is caused by inconsistencies in svn2git.
			// Worst case would be clients downloading a package update twice, once from their official mirror,
			// and then after build from ALHP. Best case we prevent a not buildable package from staying in the repos
			// in an outdated version.
			if time.Since(local.BuildDate()).Hours() >= 48 && p.DBPackage.RepoVersion != "" {
				return false, errors.New("overdue package waiting")
			}
		} else {
			log.Infof("Delayed %s: not all dependencies are up to date or resolvable", p.Srcinfo.Pkgbase)
			p.DBPackage.Update().SetStatus(dbpackage.StatusDelayed).SetSkipReason("waiting for mirror").ExecX(ctx)
		}
		return false, nil
	}

	return true, nil
}

func (p *ProtoPackage) build(ctx context.Context) (time.Duration, error) {
	start := time.Now().UTC()
	chroot := "build_" + uuid.New().String()

	err := p.genSrcinfo()
	if err != nil {
		return time.Since(start), fmt.Errorf("error generating srcinfo: %w", err)
	}
	p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)

	log.Infof("[P] build starting: %s->%s->%s", p.FullRepo, p.Pkgbase, p.Version)

	p.toDBPackage(true)
	p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusBuilding).ClearSkipReason().SaveX(ctx)

	err = p.importKeys()
	if err != nil {
		log.Warningf("[P] failed to import pgp keys for %s->%s->%s: %v", p.FullRepo, p.Pkgbase, p.Version, err)
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

		if reDownloadError.MatchString(out.String()) || rePortError.MatchString(out.String()) || reSigError.MatchString(out.String()) {
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
		SetHash(p.Hash).
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
	} else {
		pkg, err = dbs.FindSatisfier(p.DBPackage.Packages[0])
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
		return "", fmt.Errorf("%s: no matching PKGBUILD found (searched: %s, canidates: %s)", p.Pkgbase,
			filepath.Join(conf.Basedir.Work, upstreamDir, "**/"+p.Pkgbase+"/repos/*/PKGBUILD"), pkgBuilds)
	}

	pPkg := PKGBUILD(fPkgbuilds[0])
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.RepositoryEQ(dbpackage.Repository(pPkg.Repo())),
		dbpackage.March(p.March), dbpackage.Pkgbase(p.Pkgbase)).Only(context.Background())
	if err == nil {
		return dbPkg.Version, nil
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
	if p.DBPackage.Version == "" {
		return false
	}

	if err := p.genSrcinfo(); err != nil {
		return false
	}

	if p.Version == "" {
		p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
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

	if p.DBPackage != nil && p.DBPackage.Srcinfo != nil {
		var err error
		p.Srcinfo, err = srcinfo.Parse(*p.DBPackage.Srcinfo)
		if err != nil {
			return err
		}
		return nil
	}

	cmd := exec.Command("makepkg", "--printsrcinfo", "-p", filepath.Base(p.Pkgbuild)) //nolint:gosec
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
	if p.DBPackage != nil {
		p.DBPackage = p.DBPackage.Update().SetSrcinfoHash(p.Hash).SetSrcinfo(string(res)).SaveX(context.Background())
	}

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

func (p *ProtoPackage) toDBPackage(create bool) {
	if p.DBPackage != nil {
		return
	}

	dbPkg, err := db.DbPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March),
		dbpackage.RepositoryEQ(p.Repo))).Only(context.Background())
	if err != nil && create {
		dbPkg = db.DbPackage.Create().
			SetPkgbase(p.Pkgbase).
			SetMarch(p.March).
			SetPackages(packages2slice(p.Srcinfo.Packages)).
			SetRepository(p.Repo).
			SaveX(context.Background())
	}

	p.DBPackage = dbPkg
}

func (p *ProtoPackage) exists() (bool, error) {
	dbPkg, err := db.DbPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March))).Exist(context.Background())
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

func (p *ProtoPackage) PkgbaseEquals(p2 *ProtoPackage, marchSensitive bool) bool {
	return (marchSensitive && (p.Pkgbase == p2.Pkgbase && p.FullRepo == p2.FullRepo)) || (!marchSensitive && p.Pkgbase == p2.Pkgbase)
}
