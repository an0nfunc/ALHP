package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"git.harting.dev/ALHP/ALHP.GO/ent"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	"github.com/Jguer/go-alpm/v2"
	"github.com/Morganamilo/go-srcinfo"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

func (p *ProtoPackage) setupBuildDir() (string, error) {
	buildDir := filepath.Join(conf.Basedir.Work, buildDir, p.March, p.Pkgbase+"-"+p.Version)

	err := cleanBuildDir(buildDir)
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
		_, err = copyFile(file, filepath.Join(buildDir, filepath.Base(file)))
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

	cmd := exec.Command("sh", "-c", "cd "+filepath.Dir(p.Pkgbuild)+"&&"+"makepkg --printsrcinfo -p "+filepath.Base(p.Pkgbuild))
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
