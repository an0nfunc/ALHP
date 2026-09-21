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
	"slices"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Skip reasons surfaced from the build pipeline. Hoisted so the same string
// is used wherever a package is skipped for that reason.
const (
	SkipReasonAnyArch        = "arch = any"
	SkipReasonAnyArchMoved   = "arch = any (moved upstream)"
	upstreamDefaultGitBranch = "main"
	// archAny is the arch of packages that are not architecture specific.
	archAny = "any"
	// debugSuffix marks the pkgname of a package carrying debug symbols.
	debugSuffix = "-debug"
	// SkipReasonSonameMismatch prefixes the reason of a build we refused to
	// publish because it links a soname the repos no longer carry.
	SkipReasonSonameMismatch = "soname mismatch: "
	// noSkipReason clears any skip reason when recording a failed build.
	noSkipReason = ""
	// SkipReasonUnreleased marks a UseLatest build whose PKGBUILD is newer than
	// anything upstream has in the repo, i.e. main carried a tag staged for
	// testing or staging. Publishing it would ship a package Arch has not
	// released, with dependencies no released package satisfies.
	SkipReasonUnreleased = "ahead of upstream repo"
	// SkipReasonStalled, SkipReasonSilent and SkipReasonTimeout mark builds ALHP
	// killed itself. These values are load-bearing: housekeeping keys on them via
	// killSkipReasons to keep a killed build out of its requeue path, since a
	// truncated kill log can match a fixable-error pattern by accident and would
	// otherwise be rebuilt into the same hang forever.
	SkipReasonStalled = "build stalled"
	SkipReasonSilent  = "build silent"
	SkipReasonTimeout = "build timeout"
)

// killSkipReasons is every skip reason killReason can persist. Housekeeping's
// requeue paths exclude the whole set, so a new kill cause must be added here or
// the build it kills gets rebuilt into the same hang.
var killSkipReasons = []string{SkipReasonStalled, SkipReasonSilent, SkipReasonTimeout}

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
	// SyncPkg is the alpm package resolved by isAvailable; cached so
	// later checks (drift, arch-any-move) don't re-do FindSatisfier.
	SyncPkg alpm.IPackage
	// UseLatest causes SRCINFO/PKGBUILD to be fetched from
	// upstreamDefaultGitBranch (main) instead of state.TagVer/state.TagRev.
	// Set when upstream Arch ships a rebuild that state.git did not record.
	UseLatest bool
	// maxRSS is DBPackage.MaxRss snapshotted when the package was admitted to
	// BuildManager.building, written and read under buildingLock. The scheduler
	// needs the peak of every in-flight build, but build() reassigns DBPackage as
	// it goes, so reading it there would race.
	maxRSS *int64
}

var (
	ErrorNotEligible = errors.New("package is not eligible")
	// ErrInvalidMeta marks upstream metadata rejected by checkMetaName. Callers
	// must map it to ErrorNotEligible: a malformed new version says nothing about
	// the package already published, and any other error purges that build.
	ErrInvalidMeta = errors.New("invalid package metadata")
)

func (p *ProtoPackage) isEligible(ctx context.Context) bool {
	skipping := false
	switch {
	case p.Arch == archAny:
		log.Debugf("skipped %s: any-package", p.Pkgbase)
		p.DBPackage.SkipReason = SkipReasonAnyArch
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case MatchGlobList(p.Pkgbase, conf.Blacklist.Packages):
		log.Debugf("skipped %s: package on no-build list", p.Pkgbase)
		p.DBPackage.SkipReason = "blacklisted"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.DBPackage.MaxRss != nil && datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB > conf.Build.MemoryLimit: //nolint:gosec
		log.Debugf("skipped %s: memory limit exceeded (%s)", p.Pkgbase, datasize.ByteSize(*p.DBPackage.MaxRss)*datasize.KB) //nolint:gosec
		p.DBPackage.SkipReason = "memory limit exceeded"
		p.DBPackage.Status = dbpackage.StatusSkipped
		skipping = true
	case p.isPkgFailed():
		log.Debugf("skipped %s: failed build", p.Pkgbase)
		skipping = true
	case p.Srcinfo != nil:
		// skip haskell packages, since they cannot be optimized currently (no -O3 & march has no effect as far as I know)
		if Contains(p.Srcinfo.MakeDepends, "ghc") || Contains(p.Srcinfo.MakeDepends, "haskell-ghc") ||
			Contains(p.Srcinfo.Depends, "ghc") || Contains(p.Srcinfo.Depends, "haskell-ghc") {
			log.Debugf("skipped %s: haskell", p.Pkgbase)
			p.DBPackage.SkipReason = "haskell"
			p.DBPackage.Status = dbpackage.StatusSkipped
			skipping = true
		}
	}

	if skipping {
		p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).SetStatus(p.DBPackage.Status).
			SetSkipReason(p.DBPackage.SkipReason).SetTagRev(p.State.TagRev).SaveX(ctx)
		return false
	}
	p.DBPackage = p.DBPackage.Update().SetUpdated(time.Now()).SetVersion(p.Version).SaveX(ctx)

	if Contains(conf.Blacklist.LTO, p.Pkgbase) && p.DBPackage.Lto != dbpackage.LtoDisabled {
		p.DBPackage = p.DBPackage.Update().SetLto(dbpackage.LtoDisabled).SaveX(ctx)
	}

	repoVer, err := p.repoVersion()
	if err != nil {
		p.DBPackage = p.DBPackage.Update().ClearRepoVersion().SaveX(ctx)
	} else if alpm.VerCmp(repoVer, p.Version) > 0 {
		log.Debugf("skipped %s: version in repo higher than in PKGBUILD (%s < %s)", p.Pkgbase, p.Version, repoVer)
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusLatest).ClearSkipReason().SetTagRev(p.State.TagRev).SaveX(ctx)
		return false
	}

	return true
}

func (p *ProtoPackage) build(ctx context.Context) (time.Duration, error) {
	start := time.Now().UTC()
	// one id per build, rendered as the chroot copy name and the network namespace
	// name; neither is derived from the other
	buildID := uuid.New().String()
	chroot := chrootName(buildID)

	buildFolder, err := p.setupBuildDir(ctx)
	if err != nil {
		if errors.Is(err, ErrInvalidMeta) {
			// reachable before build()'s own check below, because genQueue assigns
			// Version from an HTTP-fetched .SRCINFO for UseLatest packages
			log.Warningf("[P] skipping %s->%s: %v", p.FullRepo, p.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).
				SetSkipReason("invalid version").SetTagRev(p.State.TagRev).SaveX(ctx)

			return time.Since(start), ErrorNotEligible
		}

		return time.Since(start), fmt.Errorf("error setting up build folder: %w", err)
	}
	defer func() {
		log.Debugf("removing chroot %s", chroot)
		err := cleanBuildDir(buildFolder, filepath.Join(conf.Basedir.Work, chrootDir, chroot))
		if err != nil {
			log.Errorf("error removing builddir %s and chroot %s: %v", buildFolder, chroot, err)
		}
	}()

	err = p.genSrcinfo(ctx)
	if err != nil {
		// A deadline or a shutdown says the host ran out of time, not that the
		// package is broken, and the plain error below reaches the purge. Without
		// this a slow PKGBUILD deletes its own published build, which is the one
		// thing the timeout must not be able to cause.
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return time.Since(start), fmt.Errorf("%w: error generating srcinfo: %w", ErrorNotEligible, err)
		}

		return time.Since(start), fmt.Errorf("error generating srcinfo: %w", err)
	}
	p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
	// the .SRCINFO this came from is fetched over HTTP and is not linted by makepkg;
	// the version becomes a directory name that helpers running as root are handed
	if err := checkMetaName("version", p.Version); err != nil {
		// ErrorNotEligible so a bad new upstream version does not delete the good
		// published build. TagRev is pinned like every other terminal skip, though
		// note genQueue's re-pick guard is skipped for UseLatest packages, which is
		// exactly the case whose version came from upstream unvalidated.
		log.Warningf("[P] skipping %s->%s: %v", p.FullRepo, p.Pkgbase, err)
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).
			SetSkipReason("invalid version").SetTagRev(p.State.TagRev).SaveX(ctx)

		return time.Since(start), ErrorNotEligible
	}

	// Refuse to publish what only main has. Upstream tags a rebuild for staging
	// or testing long before releasing it, so a build from main can resolve
	// against packages only staging carries and hand users a dependency they
	// cannot install. Guarded on UseLatest: from the pinned tag, being ahead of
	// the mirror is just state.git having moved before the mirror synced.
	if p.UseLatest && p.SyncPkg != nil && aheadOfUpstream(p.Version, p.State.PkgVer, p.SyncPkg.Version()) {
		log.Infof("[P] skipping %s->%s->%s: %s has not released it yet (upstream repo: %s)",
			p.FullRepo, p.Pkgbase, p.Version, upstreamDefaultGitBranch, p.SyncPkg.Version())
		// Delayed, not skipped: this resolves itself once upstream promotes the
		// tag, and housekeeping purges the published build of any package left
		// skipped. Purging here would take down the good older build over a
		// version upstream has not released.
		// TagRev is left alone because terminal outcomes pin it and delays do
		// not; the other delays below do the same. Nothing published, so
		// nothing to re-pin to.
		p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusDelayed).
			SetSkipReason(SkipReasonUnreleased).SaveX(ctx)

		return time.Since(start), ErrorNotEligible
	}

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
		var multipleStateFilesError MultipleStateFilesError
		var unableToSatisfyError UnableToSatisfyError
		switch {
		default:
			return time.Since(start), fmt.Errorf("error solving deps: %w", err)
		case errors.As(err, &multipleStateFilesError):
			log.Infof("skipped %s: multiple PKGBUILDs for dependency found: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("multiple PKGBUILD for dep. found").SaveX(ctx)
			return time.Since(start), err
		case errors.As(err, &unableToSatisfyError):
			log.Infof("skipped %s: unable to resolve dependencies: %v", p.Srcinfo.Pkgbase, err)
			p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusSkipped).SetSkipReason("unable to resolve dependencies").SaveX(ctx)
			return time.Since(start), ErrorNotEligible
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

	// kept across the build: SetStatus(Building) clears it, and the soname check
	// below needs to know whether this package was already rejected once
	priorSkipReason := p.DBPackage.SkipReason
	p.DBPackage = p.DBPackage.Update().SetStatus(dbpackage.StatusBuilding).ClearSkipReason().SaveX(ctx)

	// not fatal: makepkg verifies the sources itself and fails the build with its
	// own message, which names the key but not why it is absent. This line carries
	// what it cannot, the declared keys no keyserver supplied and whatever any
	// server that failed reported.
	if err := p.importKeys(ctx); err != nil {
		log.Warningf("[P] %s->%s->%s source verification will fail: %v", p.FullRepo, p.Pkgbase, p.Version, err)
	}

	// before nextBuildNo: a rewrite we cannot prove is abandoned, and abandoning
	// it must not consume a build number. Also before increasePkgRel, so the bound
	// edit is the only change in flight and p.Srcinfo is still upstream's
	if err := p.prepareBoundRewrite(ctx); err != nil {
		// a shutdown killing makepkg mid-reparse is not the package's fault, and
		// counting it would both dirty the metric and consume a build number for
		// every package in flight at the time
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}
		// counted before the branch below, so the attempt that most conclusively
		// could not be verified is not the one the counter misses
		buildManager.metrics.boundRewritesRefused.WithLabelValues(p.FullRepo).Inc()
		if errors.Is(err, errPkgbuildDirty) {
			// Neither the original nor a proven rewrite, so building it would
			// publish something nothing has vetted. Wrapped in ErrorNotEligible so
			// the published version survives: the only way to get here is a failed
			// write, which is a host fault (ENOSPC, EIO, a read-only mount) that
			// says nothing about the package and would otherwise walk the repo
			// deleting every build in turn.
			return time.Since(start), fmt.Errorf("%w: %w", ErrorNotEligible, err)
		}
		// otherwise today's behavior, minus the fix: the package still carries the
		// bug and checkArtifactBounds reports it, which beats not publishing it
		log.Warningf("[P] %s->%s building without bound rewrite: %v", p.FullRepo, p.Pkgbase, err)
	}

	buildNo, maxVersionBase, err := p.nextBuildNo()
	if err != nil {
		return time.Since(start), err
	}
	// before the build, not after: a build that fails or gets discarded must
	// still consume its number, because by the time we know it published
	// nothing the artifact may already have been moved live
	p.DBPackage = p.DBPackage.Update().SetBuildNo(buildNo).SetMaxVersionBase(maxVersionBase).SaveX(ctx)

	err = p.increasePkgRel(ctx, buildNo)
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
	// buildCtx carries the per-build deadlines; canceling it kills the build without
	// disturbing the process-wide ctx, and the cause tells the two deadlines apart.
	buildCtx, cancelBuild := context.WithCancelCause(ctx)
	defer cancelBuild(nil)
	if timeout := buildTimeout(); timeout > 0 {
		var stopTimeout context.CancelFunc
		buildCtx, stopTimeout = context.WithTimeoutCause(buildCtx, timeout, ErrBuildTimeout)
		defer stopTimeout()
	}

	cmd, releaseCmd, err := buildCommand(buildCtx, p, buildID, makepkgFile)
	if err != nil {
		return time.Since(start), err
	}
	defer releaseCmd()
	var out bytes.Buffer
	progress := newProgressWriter(&out)
	cmd.Stdout = progress
	cmd.Stderr = progress

	if err = cmd.Start(); err != nil {
		return time.Since(start), fmt.Errorf("error starting build: %w", err)
	}

	limits := buildStallLimits()
	monitor := startBuildMonitor(cmd.Process.Pid, progress, limits, func(cause error) {
		log.Warningf("[P] %s->%s->%s: %s, killing build", p.FullRepo, p.Pkgbase, p.Version, limits.reason(cause))
		cancelBuild(cause)
	})

	err = cmd.Wait()
	peakMem := monitor.stop()

	// a child that outlived a successful build and held the output pipe open trips
	// WaitDelay. os/exec closes the pipes and drains its copy goroutines before
	// returning this, so the log and the artifacts are complete and only the pipe was
	// late; without this the build would be recorded as "failed: exit code 0".
	// Gated on ctx so a shutdown landing in this window still takes the early return
	// below instead of publishing against a canceled context.
	if ctx.Err() == nil && errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		// not redundant with the ctx gate above, which only sees the process-wide
		// context: our own stall can set the cause during Wait's pipe drain, after
		// the cancel handshake, so nothing was killed but the build still exited 0
		if _, _, killed := killReason(context.Cause(buildCtx)); !killed {
			log.Warningf("[P] %s->%s->%s exited successfully but left a child holding the output pipe",
				p.FullRepo, p.Pkgbase, p.Version)
			err = nil
		}
	}

	if err != nil {
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}

		// Isolation never came up, so no build ran and this says nothing about the
		// package. Checked before everything below because the alternative is the
		// generic failure path, which records a failed build pinned to the current
		// TagRev and purges the published package: one bad /etc/resolv.conf would
		// walk the whole repo and delete it, with no requeue until upstream moves.
		if networkIsolationEnabled() && cmd.ProcessState.ExitCode() == exitIsolationSetup {
			p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).ExecX(ctx)
			// ErrorNotEligible, so buildmanager.go's error branch does not purge: the
			// published package is still good, and 121 is a host-wide fault that would
			// otherwise delete one package per build until someone noticed.
			log.Errorf("[P] %s->%s network isolation setup failed: %s", p.FullRepo, p.Pkgbase,
				strings.TrimSpace(lastLine(out.String())))
			buildManager.isolationFailures.Add(1)

			return time.Since(start), ErrorNotEligible
		}

		// checked before the log heuristics below: a killed build's log is truncated
		// mid-stream and could incidentally match one of them, which would requeue the
		// package and hang it again on the next pass
		cause := context.Cause(buildCtx)
		if metric, skipReason, killed := killReason(cause); killed {
			buildManager.metrics.buildsKilled.WithLabelValues(p.FullRepo, metric).Inc()
			if fErr := p.recordFailedBuild(ctx, start, out.String(), skipReason); fErr != nil {
				return time.Since(start), fErr
			}
			return time.Since(start), fmt.Errorf("build killed: %w", cause)
		}

		if p.DBPackage.Lto != dbpackage.LtoAutoDisabled && p.DBPackage.Lto != dbpackage.LtoDisabled &&
			(reLdError.MatchString(out.String()) || reRustLTOError.MatchString(out.String())) {
			p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).SetSkipReason("non-LTO rebuild").SetLto(dbpackage.LtoAutoDisabled).ExecX(ctx)
			return time.Since(start), errors.New("ld/lto-incompatibility error detected, LTO disabled")
		}

		if reDownloadError.MatchString(out.String()) || reDownloadError2.MatchString(out.String()) ||
			rePortError.MatchString(out.String()) || reSigError.MatchString(out.String()) {
			p.DBPackage.Update().SetStatus(dbpackage.StatusQueued).ExecX(ctx)
			return time.Since(start), errors.New("known build error detected")
		}

		if fErr := p.recordFailedBuild(ctx, start, out.String(), noSkipReason); fErr != nil {
			return time.Since(start), fErr
		}
		return time.Since(start), fmt.Errorf("build failed: exit code %d", cmd.ProcessState.ExitCode())
	}

	buildManager.isolationFailures.Store(0)

	Rusage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		log.Panicf("rusage is not of type *syscall.Rusage, are we running on unix-like?")
	}

	pkgFiles, err := filepath.Glob(filepath.Join(filepath.Dir(p.Pkgbuild), "*.pkg.tar.zst"))
	if err != nil {
		return time.Since(start), fmt.Errorf("error scanning builddir for artifacts: %w", err)
	}

	if len(pkgFiles) == 0 {
		return time.Since(start), errors.New("no build-artifacts found")
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

	// the build itself succeeded, so any log from an earlier failure is stale.
	// Removed before the soname check below, which can return early: leaving it
	// behind lets logHK requeue the package and undo that check's escalation.
	if _, err := os.Stat(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log")); err == nil {
		err := os.Remove(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log"))
		if err != nil {
			return time.Since(start), fmt.Errorf("error removing log: %w", err)
		}
	}

	// Never publish an artifact that links a soname the repos no longer carry.
	// The mirror's own dependency closure can be transiently unsatisfiable at
	// the ABI level, and version comparison cannot see it: depends carry plain
	// pkgnames, so nothing upstream says which soname a build needs.
	//
	// The previous baseline is kept unless a new one is computed, so a transient
	// read error cannot disarm the housekeeping check for this package.
	sonames := p.DBPackage.Sonames
	if scan, sErr := scanPackagesSonames(p.runtimePkgFiles()); sErr != nil {
		log.Warningf("[P] %s->%s error reading sonames: %v", p.FullRepo, p.Pkgbase, sErr)
	} else {
		buildManager.alpmMutex.Lock()
		provided := buildManager.sonameIndex
		stale, staleErr := staleAgainstDeps(scan, p.srcinfoDepends(), alpmHandle, provided)
		buildManager.alpmMutex.Unlock()

		switch {
		case staleErr != nil:
			log.Warningf("[P] %s->%s error resolving sonames: %v", p.FullRepo, p.Pkgbase, staleErr)
		case len(stale) > 0:
			reason := SkipReasonSonameMismatch + mismatchStrings(stale)
			log.Warningf("[P] discarding %s->%s->%s: %s", p.FullRepo, p.Pkgbase, p.Version, reason)
			if err := p.discardArtifacts(); err != nil {
				return time.Since(start), fmt.Errorf("error discarding artifacts: %w", err)
			}

			// normally the library is mid-transition and the next cycle's chroot
			// refresh resolves it, so delay and retry. If a rebuild already
			// failed to resolve it, stop: retrying costs a full compile per
			// cycle, and failed both surfaces it and lets housekeeping purge
			// whatever stale version is still published.
			status := dbpackage.StatusDelayed
			if strings.HasPrefix(priorSkipReason, SkipReasonSonameMismatch) {
				log.Warningf("[P] %s->%s rebuild did not resolve soname mismatch, marking failed",
					p.FullRepo, p.Pkgbase)
				status = dbpackage.StatusFailed
			}
			p.DBPackage.Update().SetStatus(status).SetSkipReason(reason).ExecX(ctx)
			return time.Since(start), ErrorNotEligible
		default:
			sonames = scan.trackable(provided)
		}
	}

	// after the soname gate, so a discarded artifact is not inspected, and before
	// the row is marked built. Reports without discarding: a surviving bound means
	// the artifact is what ALHP ships today, so withholding it would cost users a
	// package to fix nothing
	if n := p.checkArtifactBounds(); n > 0 {
		buildManager.metrics.defeatedBoundEntries.WithLabelValues(p.FullRepo, "artifact").Add(float64(n))
	}

	updatePkg := p.DBPackage.Update().
		SetSonames(sonames).
		SetStatus(dbpackage.StatusBuilt).
		SetLto(dbpackage.LtoEnabled).
		SetBuildTimeStart(start).
		SetLastVersionBuild(p.Version).
		SetTagRev(p.State.TagRev).
		SetMaxRss(peakMem).
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

// recordFailedBuild writes the build log to the log directory and marks the package
// as failed. skipReason is kept for operator visibility; an empty value clears it.
func (p *ProtoPackage) recordFailedBuild(ctx context.Context, start time.Time, buildLog, skipReason string) error {
	if err := os.MkdirAll(filepath.Join(conf.Basedir.Repo, logDir, p.March), 0o755); err != nil {
		return fmt.Errorf("error creating logdir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(conf.Basedir.Repo, logDir, p.March, p.Pkgbase+".log"), //nolint:gosec
		[]byte(strings.ToValidUTF8(buildLog, "")), 0o644); err != nil {
		return fmt.Errorf("error writing to logdir: %w", err)
	}

	// LastVersionBuild is not cleared here, unlike the resource stats below: it
	// records the last version that published, not anything about this build,
	// and seedBuildNo recovers a purged row from it
	updatePkg := p.DBPackage.Update().
		SetStatus(dbpackage.StatusFailed).
		SetBuildTimeStart(start).
		ClearMaxRss().
		ClearIoOut().
		ClearIoIn().
		ClearUTime().
		ClearSTime().
		SetTagRev(p.State.TagRev)

	if skipReason == "" {
		updatePkg.ClearSkipReason()
	} else {
		updatePkg.SetSkipReason(skipReason)
	}

	updatePkg.ExecX(ctx)
	return nil
}

// srcinfoDepends lists every dependency the PKGBUILD declares, across the
// pkgbase and all split packages, with duplicates removed. Used to decide which
// sonames are supposed to be resolved through the repos.
func (p *ProtoPackage) srcinfoDepends() []string {
	if p.Srcinfo == nil {
		return nil
	}

	deps := append(packages2slice(p.Srcinfo.Depends), packages2slice(p.Srcinfo.MakeDepends)...)
	for i := range p.Srcinfo.Packages {
		deps = append(deps, packages2slice(p.Srcinfo.Packages[i].Depends)...)
	}

	// an override emptied in a package_() function carries a sentinel value
	deps = slices.DeleteFunc(deps, func(dep string) bool {
		return dep == srcinfo.EmptyOverride
	})
	slices.Sort(deps)
	return slices.Compact(deps)
}

// runtimePkgFiles are the built packages whose linkage matters. Debug packages
// carry separate debug objects with no dynamic section, so scanning them only
// buffers hundreds of MB for nothing.
func (p *ProtoPackage) runtimePkgFiles() []string {
	files := make([]string, 0, len(p.PkgFiles))
	for _, file := range p.PkgFiles {
		if Package(file).IsDebug() {
			continue
		}
		files = append(files, file)
	}
	return files
}

// discardArtifacts removes the built packages from the holding dir so
// movePackagesLive cannot publish them, and clears PkgFiles so IsBuilt no
// longer reports the package as built.
func (p *ProtoPackage) discardArtifacts() error {
	for _, file := range p.PkgFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(file + ".sig"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	p.PkgFiles = nil
	return nil
}

func (p *ProtoPackage) setupBuildDir(ctx context.Context) (string, error) {
	// Guarded at the sink, not only where Version is assigned: there are three
	// assignment sites and genQueue's runs before build()'s check, so a UseLatest
	// package reaches here with a version straight from an HTTP-fetched .SRCINFO.
	// This is where it becomes a path that root-run helpers are handed.
	if err := checkMetaName("pkgbase", p.Pkgbase); err != nil {
		return "", err
	}
	if err := checkMetaName("version", p.Version); err != nil {
		return "", err
	}

	// treeDir, not buildDir: a local of that name shadows the const this Join
	// needs, and the two read identically at every use below
	treeDir := filepath.Join(conf.Basedir.Work, buildDir, p.March, p.Pkgbase+"-"+p.Version)

	err := cleanBuildDir(treeDir, "")
	if err != nil {
		return "", fmt.Errorf("removing old builddir failed: %w", err)
	}

	err = os.MkdirAll(treeDir, 0o755)
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

	if err := retry.Do(ctx, gr, func(ctx context.Context) error {
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", p.cloneBranch(), //nolint:gosec
			fmt.Sprintf("https://gitlab.archlinux.org/archlinux/packaging/packages/%s.git", gitlabPath), treeDir)
		res, err := cmd.CombinedOutput()
		log.Debug(string(res))
		if err != nil {
			return retry.RetryableError(err)
		}
		return nil
	}); err != nil {
		return "", err
	}
	p.Pkgbuild = filepath.Join(treeDir, "PKGBUILD")

	return treeDir, nil
}

func (p *ProtoPackage) repoVersion() (string, error) {
	if err := p.findPkgFiles(); err != nil {
		return "", err
	}

	if len(p.PkgFiles) == 0 {
		return "", errors.New("not found")
	}

	fNameSplit := strings.Split(p.PkgFiles[0], "-")
	return fNameSplit[len(fNameSplit)-3] + "-" + fNameSplit[len(fNameSplit)-2], nil
}

// nextBuildNo picks the build number p.Version gets published under, and the
// high-water version base that follows from it.
//
// A published filename must never be reused: mirrors and pacman caches treat it
// as immutable, so different content under a name someone already fetched fails
// signature verification for them with nothing to explain why. Two builds of one
// upstream version are otherwise identical, so the build number is all that
// keeps the name unique.
//
// Restarting at 1 is safe only above everything this row ever built, where no
// filename can exist yet, and the mark only rises, so a base can trip the reset
// at most once. Everything else continues a counter that only moves forward,
// which is what covers upstream walking a version back and then forward again: a
// drift build from main publishes 1.0-2.1, housekeeping purges it because
// upstream never released -2, and upstream then releases -2 for real.
//
// Bases rather than versions, because increasePkgRel replaces the trailing
// pkgrel component instead of appending to it, so upstream pkgrel 1 and 1.1 both
// publish into 1.N. Comparing full versions lets upstream's own fractional bump
// trip the reset and land the counter back inside numbers 1.N already used.
//
// The bump past upstream's own build number keeps a package built from pkgrel
// 1.4 outranking upstream's 1.4 rather than tying with it.
//
// p.Version still carries upstream's pkgrel here, increasePkgRel has not run.
func (p *ProtoPackage) nextBuildNo() (buildNo int, maxVersionBase string, err error) {
	maxVersionBase = p.DBPackage.MaxVersionBase
	buildNo = p.DBPackage.BuildNo + 1
	if versionBase := upstreamVersion(p.Version); maxVersionBase == "" ||
		alpm.VerCmp(versionBase, maxVersionBase) > 0 {
		maxVersionBase = versionBase
		buildNo = 1
	}

	_, upstreamBuildNo, err := splitPkgRel(p.Srcinfo.Pkgrel)
	if err != nil {
		return 0, "", err
	}
	if buildNo <= upstreamBuildNo {
		buildNo = upstreamBuildNo + 1
	}

	return buildNo, maxVersionBase, nil
}

// increasePkgRel rewrites the PKGBUILD's pkgrel, and p.Version with it, so the
// build publishes under build number buildNo. buildNo is the trailing pkgrel
// component verbatim, so it has to clear any build number upstream's own pkgrel
// carries; nextBuildNo is what guarantees that.
func (p *ProtoPackage) increasePkgRel(ctx context.Context, buildNo int) error {
	if p.Srcinfo == nil {
		err := p.genSrcinfo(ctx)
		if err != nil {
			return fmt.Errorf("error generating srcinfo: %w", err)
		}
	}

	if p.Version == "" {
		p.Version = constructVersion(p.Srcinfo.Pkgver, p.Srcinfo.Pkgrel, p.Srcinfo.Epoch)
		if err := checkMetaName("version", p.Version); err != nil {
			return err
		}
	}

	pkgRelBase, upstreamBuildNo, err := splitPkgRel(p.Srcinfo.Pkgrel)
	if err != nil {
		return err
	}
	if buildNo <= upstreamBuildNo {
		return fmt.Errorf("build number %d does not clear upstream pkgrel %q", buildNo, p.Srcinfo.Pkgrel)
	}
	newPkgRel := pkgRelBase + "." + strconv.Itoa(buildNo)

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

	nStr := rePkgRel.ReplaceAllLiteralString(string(fStr), "pkgrel="+newPkgRel)
	versionSplit := strings.Split(p.Version, "-")
	versionSplit[len(versionSplit)-1] = newPkgRel
	p.Version = strings.Join(versionSplit, "-")

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

	return nil
}

// keyservers are all queried, in order, rather than stopping at the first that
// succeeds. A zero exit says nothing about whether a key arrived: gpg exits zero
// for one it fetched but skipped, which is what a server holding a key without
// user IDs returns, and a server can also answer with a copy predating a signing
// subkey rotation. In both cases the next server may hold what the previous one
// did not, and neither is visible from the exit status.
//
// hkps rather than a bare host, which gpg reads as hkp on port 11371 in the
// clear. The fingerprint binding means an on-path answer cannot substitute a
// key, but it can withhold one or serve a copy predating a rotation.
var keyservers = []string{"hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com"}

// importKeys fetches the PGP keys makepkg will verify the sources against, and
// reports the ones no keyserver could supply.
//
// The fetch is unconditional. validpgpkeys names primary fingerprints, and a
// primary already in the keyring resolves whether or not the signing subkey
// upstream has rotated to is under it, so fetching only the keys that fail to
// resolve would never pick a rotation up. What the resolve check decides is
// whether to report: a keyserver being unreachable does not matter for a package
// whose keys are all present, and saying so every time buries the case where one
// is not.
//
// A subkey absent from every keyserver's copy stays invisible here, because
// nothing names it. makepkg's own verification is what catches that.
func (p *ProtoPackage) importKeys(ctx context.Context) error {
	if p.Srcinfo == nil {
		if err := p.genSrcinfo(ctx); err != nil {
			return fmt.Errorf("error generating srcinfo: %w", err)
		}
	}

	if len(p.Srcinfo.ValidPGPKeys) == 0 {
		return nil
	}

	var errs []error
	for _, keyserver := range keyservers {
		if err := recvKeys(ctx, keyserver, p.Srcinfo.ValidPGPKeys); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", keyserver, err))
		}
	}

	// a shutdown fails every probe below, which would report each declared key as
	// absent for whatever was in flight at the time
	if ctx.Err() != nil {
		return ctx.Err()
	}

	absent := absentKeys(ctx, p.Srcinfo.ValidPGPKeys)
	if len(absent) == 0 {
		return nil
	}

	// gpg exits zero for a key it fetched but did not import, such as one a
	// keyserver serves without a user ID, so errs can be empty while keys are
	// still absent
	return errors.Join(
		fmt.Errorf("keys %v absent after trying every keyserver", absent),
		errors.Join(errs...),
	)
}

// recvKeysTimeout bounds one keyserver round. dirmngr does not fall back to
// another address when a keyserver resolves to one the host cannot reach, so
// without a deadline an unreachable server holds the build slot.
const recvKeysTimeout = 2 * time.Minute

// recvKeys pulls keys from one keyserver under a deadline.
func recvKeys(ctx context.Context, keyserver string, keys []string) error {
	ctx, cancel := context.WithTimeout(ctx, recvKeysTimeout)
	defer cancel()

	// -- for the same reason absentKeys uses it: these are upstream text, and gpg
	// has no positional boundary, so an option-shaped entry is read as an option.
	// One gpg accepts makes the round exit zero having fetched nothing, and one
	// taking an argument swallows the next declared key
	args := make([]string, 0, 4+len(keys))
	args = append(args, "--keyserver", keyserver, "--recv-keys", "--")
	args = append(args, keys...)

	cmd := exec.CommandContext(ctx, "gpg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = killProcessGroup(cmd)
	cmd.WaitDelay = time.Second

	res, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(res)))
	}

	return nil
}

// absentKeys returns the subset of keys the local keyring cannot resolve. An id
// naming a subkey resolves through the primary it hangs off, so resolving says
// only that the keyring holds that key material: an entry naming a primary
// resolves while a signing subkey added to it upstream is still absent, and
// makepkg cannot verify a source signed by a subkey the keyring lacks. A revoked
// or an expired key resolves too, and makepkg accepts only the expired one.
func absentKeys(ctx context.Context, keys []string) []string {
	var absent []string
	for _, key := range keys {
		// -- because the key is upstream text: without it an option-shaped entry
		// is read as a gpg option, and one gpg accepts exits zero and reads as a
		// key that is present
		if err := exec.CommandContext(ctx, "gpg", "--batch", "--list-keys", "--", key).Run(); err != nil {
			absent = append(absent, key)
		}
	}

	return absent
}

func (p *ProtoPackage) isAvailable(ctx context.Context, h *alpm.Handle) bool {
	dbs, err := h.SyncDBs()
	if err != nil {
		return false
	}

	buildManager.alpmMutex.Lock()
	defer buildManager.alpmMutex.Unlock()

	var pkg alpm.IPackage
	switch {
	case p.Srcinfo != nil:
		pkg, err = dbs.FindSatisfier(p.Srcinfo.Packages[0].Pkgname)
	case p.DBPackage != nil && len(p.DBPackage.Packages) > 0:
		pkg, err = dbs.FindSatisfier(p.DBPackage.Packages[0])
	default:
		cmd := exec.CommandContext(ctx, "unbuffer", "pacsift", "--exact", "--base="+p.Pkgbase, "--repo="+p.Repo.String(), //nolint:gosec
			"--sysroot="+filepath.Join(conf.Basedir.Work, chrootDir, pristineChroot))
		var res []byte
		res, err = cmd.Output()
		if err != nil {
			// pacsift exiting non-zero is a routine answer about one package, but
			// failing to run at all is a host problem that blocks every package
			// from ever being queued, and callers act on false destructively
			var exitErr *exec.ExitError
			switch {
			case ctx.Err() != nil:
				log.Debugf("pacsift canceled for %s: %v", p.Pkgbase, err)
			case errors.As(err, &exitErr):
				log.Debugf("pacsift found nothing for %s: %v", p.Pkgbase, err)
			default:
				log.Warningf("unable to run pacsift for %s: %v", p.Pkgbase, err)
			}
			return false
		}

		var splitPkgs []string
		for line := range strings.SplitSeq(strings.TrimSpace(string(res)), "\n") {
			// pacsift prints "<repo>/<pkgname>"; anything else is not a package
			// and must not reach SetPackages, which would poison the row
			_, name, ok := strings.Cut(line, "/")
			if !ok || name == "" {
				continue
			}
			splitPkgs = append(splitPkgs, name)
		}
		if len(splitPkgs) == 0 {
			log.Debugf("pacsift found nothing for %s", p.Pkgbase)
			return false
		}

		if p.DBPackage != nil {
			p.DBPackage, err = p.DBPackage.Update().SetPackages(splitPkgs).Save(ctx)
			if err != nil {
				return false
			}
		}
		pkg, err = dbs.FindSatisfier(splitPkgs[0])
	}
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

	p.SyncPkg = pkg
	return true
}

// cloneBranch returns the git ref to use when cloning the upstream
// packaging repo. The default ref is the tag recorded in state.git;
// UseLatest overrides that to track the package repo's main branch
// (used when state.git lags real upstream).
func (p *ProtoPackage) cloneBranch() string {
	if p.UseLatest {
		return upstreamDefaultGitBranch
	}
	return p.State.TagVer
}

func (p *ProtoPackage) GitVersion(h *alpm.Handle) (string, error) {
	if p.Pkgbase == "" {
		return "", errors.New("invalid arguments")
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

		for _, stateFile := range fStateFiles {
			repo, _, _, err := stateFileMeta(stateFile)
			if err != nil {
				continue
			}

			if iPackage.DB().Name() == repo {
				fStateFiles = []string{stateFile}
				break
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

// printSrcinfoTimeout bounds a --printsrcinfo run. makepkg sources the PKGBUILD
// to produce it, so upstream top-level code runs here, and a package that blocks
// there would hold its build slot forever: the stall and silence windows watch
// the build command, not this.
//
// Generous because real packages are slower than they look: most print in a
// couple of seconds, but mesa and linux-firmware take about 15s and
// gst-plugins-rs, which carries bounds this feature exists to rewrite, has been
// measured between 52s and 93s on an idle host. A build machine runs several
// builds at once, so the ceiling has to clear that by a wide margin or the
// rewrite lands or not depending on load. This still bounds the hang, two orders
// of magnitude under a build timeout.
const printSrcinfoTimeout = 5 * time.Minute

// printSrcinfo returns the srcinfo makepkg resolves from pkgbuild, under a
// deadline because producing it executes upstream bash.
func printSrcinfo(ctx context.Context, pkgbuild string) (*srcinfo.Srcinfo, error) {
	ctx, cancel := context.WithTimeout(ctx, printSrcinfoTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "makepkg", "--printsrcinfo", "-p", filepath.Base(pkgbuild)) //nolint:gosec
	cmd.Dir = filepath.Dir(pkgbuild)
	// the whole group, since the PKGBUILD's own top-level code may have forked:
	// killing the direct child alone leaves those behind on every deadline, one
	// leak per attempt for a package that is retried every cycle
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = killProcessGroup(cmd)
	// a child still holding the pipe must not outlive the deadline, since
	// CombinedOutput waits on the pipe rather than on the process
	cmd.WaitDelay = time.Second

	res, err := cmd.CombinedOutput()
	if err != nil {
		// the exit status of a killed makepkg is "signal: killed", which says
		// nothing about the package. Surface the context error instead, so callers
		// can tell a host that ran out of time from a PKGBUILD that cannot parse
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("makepkg --printsrcinfo did not finish (PKGBUILD: %s): %w", pkgbuild, ctxErr)
		}

		return nil, fmt.Errorf("makepkg exit non-zero (PKGBUILD: %s): %w (%s)", pkgbuild, err, string(res))
	}

	return srcinfo.Parse(string(res))
}

func (p *ProtoPackage) genSrcinfo(ctx context.Context) error {
	if p.Srcinfo != nil {
		return nil
	}

	info, err := printSrcinfo(ctx, p.Pkgbuild)
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
		return errors.New("unable to find pkgfiles without dbpkg or srcinfo present")
	}

	var realPkgs []string
	if p.DBPackage != nil {
		realPkgs = append(realPkgs, p.DBPackage.Packages...)
	} else {
		for i := range p.Srcinfo.Packages {
			realPkgs = append(realPkgs, p.Srcinfo.Packages[i].Pkgname)
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

func (p *ProtoPackage) toDBPackage(ctx context.Context, create bool) error {
	if p.DBPackage != nil {
		return nil
	}

	dbPkg, err := db.DBPackage.Query().Where(
		dbpackage.Pkgbase(p.Pkgbase),
		dbpackage.March(p.March),
		dbpackage.RepositoryEQ(p.Repo),
	).Only(ctx)
	if err != nil && ent.IsNotFound(err) && create {
		dbPkg, err = db.DBPackage.Create().
			SetPkgbase(p.Pkgbase).
			SetMarch(p.March).
			SetRepository(p.Repo).
			Save(ctx)
		if err != nil {
			return err
		}
	} else if err != nil && !ent.IsNotFound(err) {
		return err
	}

	p.DBPackage = dbPkg
	return nil
}

func (p *ProtoPackage) exists(ctx context.Context) (bool, error) {
	dbPkg, err := db.DBPackage.Query().Where(dbpackage.And(dbpackage.Pkgbase(p.Pkgbase), dbpackage.March(p.March))).Exist(ctx)
	if err != nil {
		return false, err
	}

	return dbPkg, nil
}

func (p *ProtoPackage) isMirrorLatest(h *alpm.Handle) (latest bool, foundPkg *alpm.Package, version string, err error) {
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

		svn2gitVer, err := (&ProtoPackage{ //nolint:exhaustruct
			Pkgbase: pkg.Base(),
			March:   p.March,
		}).GitVersion(h)
		if err != nil {
			return false, nil, "", err
		} else if svn2gitVer == "" {
			return false, nil, "", errors.New("no svn2git version")
		}

		if alpm.VerCmp(svn2gitVer, pkg.Version()) > 0 {
			switch v := pkg.(type) {
			case *alpm.Package:
				return false, v, svn2gitVer, nil
			default:
				return false, nil, "", fmt.Errorf("invalid package type: %T", pkg)
			}
		}
	}

	return true, nil, "", nil
}

func (p *ProtoPackage) PkgbaseEquals(p2 *ProtoPackage, marchSensitive bool) bool {
	return (marchSensitive && (p.Pkgbase == p2.Pkgbase && p.FullRepo == p2.FullRepo)) || (!marchSensitive && p.Pkgbase == p2.Pkgbase)
}

func (p *ProtoPackage) IsBuilt() (bool, error) {
	if p.DBPackage == nil {
		return false, nil
	}

	matches, err := filepath.Glob(filepath.Join(conf.Basedir.Work, waitingDir, p.FullRepo, p.DBPackage.Packages[0]+"*-x86_64.pkg.tar.zst"))
	if err != nil {
		return false, err
	}

	return len(matches) > 0, nil
}
