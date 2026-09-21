package main

import (
	"context"

	"github.com/Jguer/go-alpm/v2"
	log "github.com/sirupsen/logrus"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
)

// Detection of upstream conflicts/replaces entries our pkgrel bump defeats.
//
// When upstream merges a package away, the surviving package carries the
// transition in its own metadata: geocode-glib declares
// `replaces=('geocode-glib-2<=3.26.4-5')` plus a conflict on the same bound, so
// one -Syu drops the old package and installs the new one without the user
// having to know anything happened. increasePkgRel publishes our copy of the old
// package as 3.26.4-5.1, which is above that bound, so neither entry matches
// what is installed. pacman leaves the old package in place, the transaction
// dies on file conflicts, and the user is left to work out that a `-Rdd` of the
// merged-away package is what unblocks their upgrade.
//
// versionbound_rewrite.go fixes this at the source for the packages it can prove
// the edit correct for, so what is left to report here is what no rewrite can
// reach: a replacing package that is arch=any never passes through ALHP to be
// rewritten at all, and a package we published before the rewrite existed keeps
// its bumped version until upstream moves it. The condition is rare and the
// manual step is safe once known, so what is actually missing is knowing it
// happened in time to say so.
//
// Only conflicts and replaces are indexed. An upper-bounded `depends` breaks the
// same way, but pacman names the unsatisfied dependency itself, which needs no
// help from here.

// versionBound is one upper-bounded conflicts/replaces entry together with the
// package declaring it. The constrained name is the boundIndex key.
type versionBound struct {
	source  string
	kind    string
	mod     alpm.DepMod
	version string
}

// String renders the entry the way the PKGBUILD spells it, minus the
// constrained name.
func (v versionBound) String() string {
	return v.kind + " " + v.mod.String() + v.version + " (" + v.source + ")"
}

// boundIndex maps a constrained pkgname to every upper-bounded conflicts or
// replaces entry the sync DBs declare against it.
type boundIndex map[string][]versionBound

// collectVersionBounds builds the index from all registered sync DBs.
// Callers must hold buildManager.alpmMutex.
func collectVersionBounds(h *alpm.Handle) (boundIndex, error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return nil, err
	}

	bounds := make(boundIndex)
	for _, db := range dbs.Slice() {
		err := db.PkgCache().ForEach(func(pkg alpm.IPackage) error {
			bounds.add(pkg, "conflicts", pkg.Conflicts())
			bounds.add(pkg, "replaces", pkg.Replaces())
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return bounds, nil
}

// add indexes the upper-bounded entries of one dependency list.
func (b boundIndex) add(pkg alpm.IPackage, kind string, deps alpm.IDependList) {
	for _, dep := range deps.Slice() {
		if bound, ok := boundFrom(pkg.Name(), kind, dep); ok {
			b[dep.Name] = append(b[dep.Name], bound)
		}
	}
}

// boundFrom converts one dependency entry into an indexable bound, reporting
// false for the entries our build number cannot defeat.
func boundFrom(source, kind string, dep alpm.Depend) (versionBound, bool) {
	// an entry carrying no version has nothing to compare against at all
	if dep.Version == "" {
		return versionBound{}, false
	}

	switch dep.Mod {
	case alpm.DepModEq, alpm.DepModLE, alpm.DepModLT:
		return versionBound{
			source:  source,
			kind:    kind,
			mod:     dep.Mod,
			version: dep.Version,
		}, true
	case alpm.DepModAny, alpm.DepModGE, alpm.DepModGT:
		// increasePkgRel only ever raises a version, so an entry upstream
		// satisfies with >= or > stays satisfied once the build number is
		// appended, and DepModAny constrains no version in the first place
		return versionBound{}, false
	default:
		return versionBound{}, false
	}
}

// satisfiesBound reports whether version meets the entry, using the comparison
// pacman itself applies. A bound carrying no pkgrel compares only as far as
// pkgver, so our build number cannot move the result either way.
func satisfiesBound(version string, mod alpm.DepMod, bound string) bool {
	cmp := alpm.VerCmp(version, bound)
	switch mod {
	case alpm.DepModEq:
		return cmp == 0
	case alpm.DepModLE:
		return cmp <= 0
	case alpm.DepModLT:
		return cmp < 0
	case alpm.DepModGE:
		return cmp >= 0
	case alpm.DepModGT:
		return cmp > 0
	case alpm.DepModAny:
		return true
	default:
		// a comparison pacman does not define is not one we can judge a version
		// against, and reporting on a guess would be worse than staying quiet
		return true
	}
}

// violatedBy returns the entries constraining pkgname that version breaks and
// the version it was built from would have met. That difference is the whole
// test: an entry upstream's own version already violates is upstream's business,
// and reporting it would bury the ones we caused under entries left in the repos
// from renames years ago.
//
// upstreamVersion strips one dot-separated component, so an upstream pkgrel
// carrying a dot of its own is stripped back further than the build number
// alone. The result compares low, which can only add a report, never drop one,
// and needs a bound written against a fractional upstream pkgrel to happen at
// all.
func (b boundIndex) violatedBy(pkgname, version string) []versionBound {
	bounds := b[pkgname]
	if len(bounds) == 0 {
		return nil
	}

	// nothing we appended, so nothing we can be responsible for
	upstream := upstreamVersion(version)
	if upstream == version {
		return nil
	}

	var broken []versionBound
	for _, bound := range bounds {
		if !satisfiesBound(version, bound.mod, bound.version) &&
			satisfiesBound(upstream, bound.mod, bound.version) {
			broken = append(broken, bound)
		}
	}
	return broken
}

// reportDefeatedBounds logs every entry our published version of pkgname
// defeats and returns how many there were, which is what the caller adds to the
// entry counter.
//
// Warning rather than Info: the upgrade path for anyone with this package
// installed is broken until they are told which package to remove, and nothing
// downstream of here can work that out on its own.
func reportDefeatedBounds(bounds boundIndex, fullRepo, pkgname, version string) int {
	broken := bounds.violatedBy(pkgname, version)
	for _, bound := range broken {
		log.Warningf("[HK/%s] %s %s is above upstream %s, so pacman will not act on it; "+
			"an upgrade needs `pacman -Rdd %s` first", fullRepo, pkgname, version, bound, pkgname)
	}
	return len(broken)
}

// boundHK reports published packages whose version defeats an upstream
// conflicts or replaces entry written against them, so a merge upstream can be
// announced before users run into the file conflicts it causes.
//
// Runs after the per-repo passes, not inside them: a package that left the repos
// this cycle no longer has a row to find here, and is reported from its artifact
// at the point the row is deleted instead.
//
// Counts rather than calling reportDefeatedBounds, because this condition holds
// every cycle until the declaring package next rebuilds, and a per-entry warning
// on that shape repeats forever. The purge and artifact sites are the ones that
// fire once and carry the actionable pacman -Rdd line; here one count per repo
// and the gauge carry the trend.
func boundHK(ctx context.Context) error {
	bounds := buildManager.bounds()

	// seeded so a repo that clears its last violation reports the zero. A gauge
	// child persists once set, so leaving it absent pins the last reading
	defeated := make(map[string]int, len(repos))
	for _, fullRepo := range repos {
		defeated[fullRepo] = 0
	}

	dbPkgs, err := db.DBPackage.Query().Where(
		dbpackage.RepoVersionNotNil(),
		dbpackage.RepoVersionNEQ(""),
	).All(ctx)
	if err != nil {
		return err
	}

	for _, dbPkg := range dbPkgs {
		fullRepo := dbPkg.Repository.String() + "-" + dbPkg.March
		for _, pkgname := range dbPkg.Packages {
			if len(bounds.violatedBy(pkgname, dbPkg.RepoVersion)) > 0 {
				defeated[fullRepo]++
			}
		}
	}

	for fullRepo, n := range defeated {
		buildManager.metrics.defeatedBoundPackages.WithLabelValues(fullRepo).Set(float64(n))
		if n > 0 {
			log.Infof("[HK/%s] %d published packages above an upstream conflicts/replaces bound", fullRepo, n)
		}
	}
	return nil
}
