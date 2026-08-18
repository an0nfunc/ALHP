package main

import (
	"archive/tar"
	"bufio"
	"context"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"errors"
	"fmt"
	"github.com/klauspost/compress/zstd"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"strings"
)

type Package string

// Name returns package's name
func (pkg Package) Name() string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	return strings.Join(fNameSplit[:len(fNameSplit)-3], "-")
}

// IsDebug returns whether pkg carries debug symbols rather than the package
// itself. Debug packages are tracked separately and never enter a repo db.
func (pkg Package) IsDebug() bool {
	return strings.HasSuffix(pkg.Name(), debugSuffix)
}

// MArch returns package's march
func (pkg Package) MArch() *string {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	res := strings.Join(strings.Split(splitPath[len(splitPath)-4], "-")[1:], "-")
	return &res
}

// Repo returns package's dbpackage.Repository
func (pkg Package) Repo() dbpackage.Repository {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	return dbpackage.Repository(strings.Split(splitPath[len(splitPath)-4], "-")[0])
}

// FullRepo returns package's dbpackage.Repository-march
func (pkg Package) FullRepo() *string {
	splitPath := strings.Split(string(pkg), string(filepath.Separator))
	return &splitPath[len(splitPath)-4]
}

// Version returns version extracted from package
func (pkg Package) Version() string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	return strings.Join(fNameSplit[len(fNameSplit)-3:len(fNameSplit)-1], "-")
}

// Arch returns package's Architecture
func (pkg Package) Arch() *string {
	fNameSplit := strings.Split(filepath.Base(string(pkg)), "-")
	fNameSplit = strings.Split(fNameSplit[len(fNameSplit)-1], ".")
	return &fNameSplit[0]
}

// HasValidSignature returns if package has valid detached signature file.
// Signatures made with a now-expired key (EXPKEYSIG) or with an expired
// signature timestamp (EXPSIG) are reported invalid even though gpg exits 0 for them.
// KEYEXPIRED is intentionally not matched because GnuPG may emit it for unrelated
// expired keys in the keyring, not just the signing key of this signature.
func (pkg Package) HasValidSignature() (bool, error) {
	cmd := exec.Command("gpg", "--verify", "--status-fd", "1", string(pkg)+".sig", string(pkg)) //nolint:gosec
	res, err := cmd.CombinedOutput()
	switch {
	case cmd.ProcessState.ExitCode() == 2 || cmd.ProcessState.ExitCode() == 1:
		return false, nil
	case cmd.ProcessState.ExitCode() == 0:
		s := string(res)
		if strings.Contains(s, "[GNUPG:] EXPKEYSIG ") ||
			strings.Contains(s, "[GNUPG:] EXPSIG ") {
			return false, nil
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("error checking signature: %w (%s)", err, res)
	}

	return false, nil
}

// pkginfoName is the pacman metadata member carrying pkgbase.
const pkginfoName = ".PKGINFO"

// maxPkginfoMembers caps how far into an archive we look for .PKGINFO. makepkg
// writes it first, so anything beyond the first handful of members means the
// archive is not one of ours and we would otherwise walk a whole package to
// find that out.
const maxPkginfoMembers = 8

// errNoPkgbase reports an archive that carries no usable pkgbase. makepkg emits
// pkgbase unconditionally and defaults it to the first pkgname, so this means a
// corrupt or foreign archive rather than a package we could guess a base for.
var errNoPkgbase = errors.New("no pkgbase in " + pkginfoName)

// Pkgbase reads pkgbase out of the package's .PKGINFO. Unlike Name(), which is
// derived from the filename, this is authoritative: it is what lets a pkgname
// claimed by more than one db row be attributed to the row that actually owns
// it after an upstream pkgname move.
func (pkg Package) Pkgbase() (string, error) {
	path := string(pkg)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("error opening %s: %w", path, err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for range maxPkginfoMembers {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error reading %s: %w", path, err)
		}
		if hdr.Name != pkginfoName {
			continue
		}

		// .PKGINFO is a handful of "key = value" lines; bufio.Scanner's default
		// 64KB line cap is well above anything makepkg writes.
		scanner := bufio.NewScanner(tr)
		for scanner.Scan() {
			base, ok := strings.CutPrefix(scanner.Text(), "pkgbase = ")
			if !ok {
				continue
			}
			if base = strings.TrimSpace(base); base != "" {
				return base, nil
			}
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading %s from %s: %w", pkginfoName, path, err)
		}
		break
	}

	return "", fmt.Errorf("%s: %w", path, errNoPkgbase)
}

// DBPackage returns ent.DBPackage for package
func (pkg Package) DBPackage(ctx context.Context, db *ent.Client) (*ent.DBPackage, error) {
	return pkg.DBPackageIsolated(ctx, *pkg.MArch(), pkg.Repo(), db)
}

// claimsPkgname matches rows whose packages array claims pkgname within one
// march and repository. Shared by DBPackageIsolated and resolveOwner so the two
// can never disagree about which rows are candidates.
func claimsPkgname(pkgname, march string, repo dbpackage.Repository) func(*sql.Selector) {
	return func(s *sql.Selector) {
		s.Where(
			sql.And(
				sqljson.ValueContains(dbpackage.FieldPackages, pkgname),
				sql.EQ(dbpackage.FieldMarch, march),
				sql.EQ(dbpackage.FieldRepository, repo)),
		)
	}
}

// DBPackageIsolated returns ent.DBPackage like DBPackage, but not relying on the path for march and repo.
// More than one row can claim a pkgname while a stale row lags an upstream pkgname move, in which case
// this returns *ent.NotSingularError; callers that must not lose the package use resolveOwner instead.
func (pkg Package) DBPackageIsolated(ctx context.Context, march string, repo dbpackage.Repository, db *ent.Client) (*ent.DBPackage, error) {
	dbPkg, err := db.DBPackage.Query().Where(claimsPkgname(pkg.Name(), march, repo)).Only(ctx)
	if ent.IsNotFound(err) {
		log.Debugf("not found in database: %s", pkg.Name())
		return nil, err
	} else if err != nil {
		return nil, err
	}
	return dbPkg, nil
}

// errAmbiguousOwner reports a pkgname that no single row can be said to own.
var errAmbiguousOwner = errors.New("cannot attribute package to a single db entry")

// resolveByPkgbase picks the row that actually owns an artifact when more than one
// row's packages array still claims its pkgname, which happens while a stale row
// lags an upstream pkgname move. It errors rather than guessing: (pkgbase, march,
// repository) carries no unique constraint, so a caller that deletes or purges on
// the result must not act on an arbitrary pick.
func resolveByPkgbase(candidates []*ent.DBPackage, pkgbase string) (*ent.DBPackage, error) {
	var match *ent.DBPackage
	for _, c := range candidates {
		if c.Pkgbase != pkgbase {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("%w: %d entries with pkgbase %s", errAmbiguousOwner, len(candidates), pkgbase)
		}
		match = c
	}
	if match == nil {
		return nil, fmt.Errorf("%w: none of %d entries has pkgbase %s", errAmbiguousOwner, len(candidates), pkgbase)
	}
	return match, nil
}

// resolveOwner re-resolves an artifact whose pkgname is claimed by more than one row,
// using the pkgbase recorded in its own .PKGINFO. It queries with All rather than Only
// so that no *ent.NotFoundError can escape: callers treat that as "orphan, safe to
// delete", and a failure to attribute a good build must never mean that.
func resolveOwner(ctx context.Context, pkg Package, march string, repo dbpackage.Repository, db *ent.Client) (*ent.DBPackage, error) {
	pkgbase, err := pkg.Pkgbase()
	if err != nil {
		return nil, err
	}

	candidates, err := db.DBPackage.Query().Where(claimsPkgname(pkg.Name(), march, repo)).All(ctx)
	if err != nil {
		return nil, err
	}
	return resolveByPkgbase(candidates, pkgbase)
}
