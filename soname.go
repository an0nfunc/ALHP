package main

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Jguer/go-alpm/v2"
	"github.com/klauspost/compress/zstd"
)

// Detection of packages linked against a soname version that no longer exists.
//
// Upstream Arch can publish a package that was built against a new soname
// before the library carrying that soname reaches the mirrors (nix 2.35.1-2
// landed 11h before lowdown 3.1.1-1). ALHP resolves build-time dependencies
// from the pristine chroot's pacman DB, which is only refreshed once per
// build cycle, so it can rebuild such a package against the *old* library and
// publish an artifact that links a soname nothing provides. Nothing in the
// version-based checks can spot that afterwards: our pkgrel suffix keeps our
// version above upstream's and state.git agrees, so the package stays LATEST
// forever while Arch's own package self-heals on the next -Syu.
//
// This mirrors what Arch's sogrep-driven rebuild workflow catches, using
// DT_NEEDED from the built artifacts against the `provides` entries in the
// sync DBs.

// elfMagic identifies an ELF object.
const elfMagic = "\x7fELF"

// maxELFSize caps how much of a single file we buffer to parse its dynamic
// section. Clear of the largest shipped binaries (libLLVM is ~130MB) while
// keeping a corrupt archive from exhausting memory, which matters because
// several builds scan their artifacts concurrently.
const maxELFSize = 256 << 20

// sonameSep separates the soname from its ELF class in a recorded entry, e.g.
// "liblowdown.so.3|64". Chosen because it cannot occur in a soname.
const sonameSep = "|"

// ELF classes as recorded alongside a soname, matching the `-32`/`-64` suffix
// pacman appends to soname provides.
const (
	bits32 = 32
	bits64 = 64
	// elfHeaderSize is the smallest file that could carry a 64-bit ELF header.
	elfHeaderSize = 64
)

// soname is a DT_NEEDED entry together with the ELF class of the object that
// needs it. Bitness matters: multilib packages provide `...so=N-32` entries
// that must not satisfy a 64-bit consumer.
type soname struct {
	Name string
	Bits int
}

func (s soname) String() string {
	return s.Name + sonameSep + strconv.Itoa(s.Bits)
}

func parseSoname(s string) (soname, error) {
	name, bits, ok := strings.Cut(s, sonameSep)
	if !ok {
		return soname{}, fmt.Errorf("malformed soname entry %q", s)
	}
	b, err := strconv.Atoi(bits)
	if err != nil {
		return soname{}, fmt.Errorf("malformed soname entry %q: %w", s, err)
	}
	return soname{Name: name, Bits: b}, nil
}

// base splits "liblowdown.so.3" into ("liblowdown.so", "3"). Reports false for
// unversioned entries like "libnixutil.so", which carry no version to compare.
func (s soname) base() (base, version string, ok bool) {
	prefix, version, ok := strings.Cut(s.Name, ".so.")
	if !ok {
		return "", "", false
	}
	return prefix + ".so", version, true
}

// sonameKey identifies a versionless soname for a given ELF class.
type sonameKey struct {
	Base string
	Bits int
}

// providedSonames maps every soname exported as a `provides` entry by any
// package in the sync DBs to the versions available for it, and which package
// carries each version.
type providedSonames map[sonameKey]map[string]string

// collectProvidedSonames builds the soname index from all registered sync DBs.
// Callers must hold buildManager.alpmMutex.
func collectProvidedSonames(h *alpm.Handle) (providedSonames, error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return nil, err
	}

	provided := make(providedSonames)
	for _, db := range dbs.Slice() {
		err := db.PkgCache().ForEach(func(pkg alpm.IPackage) error {
			provided.add(pkg)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return provided, nil
}

// add indexes every soname pkg exports as a `provides` entry. makepkg writes
// those as `<name>.so=<ver>-<bits>`, anything else is not a soname.
func (p providedSonames) add(pkg alpm.IPackage) {
	for _, dep := range pkg.Provides().Slice() {
		if !strings.HasSuffix(dep.Name, ".so") || dep.Version == "" {
			continue
		}
		// makepkg emits `<soversion>-<soarch>`, so the bitness is the last
		// field and the soversion may itself contain a dash
		sep := strings.LastIndex(dep.Version, "-")
		if sep < 0 {
			continue
		}
		version, bits := dep.Version[:sep], dep.Version[sep+1:]
		b, err := strconv.Atoi(bits)
		if err != nil {
			continue
		}
		key := sonameKey{Base: dep.Name, Bits: b}
		if p[key] == nil {
			p[key] = make(map[string]string)
		}
		p[key][version] = pkg.Name()
	}
}

// satisfied reports whether s is provided at exactly the version it needs.
func (p providedSonames) satisfied(s soname) bool {
	base, version, ok := s.base()
	if !ok {
		return false
	}
	versions := p[sonameKey{Base: base, Bits: s.Bits}]
	_, found := versions[version]
	return found
}

// SonameMismatch is a needed soname whose base is provided by the repos, but
// only at other versions.
type SonameMismatch struct {
	Needed soname
	// Version is the soname version Needed asks for.
	Version   string
	Providers []string
	Available []string
}

func (m SonameMismatch) String() string {
	return fmt.Sprintf("%s (need %s, %s provide %s)", m.Needed.Name, m.Version,
		strings.Join(m.Providers, ","), strings.Join(m.Available, ","))
}

// mismatch describes how s fails against the index, or nil if s is satisfied or
// if nothing provides its base at all. The latter is not an error: sonames with
// no provider anywhere (the dynamic linker, libs bundled in the package,
// parallel-installed versions in private dirs whose owner exports no provides
// like llvm20-libs) are linked the same way in upstream Arch's own packages.
func (p providedSonames) mismatch(s soname) *SonameMismatch {
	base, version, ok := s.base()
	if !ok {
		return nil
	}
	versions := p[sonameKey{Base: base, Bits: s.Bits}]
	if len(versions) == 0 {
		return nil
	}
	if _, found := versions[version]; found {
		return nil
	}

	return &SonameMismatch{
		Needed:    s,
		Version:   version,
		Providers: slices.Compact(slices.Sorted(maps.Values(versions))),
		Available: slices.Sorted(maps.Keys(versions)),
	}
}

// packageSonames is what inspecting a pkgbase's built packages found.
type packageSonames struct {
	// Needed is every DT_NEEDED entry across the packages' ELF objects.
	Needed map[soname]struct{}
	// Shipped holds the soname-shaped file names the packages carry, used to
	// discard sonames they satisfy from their own payload via RPATH.
	Shipped map[string]struct{}
}

func newPackageSonames() *packageSonames {
	return &packageSonames{
		Needed:  make(map[soname]struct{}),
		Shipped: make(map[string]struct{}),
	}
}

// scanPackagesSonames reads DT_NEEDED from every ELF object in the given
// packages, as produced by one pkgbase's split packages. One zstd decoder is
// reused across all of them: each carries async block decoders worth ~34MB.
func scanPackagesSonames(pkgFiles []string) (*packageSonames, error) {
	res := newPackageSonames()
	if len(pkgFiles) == 0 {
		return res, nil
	}

	zr, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	for _, pkgFile := range pkgFiles {
		if err := res.scanFile(pkgFile, zr); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// scanFile adds one .pkg.tar.zst to the result. Non-ELF members and objects
// without a dynamic section are skipped, as is any member that fails to parse,
// rather than failing the whole package.
func (s *packageSonames) scanFile(pkgFile string, zr *zstd.Decoder) error {
	f, err := os.Open(pkgFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	if err := zr.Reset(f); err != nil {
		return fmt.Errorf("error opening %s: %w", pkgFile, err)
	}

	var head [len(elfMagic)]byte
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error reading %s: %w", pkgFile, err)
		}

		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeSymlink, tar.TypeLink:
		default:
			continue
		}
		if strings.HasPrefix(hdr.Name, ".") {
			// pacman metadata (.PKGINFO, .BUILDINFO, .MTREE)
			continue
		}
		// only soname-shaped names can ever satisfy a DT_NEEDED entry, and
		// packages like qt6-base ship thousands of files that cannot
		if base := filepath.Base(hdr.Name); strings.Contains(base, ".so") {
			s.Shipped[base] = struct{}{}
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size < elfHeaderSize || hdr.Size > maxELFSize {
			continue
		}

		// check the magic before allocating for the whole object
		if _, err := io.ReadFull(tr, head[:]); err != nil {
			continue
		}
		if string(head[:]) != elfMagic {
			continue
		}
		buf := make([]byte, hdr.Size)
		copy(buf, head[:])
		if _, err := io.ReadFull(tr, buf[len(head):]); err != nil {
			continue
		}

		ef, err := elf.NewFile(bytes.NewReader(buf))
		if err != nil {
			continue
		}
		bits := bits64
		if ef.Class == elf.ELFCLASS32 {
			bits = bits32
		}
		needed, err := ef.DynString(elf.DT_NEEDED)
		_ = ef.Close()
		if err != nil {
			// no dynamic section (static binary, object file, ...)
			continue
		}
		for _, name := range needed {
			s.Needed[soname{Name: name, Bits: bits}] = struct{}{}
		}
	}
}

// external drops sonames the package satisfies from its own payload; only the
// remainder is resolved through the repos.
func (s *packageSonames) external() []soname {
	out := make([]soname, 0, len(s.Needed))
	for need := range s.Needed {
		if _, bundled := s.Shipped[need.Name]; bundled {
			continue
		}
		out = append(out, need)
	}
	return out
}

// trackable returns the entries worth recording for future staleness checks:
// those currently resolvable through a repo `provides` entry. Anything else
// carries no baseline we could compare against later.
//
// Never nil: a package with nothing to record still has to be distinguishable
// from one that was never scanned, or housekeeping re-scans it forever. Soname
// provides are rare enough (glibc and gcc-libs declare none) that a package
// linking only libc/libstdc++ has nothing trackable at all.
func (s *packageSonames) trackable(provided providedSonames) []string {
	out := []string{}
	for _, need := range s.external() {
		if provided.satisfied(need) {
			out = append(out, need.String())
		}
	}
	slices.Sort(out)
	return out
}

// staleRecorded reports recorded sonames that are no longer provided at the
// recorded version. Malformed entries are ignored so a schema change can never
// wedge housekeeping.
func staleRecorded(recorded []string, provided providedSonames) []SonameMismatch {
	var stale []SonameMismatch
	for _, entry := range recorded {
		s, err := parseSoname(entry)
		if err != nil {
			continue
		}
		if m := provided.mismatch(s); m != nil {
			stale = append(stale, *m)
		}
	}
	return stale
}

// staleAgainstDeps checks freshly scanned sonames without relying on a
// recorded baseline, for packages built before sonames were tracked and for
// verifying a build's own artifacts.
//
// The declared dependencies only decide which soname bases are in scope;
// whether a soname is satisfied is judged against the full index, the same way
// staleRecorded does it. Scoping is what separates a genuine stale link (nix
// needs liblowdown.so.3, its dependency lowdown provides 4) from a private or
// parallel-installed library that merely shares a base name with an unrelated
// package (clang20 needs libLLVM.so.20.1 from llvm20-libs, which exports no
// provides at all, while the unrelated llvm-libs provides 22.1). Judging
// against the full index matters because FindSatisfier returns only one of
// possibly several providers of a dep string, and repos carry bases provided at
// different versions by different packages (libavcodec.so, libfltk.so, ...).
func staleAgainstDeps(scan *packageSonames, deps []string, h *alpm.Handle,
	provided providedSonames,
) ([]SonameMismatch, error) {
	dbs, err := h.SyncDBs()
	if err != nil {
		return nil, err
	}

	scope := make(map[sonameKey]struct{})
	for _, dep := range deps {
		pkg, err := dbs.FindSatisfier(dep)
		if err != nil {
			continue
		}
		depProvided := make(providedSonames)
		depProvided.add(pkg)
		for key := range depProvided {
			scope[key] = struct{}{}
		}
	}

	var stale []SonameMismatch
	for _, need := range scan.external() {
		base, _, ok := need.base()
		if !ok {
			continue
		}
		if _, inScope := scope[sonameKey{Base: base, Bits: need.Bits}]; !inScope {
			continue
		}
		if m := provided.mismatch(need); m != nil {
			stale = append(stale, *m)
		}
	}
	return stale, nil
}

func mismatchStrings(mismatches []SonameMismatch) string {
	out := make([]string, 0, len(mismatches))
	for _, m := range mismatches {
		out = append(out, m.String())
	}
	return strings.Join(out, "; ")
}
