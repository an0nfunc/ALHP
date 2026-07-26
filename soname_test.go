package main

import (
	"testing"
)

// sonames reused across the table tests below
const (
	soLowdown3 = "liblowdown.so.3"
	soNixUtil  = "libnixutil.so"
	soLdLinux  = "ld-linux-x86-64.so.2"
	soLibc6    = "libc.so.6"
)

func TestSonameRoundTrip(t *testing.T) {
	t.Parallel()

	for _, want := range []soname{
		{Name: soLowdown3, Bits: 64},
		{Name: "libbz2.so.1.0", Bits: 32},
		{Name: soNixUtil, Bits: 64},
	} {
		got, err := parseSoname(want.String())
		if err != nil {
			t.Fatalf("parseSoname(%q): %v", want.String(), err)
		}
		if got != want {
			t.Errorf("round trip: got %+v, want %+v", got, want)
		}
	}

	for _, in := range []string{soLowdown3, "liblowdown.so.3|", "liblowdown.so.3|abc", ""} {
		if _, err := parseSoname(in); err == nil {
			t.Errorf("parseSoname(%q): expected error", in)
		}
	}
}

func TestSonameBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		wantBase    string
		wantVersion string
		wantOK      bool
	}{
		{soLowdown3, "liblowdown.so", "3", true},
		{"libjxl.so.0.11", "libjxl.so", "0.11", true},
		{"libnixutil.so.2.35.1", soNixUtil, "2.35.1", true},
		{soLdLinux, "ld-linux-x86-64.so", "2", true},
		// unversioned: nothing to compare against
		{soNixUtil, "", "", false},
	}

	for _, tt := range tests {
		base, version, ok := soname{Name: tt.name, Bits: 64}.base()
		if ok != tt.wantOK || base != tt.wantBase || version != tt.wantVersion {
			t.Errorf("%q: got (%q, %q, %v), want (%q, %q, %v)",
				tt.name, base, version, ok, tt.wantBase, tt.wantVersion, tt.wantOK)
		}
	}
}

// index mirrors the state that broke nix: lowdown moved from liblowdown.so.3 to
// .so.4, libjxl from 0.11 to 0.12, plus a 32-bit entry from multilib.
func testProvided() providedSonames {
	return providedSonames{
		{Base: "liblowdown.so", Bits: 64}: {"4": "lowdown"},
		{Base: "libjxl.so", Bits: 64}:     {"0.12": "libjxl"},
		{Base: "libc.so", Bits: 64}:       {"6": "glibc"},
		{Base: "libz.so", Bits: 32}:       {"1": "lib32-zlib"},
		// parallel-installed versions of the same base
		{Base: "libLLVM.so", Bits: 64}: {"22.1": "llvm-libs"},
	}
}

func TestProvidedSonamesMismatch(t *testing.T) {
	t.Parallel()

	provided := testProvided()

	tests := []struct {
		desc         string
		in           soname
		wantMismatch bool
	}{
		{"satisfied at the needed version", soname{Name: soLibc6, Bits: 64}, false},
		{"provided only at another version", soname{Name: soLowdown3, Bits: 64}, true},
		{"provided only at another version, multi-part", soname{Name: "libjxl.so.0.11", Bits: 64}, true},
		// nothing provides the base: dynamic linker, bundled or private libs.
		// upstream Arch links these the same way, so they are not our problem
		{"base not provided at all", soname{Name: soLdLinux, Bits: 64}, false},
		{"unversioned soname", soname{Name: soNixUtil, Bits: 64}, false},
		// bitness must not cross over
		{"32-bit need against 32-bit provide", soname{Name: "libz.so.1", Bits: 32}, false},
		{"64-bit need against 32-bit provide only", soname{Name: "libz.so.1", Bits: 64}, false},
	}

	for _, tt := range tests {
		got := provided.mismatch(tt.in)
		if (got != nil) != tt.wantMismatch {
			t.Errorf("%s: mismatch(%+v) = %v, want mismatch=%v", tt.desc, tt.in, got, tt.wantMismatch)
		}
	}

	m := provided.mismatch(soname{Name: soLowdown3, Bits: 64})
	if m == nil {
		t.Fatal("expected mismatch for liblowdown.so.3")
	}
	if want := "liblowdown.so.3 (need 3, lowdown provide 4)"; m.String() != want {
		t.Errorf("String() = %q, want %q", m.String(), want)
	}
}

func TestProvidedSonamesSatisfied(t *testing.T) {
	t.Parallel()

	provided := testProvided()

	if !provided.satisfied(soname{Name: soLibc6, Bits: 64}) {
		t.Error("libc.so.6 should be satisfied")
	}
	// unlike mismatch, an unprovided base is not satisfied either: there is no
	// baseline worth recording for it
	for _, s := range []soname{
		{Name: soLowdown3, Bits: 64},
		{Name: soLdLinux, Bits: 64},
		{Name: soNixUtil, Bits: 64},
	} {
		if provided.satisfied(s) {
			t.Errorf("%+v should not be satisfied", s)
		}
	}
}

func TestStaleRecorded(t *testing.T) {
	t.Parallel()

	provided := testProvided()

	recorded := []string{
		"libc.so.6|64",            // still fine
		"liblowdown.so.3|64",      // soname bumped underneath us
		"libjxl.so.0.11|64",       // same
		"ld-linux-x86-64.so.2|64", // never provided, must stay quiet
		"garbage-entry",           // malformed, must not wedge housekeeping
	}

	stale := staleRecorded(recorded, provided)
	if len(stale) != 2 {
		t.Fatalf("got %d stale entries (%s), want 2", len(stale), mismatchStrings(stale))
	}
	for _, m := range stale {
		if m.Needed.Name != soLowdown3 && m.Needed.Name != "libjxl.so.0.11" {
			t.Errorf("unexpected stale entry %s", m)
		}
	}

	if got := staleRecorded(nil, provided); len(got) != 0 {
		t.Errorf("no recorded sonames: got %d stale, want 0", len(got))
	}
}

func TestPackageSonamesExternal(t *testing.T) {
	t.Parallel()

	scan := &packageSonames{
		Needed: map[soname]struct{}{
			{Name: soLowdown3, Bits: 64}:        {},
			{Name: "libLLVM.so.20.1", Bits: 64}: {},
			{Name: soLibc6, Bits: 64}:           {},
		},
		// the package carries libLLVM.so.20.1 itself, reached via RPATH
		Shipped: map[string]struct{}{"libLLVM.so.20.1": {}},
	}

	external := scan.external()
	if len(external) != 2 {
		t.Fatalf("got %d external sonames, want 2", len(external))
	}
	for _, s := range external {
		if s.Name == "libLLVM.so.20.1" {
			t.Error("bundled soname should not be resolved through the repos")
		}
	}
}

func TestPackageSonamesTrackable(t *testing.T) {
	t.Parallel()

	provided := testProvided()
	scan := &packageSonames{
		Needed: map[soname]struct{}{
			{Name: soLibc6, Bits: 64}:          {}, // recorded
			{Name: soLowdown3, Bits: 64}:       {}, // not currently resolvable
			{Name: soLdLinux, Bits: 64}:        {}, // no provider anywhere
			{Name: "libjxl.so.0.12", Bits: 64}: {}, // recorded
			{Name: "libz.so.1", Bits: 32}:      {}, // recorded, 32-bit
		},
		Shipped: map[string]struct{}{},
	}

	// a package with nothing trackable must still return a non-nil slice: it is
	// what distinguishes "scanned, nothing to record" from "never scanned", and
	// housekeeping re-scans the latter every cycle
	empty := &packageSonames{
		Needed:  map[soname]struct{}{{Name: soLibc6, Bits: 64}: {}},
		Shipped: map[string]struct{}{},
	}
	if got := empty.trackable(providedSonames{}); got == nil {
		t.Error("trackable returned nil, want an empty non-nil slice")
	}

	got := scan.trackable(provided)
	want := []string{"libc.so.6|64", "libjxl.so.0.12|64", "libz.so.1|32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q (sorted output expected)", i, got[i], want[i])
		}
	}
}

func TestParseRepoDBDesc(t *testing.T) {
	t.Parallel()

	// two entries as repo-add writes them, concatenated the way bsdtar emits
	// them, including a field we do not care about between the two we do
	desc := `%FILENAME%
nix-2.35.1-2.1-x86_64.pkg.tar.zst

%NAME%
nix

%BASE%
nix

%VERSION%
2.35.1-2.1

%DEPENDS%
lowdown
sqlite

%FILENAME%
geeqie-2.9-3.1-x86_64.pkg.tar.zst

%NAME%
geeqie

%VERSION%
2.9-3.1
`

	got := parseRepoDBDesc(desc)
	want := map[string]string{
		"nix":    "nix-2.35.1-2.1-x86_64.pkg.tar.zst",
		"geeqie": "geeqie-2.9-3.1-x86_64.pkg.tar.zst",
	}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, filename := range want {
		if got[name] != filename {
			t.Errorf("%s: got %q, want %q", name, got[name], filename)
		}
	}

	if got := parseRepoDBDesc(""); len(got) != 0 {
		t.Errorf("empty input: got %v, want empty", got)
	}
}
