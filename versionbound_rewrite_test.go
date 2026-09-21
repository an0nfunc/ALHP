package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Morganamilo/go-srcinfo"
)

func TestRewriteLEBound(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		bound string
		want  string
		ok    bool
	}{
		{"the case from the issue", mergedBound, "3.26.4-6", true},
		{"epoch survives untouched", "1:580.119.02-3", "1:580.119.02-4", true},
		{"pkgrel rolls into two digits", "1.0-9", "1.0-10", true},
		{"vcs pkgver with git revision", "41.0+r106+gebc68374-1", "41.0+r106+gebc68374-2", true},
		{"uppercase and dots in pkgver", "2025.Q2.1-1", "2025.Q2.1-2", true},
		// no pkgrel, so pacman never compares far enough to see a build number
		{"no pkgrel", "5.111", "", false},
		// the case the obvious generalization gets wrong: increasePkgRel replaces
		// the trailing component, so upstream 5.2 publishes as 5.N and no bound
		// separates our build from the version upstream excluded
		{"dotted pkgrel is refused", "1.2-5.2", "", false},
		{"non-numeric pkgrel", "1.0-1.el7", "", false},
		{"empty pkgrel", "1.0-", "", false},
		{"empty", "", "", false},
		// Atoi accepts this and +1 wraps negative. The wrapped bound carries no
		// <=, so assertion C cannot see it and it would reach the repo
		{"pkgrel too wide to increment", "1.0-9223372036854775807", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := rewriteLEBound(tc.bound)
			if ok != tc.ok || got != tc.want {
				t.Errorf("rewriteLEBound(%q) = (%q, %t), want (%q, %t)", tc.bound, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// archStrings builds an unversioned-arch dependency list, the shape makepkg
// emits for a plain conflicts/replaces entry.
func archStrings(values ...string) []srcinfo.ArchString {
	out := make([]srcinfo.ArchString, len(values))
	for i, v := range values {
		out[i] = srcinfo.ArchString{Value: v}
	}
	return out
}

func TestBoundTargets(t *testing.T) {
	t.Parallel()

	le := mergedPkg + "<=" + mergedBound
	si := &srcinfo.Srcinfo{
		Package: srcinfo.Package{
			// the same literal in both fields is one target carrying two entries,
			// which is exactly the slack assertion A has to allow for
			Conflicts: archStrings(le, "geocode-glib-common<="+mergedBound),
			Replaces:  archStrings(le),
		},
		Packages: []srcinfo.Package{{
			Pkgname: "split",
			// a soname provide-shaped bound, where -64 is an ELF class
			Conflicts: archStrings("libatk-1.0.so<=0-64", "kimageformats5<5.111", "pinned=1.0-2"),
		}},
	}

	targets := boundTargets(si)
	if len(targets) != 2 {
		t.Fatalf("boundTargets() found %d targets, want 2: %v", len(targets), targets)
	}
	if got := targets[le]; got == nil || got.entries != 2 || got.new != mergedPkg+"<3.26.4-6" {
		t.Errorf("target for %q = %+v, want 2 entries rewritten to %s<3.26.4-6", le, got, mergedPkg)
	}
	for _, skipped := range []string{"libatk-1.0.so<=0-64", "kimageformats5<5.111", "pinned=1.0-2"} {
		if _, ok := targets[skipped]; ok {
			t.Errorf("boundTargets() should not have targeted %q", skipped)
		}
	}
}

func TestBoundSpansAndSubstitute(t *testing.T) {
	t.Parallel()

	le := mergedPkg + "<=" + mergedBound
	targets := map[string]*boundTarget{le: {old: le, new: mergedPkg + "<3.26.4-6", entries: 8}}

	for _, tc := range []struct {
		name  string
		in    string
		want  string
		count int
	}{
		{
			"single-quoted one-liner",
			"replaces=('" + le + "')\n",
			"replaces=('" + mergedPkg + "<3.26.4-6')\n",
			1,
		},
		{
			"double-quoted one-liner",
			"conflicts=(\"" + le + "\")\n",
			"conflicts=(\"" + mergedPkg + "<3.26.4-6\")\n",
			1,
		},
		{
			// 39% of real bounds sit on a continuation line with no field name,
			// which is what defeats any line-anchored regex
			"multi-line array",
			"conflicts=(\n  '" + le + "'\n  'other<=1.0-1'\n)\n",
			"conflicts=(\n  '" + mergedPkg + "<3.26.4-6'\n  'other<=1.0-1'\n)\n",
			1,
		},
		{
			"append form",
			"replaces+=('" + le + "')\n",
			"replaces+=('" + mergedPkg + "<3.26.4-6')\n",
			1,
		},
		{
			"indented inside a package function",
			"package_x() {\n  conflicts=('" + le + "')\n}\n",
			"package_x() {\n  conflicts=('" + mergedPkg + "<3.26.4-6')\n}\n",
			1,
		},
		{
			// the escape the whole scoping design exists to close: a literal in a
			// heredoc the package installs produces no metadata, so no assertion
			// over the srcinfo could ever notice it being edited
			"heredoc outside any array is untouched",
			"conflicts=('" + le + "')\npackage() {\n  cat > f <<EOF\n" + le + "\nEOF\n}\n",
			"conflicts=('" + mergedPkg + "<3.26.4-6')\npackage() {\n  cat > f <<EOF\n" + le + "\nEOF\n}\n",
			1,
		},
		{
			"shell arithmetic is untouched",
			"build() {\n  for ((i=0; i<=3; i++)); do :; done\n}\n",
			"build() {\n  for ((i=0; i<=3; i++)); do :; done\n}\n",
			0,
		},
		{
			"a commented-out array is not a span",
			"#conflicts=('" + le + "')\n",
			"#conflicts=('" + le + "')\n",
			0,
		},
		{
			// vercmp puts 3.26.4-51 above 3.26.4-5, so clipping the shorter
			// literal out of the longer one would loosen a bound to a version it
			// was written to exclude
			"a longer version is not clipped",
			"conflicts=('" + mergedPkg + "<=3.26.4-51')\n",
			"conflicts=('" + mergedPkg + "<=3.26.4-51')\n",
			0,
		},
		{
			"parens inside a quoted entry do not end the span",
			"conflicts=('weird(name)<=1.0-1' '" + le + "')\n",
			"conflicts=('weird(name)<=1.0-1' '" + mergedPkg + "<3.26.4-6')\n",
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spans, err := boundSpans(tc.in)
			if err != nil {
				t.Fatalf("boundSpans() error = %v", err)
			}
			got, counts := substituteBounds(tc.in, spans, targets)
			if got != tc.want {
				t.Errorf("substituteBounds() =\n%q\nwant\n%q", got, tc.want)
			}
			if counts[le] != tc.count {
				t.Errorf("substituteBounds() replaced %d times, want %d", counts[le], tc.count)
			}
		})
	}
}

// The two escapes that scoping on the assignment head alone does not close.
// Both must refuse rather than edit, because neither leaves a trace any srcinfo
// assertion could detect.
func TestBoundSpansRefusesUnsafeShapes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{
			// a heredoc body carrying a line that looks like an assignment. The
			// derived-array shape supplies exactly the count slack that would let
			// this edit pass assertion A unnoticed
			"assignment inside a heredoc",
			"replaces=('oldpkg<=1.0-2')\nconflicts=(\"${replaces[@]}\")\n" +
				"package() {\n  cat > f <<'EOF'\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n",
		},
		{
			"assignment inside a tab-stripping heredoc",
			"package() {\n  cat > f <<-EOF\n\tconflicts=('oldpkg<=1.0-2')\n\tEOF\n}\n",
		},
		{
			// a nested assignment yields spans that are not disjoint, which
			// substituteBounds would slice backwards through and panic on
			"assignment nested in a command substitution",
			"conflicts=('a<=1.0-1' $(\nreplaces=('b<=1.0-1')\n))\n",
		},
		{
			"unterminated heredoc",
			"package() {\n  cat > f <<EOF\nconflicts=('oldpkg<=1.0-2')\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted an unsafe shape:\n%s", tc.in)
			}
		})
	}
}

// A heredoc elsewhere in the file must not stop a real bound from being fixed.
// Forms that look like a heredoc operator but are not. Each one used to refuse a
// whole package and name a heredoc that is not in the file.
func TestBoundSpansAcceptsNonHeredocOperators(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"herestring", "build() {\n  grep foo <<< bar\n}\nconflicts=('o<=1.0-2')\n"},
		// the real shape from boost's PKGBUILD
		{"herestring with a quoted expansion", "build() {\n  grep foo <<< \"$MAKEFLAGS\"\n}\nconflicts=('o<=1.0-2')\n"},
		{"herestring without a space", "build() {\n  grep foo <<<bar\n}\nconflicts=('o<=1.0-2')\n"},
		{"left shift in an arithmetic expansion", "build() {\n  n=$(( 1 << bits ))\n}\nconflicts=('o<=1.0-2')\n"},
		{"left shift in a bare double paren", "build() {\n  (( n = 1 << bits ))\n}\nconflicts=('o<=1.0-2')\n"},
		// << inside a body is ordinary text there, not a nested operator
		{"operator inside a heredoc body", "conflicts=('o<=1.0-2')\npackage() {\n  cat > f <<'EOF'\nx << NOTATAG y\nEOF\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spans, err := boundSpans(tc.in)
			if err != nil {
				t.Fatalf("boundSpans() refused a non-heredoc operator: %v", err)
			}
			if len(spans) != 1 {
				t.Errorf("boundSpans() found %d spans, want 1", len(spans))
			}
		})
	}
}

// TestBoundSpansRefusesQuotedHeredocVariants covers the heredoc forms whose
// bodies must still be protected. A <<\EOF delimiter and a tab-indented <<-
// terminator are the same silent escape as the quoted form: bash does not expand
// the body, so a literal inside it is not a bound and must never be edited.
func TestBoundSpansRefusesQuotedHeredocVariants(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		// <<\EOF is valid bash and behaves exactly like <<'EOF'
		{
			"backslash-quoted terminator",
			"conflicts=('o<=1.0-2')\npackage() {\n  cat > f <<\\EOF\nconflicts=('o<=1.0-2')\nEOF\n}\n",
		},
		// only <<- permits an indented terminator, so a tab-indented line inside a
		// plain heredoc must not end the region early
		{
			"tab-indented line inside a plain heredoc",
			"package() {\n  cat > f <<EOF\nbody\n\tEOF\nconflicts=('o<=1.0-2')\nEOF\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted an assignment inside a heredoc body:\n%s", tc.in)
			}
		})
	}
}

func TestBoundSpansAllowsHeredocElsewhere(t *testing.T) {
	t.Parallel()

	in := "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<'EOF'\nsome unrelated content\nEOF\n}\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() = %v, want acceptance", err)
	}
	targets := map[string]*boundTarget{"oldpkg<=1.0-2": {old: "oldpkg<=1.0-2", new: "oldpkg<1.0-3", entries: 1}}
	out, counts := substituteBounds(in, spans, targets)
	if counts["oldpkg<=1.0-2"] != 1 {
		t.Errorf("replaced %d times, want 1", counts["oldpkg<=1.0-2"])
	}
	if !strings.Contains(out, "some unrelated content") {
		t.Errorf("heredoc body was disturbed:\n%s", out)
	}
}

// Arch-suffixed arrays are targets as far as the srcinfo is concerned, so they
// have to be in scope or a file carrying one abandons its other bounds too.
func TestBoundSpansCoversArchSuffixed(t *testing.T) {
	t.Parallel()

	in := "conflicts_x86_64=('oldpkg<=1.0-2')\nreplaces_i686+=('other<=2.0-3')\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() = %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("boundSpans() found %d spans, want 2", len(spans))
	}
}

func TestBoundSpansRefusesUndelimited(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"unterminated array", "conflicts=('foo<=1.0-1'\n"},
		{"unterminated single quote", "conflicts=('foo<=1.0-1)\n"},
		{"unterminated double quote", "conflicts=(\"foo<=1.0-1)\n"},
		// a trailing escape must not make the scan fall out of the string and
		// start reading its contents as shell again
		{"double quote closed only by an escape", "conflicts=(\"foo<=1.0-1\\\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans(%q) = nil error, want a refusal", tc.in)
			}
		})
	}
}

// A nil dependency list must stay nil. reflect.DeepEqual separates nil from an
// empty slice, so returning an empty one here fails assertion B for every
// package that has no conflicts at all, which looks like the design not working.
func TestWantSrcinfoPreservesNil(t *testing.T) {
	t.Parallel()

	le := mergedPkg + "<=" + mergedBound
	before := &srcinfo.Srcinfo{
		Package:  srcinfo.Package{Conflicts: archStrings(le)},
		Packages: []srcinfo.Package{{Pkgname: "split"}},
	}
	targets := map[string]*boundTarget{le: {old: le, new: mergedPkg + "<3.26.4-6", entries: 1}}

	want := wantSrcinfo(before, targets)
	if want.Replaces != nil {
		t.Errorf("wantSrcinfo() turned a nil Replaces into %#v", want.Replaces)
	}
	if want.Packages[0].Conflicts != nil {
		t.Errorf("wantSrcinfo() turned a nil split Conflicts into %#v", want.Packages[0].Conflicts)
	}
	if want.Conflicts[0].Value != mergedPkg+"<3.26.4-6" {
		t.Errorf("wantSrcinfo() left the bound as %q", want.Conflicts[0].Value)
	}
	// the input must not be mutated, since it is the comparison baseline
	if before.Conflicts[0].Value != le {
		t.Errorf("wantSrcinfo() mutated its input to %q", before.Conflicts[0].Value)
	}
}

func TestArtifactBounds(t *testing.T) {
	t.Parallel()

	// pacman writes `conflict` singular and `replaces` plural in .PKGINFO, unlike
	// the srcinfo, and reading both is what makes the artifact check an oracle for
	// the rewrite rather than a partial view of it
	pkginfo := strings.Join([]string{
		"pkgname = geocode-glib",
		"pkgbase = geocode-glib",
		"conflict = " + mergedPkg + "<=" + mergedBound,
		"conflict = geocode-glib-common<=" + mergedBound,
		"replaces = " + mergedPkg + "<=" + mergedBound,
		"provides = " + mergedPkg + "=3.26.4-6",
		"depend = glib2",
		"",
	}, "\n")

	path := filepath.Join(t.TempDir(), "geocode-glib-3.26.4-6-x86_64.pkg.tar.zst")
	writeTestPackage(t, path, []tarMember{
		// real archives carry .PKGINFO third, so the fixture does too
		{Name: ".BUILDINFO", Content: []byte("format = 2\n")},
		{Name: ".MTREE", Content: []byte("#mtree\n")},
		{Name: pkginfoName, Content: []byte(pkginfo)},
		{Name: "usr/lib/libgeocode-glib-2.so", Content: []byte("payload")},
	})

	bounds, err := artifactBounds(path)
	if err != nil {
		t.Fatalf("artifactBounds() error = %v", err)
	}

	want := []string{
		mergedPkg + "<=" + mergedBound,
		"geocode-glib-common<=" + mergedBound,
		mergedPkg + "<=" + mergedBound,
	}
	if !reflect.DeepEqual(bounds, want) {
		t.Errorf("artifactBounds() = %v, want %v", bounds, want)
	}

	// provides and depend must not leak in: rewriting a provides would change what
	// the package claims to be
	for _, b := range bounds {
		if strings.Contains(b, "=3.26.4-6") || b == "glib2" {
			t.Errorf("artifactBounds() returned a non-conflict entry %q", b)
		}
	}
}

// needMakepkg skips when makepkg is absent, rather than letting the test pass on
// a genSrcinfo failure that never reaches the invariant being asserted.
func needMakepkg(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("makepkg"); err != nil {
		t.Skipf("makepkg not available: %v", err)
	}
}

// A refusal must leave the PKGBUILD exactly as upstream wrote it. This is the
// invariant the whole design rests on: a build that proceeds unrewritten has to
// be building the file it would have built without this feature.
func TestPrepareBoundRewriteRevertsOnRefusal(t *testing.T) {
	t.Parallel()
	needMakepkg(t)

	// a bound assembled from a variable: makepkg resolves it, so it becomes a
	// target, but the literal is not in the text, so assertion A refuses
	pkgbuild := strings.Join([]string{
		"pkgname=probe",
		"pkgver=1.0",
		"pkgrel=2",
		"arch=('x86_64')",
		"_oldrel=1",
		`conflicts=("oldpkg<=1.0-$_oldrel")`,
		"package() { :; }",
		"",
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "PKGBUILD")
	if err := os.WriteFile(path, []byte(pkgbuild), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &ProtoPackage{Pkgbase: "probe", FullRepo: "extra-x86-64-v3", Pkgbuild: path}
	err := p.prepareBoundRewrite(t.Context())
	if err == nil {
		t.Fatal("prepareBoundRewrite() accepted a bound that is not present as a literal")
	}
	if errors.Is(err, errPkgbuildDirty) {
		t.Errorf("prepareBoundRewrite() reported the PKGBUILD dirty on a pre-write refusal: %v", err)
	}

	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != pkgbuild {
		t.Errorf("PKGBUILD not restored after refusal:\n%s", string(after))
	}
}

// The accepted path must rewrite the bound and hand back a srcinfo describing the
// file as it now stands, since srcinfoDepends reads it afterwards.
func TestPrepareBoundRewriteAccepts(t *testing.T) {
	t.Parallel()
	needMakepkg(t)

	pkgbuild := strings.Join([]string{
		"pkgname=probe",
		"pkgver=1.0",
		"pkgrel=2",
		"arch=('x86_64')",
		"depends=('glib2')",
		`conflicts=('oldpkg<=1.0-2' 'keepme<5.111')`,
		"package() { :; }",
		"",
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "PKGBUILD")
	if err := os.WriteFile(path, []byte(pkgbuild), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &ProtoPackage{Pkgbase: "probe", FullRepo: "extra-x86-64-v3", Pkgbuild: path}
	if err := p.prepareBoundRewrite(t.Context()); err != nil {
		t.Fatalf("prepareBoundRewrite() = %v, want acceptance", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "'oldpkg<1.0-3'") {
		t.Errorf("bound not rewritten:\n%s", string(after))
	}
	// a bound with no pkgrel is immune and must be left exactly as written
	if !strings.Contains(string(after), "'keepme<5.111'") {
		t.Errorf("untouchable bound was modified:\n%s", string(after))
	}
	// p.Srcinfo must describe the rewritten file, and depends must have survived
	if got := len(boundTargets(p.Srcinfo)); got != 0 {
		t.Errorf("p.Srcinfo still carries %d rewritable bounds", got)
	}
	if len(p.Srcinfo.Depends) != 1 || p.Srcinfo.Depends[0].Value != "glib2" {
		t.Errorf("depends did not survive: %+v", p.Srcinfo.Depends)
	}
}

// TestBoundSpansStopsAtCommentAfterOpenParen pins the bash rule that a '#'
// directly after '(' opens a comment. Read as content instead it flips quote
// parity, swallows the array's own ')' and runs the span into the function
// below, where a substitution lands in code rather than in metadata.
func TestBoundSpansStopsAtCommentAfterOpenParen(t *testing.T) {
	t.Parallel()

	const in = "conflicts=(#'\n'oldpkg<=1.0-2')\nbuild() {\n  y='\n  echo oldpkg<=1.0-2 )'\n}\n"

	spans, err := boundSpans(in)
	if err != nil {
		// refusing the file is an acceptable outcome; what must not happen is a
		// span the caller would then substitute inside
		return
	}

	for _, span := range spans {
		if segment := in[span[0]:span[1]]; strings.Contains(segment, "build()") {
			t.Errorf("span reaches past the array into the function body: %q", segment)
		}
	}
}

// TestBoundSpansRefusesUnnamedHeredocDelimiter covers heredoc operators whose
// delimiter the strict grammar cannot name. Falling through would read the body
// as ordinary text and leave it editable, which is the one escape the heredoc
// exclusion exists to close, so an unresolvable operator refuses the file.
func TestBoundSpansRefusesUnnamedHeredocDelimiter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		// bash expands the delimiter, so the body ends on whatever $TAG holds
		{
			"expanded delimiter",
			"conflicts=('o<=1.0-2')\npackage() {\n  cat > f <<$TAG\nconflicts=('o<=1.0-2')\n$TAG\n}\n",
		},
		// a form feed is whitespace to Go's \s but an ordinary word character to
		// bash, so a delimiter starting with one must not read as "no delimiter"
		{
			"form feed delimiter",
			"conflicts=('o<=1.0-2')\npackage() {\n  cat > f <<\fEOF\nconflicts=('o<=1.0-2')\n\fEOF\n}\n",
		},
		{
			"form feed delimiter after a blank",
			"conflicts=('o<=1.0-2')\npackage() {\n  cat > f << \fEOF\nconflicts=('o<=1.0-2')\n\fEOF\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted a heredoc it cannot delimit:\n%s", tc.in)
			}
		})
	}
}

// TestBoundSpansProtectsAbuttingHeredocs covers two heredoc operators on one
// line. Neither pattern may consume the byte in front of an operator, because
// FindAll does not overlap matches and the second `<<` would then have none left
// to match, leaving its body unprotected while the first body looked handled.
func TestBoundSpansProtectsAbuttingHeredocs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"abutting", "cat <<A<<B\nx\nA\nconflicts=('o<=1.0-2')\nB\n"},
		{"spaced", "cat <<A <<B\nx\nA\nconflicts=('o<=1.0-2')\nB\n"},
		// bodies on one line are consecutive, so B's starts where A's ended. Share
		// a start between them and a line inside body A ends region B early
		{"chained, B delimiter inside body A", "cat <<A<<B\nB\nA\nconflicts=('o<=1.0-2')\nB\n"},
		{"three chained", "cat <<A<<B<<C\nC\nA\nx\nB\nconflicts=('o<=1.0-2')\nC\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted an assignment inside the second heredoc body:\n%s", tc.in)
			}
		})
	}
}

// TestBoundSpansAllowsHerestring guards the other side of dropping the leading
// [^<] from both heredoc patterns: a `<<<` herestring takes its input from the
// word after it and has no body, so it must not be read as an operator.
func TestBoundSpansAllowsHerestring(t *testing.T) {
	t.Parallel()

	in := "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat <<<\"$x\"\n}\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() refused a herestring: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := in[spans[0][0]:spans[0][1]]; got != "('oldpkg<=1.0-2')" {
		t.Errorf("span = %q", got)
	}
}

// TestBoundSpansAllowsSeparateHeredocs guards the other side of chaining body
// starts: two heredocs on lines of their own are independent, so neither may
// swallow the assignment between or after them.
func TestBoundSpansAllowsSeparateHeredocs(t *testing.T) {
	t.Parallel()

	in := "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<'E1'\na\nE1\n  cat > g <<'E2'\nb\nE2\n}\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() refused two independent heredocs: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := in[spans[0][0]:spans[0][1]]; got != "('oldpkg<=1.0-2')" {
		t.Errorf("span = %q", got)
	}
}

// TestBoundSpansRefusesContinuedOperatorLine covers a heredoc operator whose
// physical line bash would continue. Chaining bodies works per physical line, so
// an operator carried past the newline lands inside the first body's region and
// reads as text there, leaving its own body unprotected while the file looks
// handled. Refusing costs nothing: upstream does not write these.
func TestBoundSpansRefusesContinuedOperatorLine(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"trailing backslash", "cat <<A \\\n  <<B\nx\nA\nconflicts=('o<=1.0-2')\nB\n"},
		{"open command substitution", "cat <<A $(echo\n) <<B\nx\nA\nconflicts=('o<=1.0-2')\nB\n"},
		{"open double quote", "cat <<A \"x\ny\" <<B\nx\nA\nconflicts=('o<=1.0-2')\nB\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted an operator on a continued line:\n%s", tc.in)
			}
		})
	}
}

// TestBoundSpansAllowsEscapedSpace guards the near miss of the check above: a
// backslash followed by a space escapes the space, not the newline, so the line
// ends where it appears to and the heredoc is ordinary.
func TestBoundSpansAllowsEscapedSpace(t *testing.T) {
	t.Parallel()

	in := "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<'EOF' \\ \nunrelated\nEOF\n}\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() refused an escaped space: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
}

// TestBoundSpansRefusesPartialDelimiter covers delimiters the pattern can only
// name the head of. Bash ends the delimiter at a metacharacter and applies quote
// removal to the whole word, so `<<E\\OF`, `<<E'O'F` and `<<EOF-x` terminate on
// EOF, EOF and EOF-x. Classifying any of them on the captured head protects a
// span that ends at the wrong line and leaves the rest of the body editable.
func TestBoundSpansRefusesPartialDelimiter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"backslash", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<E\\OF\nE\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n"},
		{"quoted middle", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<E'O'F\nE\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n"},
		{"quoted head", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<'E'OF\nE\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n"},
		{"double-quoted tail", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<E\"OF\"\nE\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n"},
		{"mixed quoting", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<\"E\"'OF'\nE\nconflicts=('oldpkg<=1.0-2')\nEOF\n}\n"},
		{"dash", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF-x\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF-x\n}\n"},
		{"dot", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF.x\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF.x\n}\n"},
		{"dollar", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF$x\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF$x\n}\n"},
		{"hash", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF#\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF#\n}\n"},
		{"brace", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF{\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF{\n}\n"},
		{"equals", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF=\nEOF\nconflicts=('oldpkg<=1.0-2')\nEOF=\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := boundSpans(tc.in); err == nil {
				t.Errorf("boundSpans() accepted a delimiter it could only name the head of:\n%s", tc.in)
			}
		})
	}
}

// TestBoundSpansAllowsDelimiterMetacharacter is the other side of that rule: a
// metacharacter directly after the delimiter ends the word rather than extending
// it, so these are ordinary heredocs and must keep working.
func TestBoundSpansAllowsDelimiterMetacharacter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"semicolon", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF;\nunrelated\nEOF\n}\n"},
		{"close paren", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF)\nunrelated\nEOF\n}\n"},
		{"pipe", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF|\nunrelated\nEOF\n}\n"},
		{"redirect", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF>f\nunrelated\nEOF\n}\n"},
		{"and", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF&&\nunrelated\nEOF\n}\n"},
		{"space", "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF \nunrelated\nEOF\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spans, err := boundSpans(tc.in)
			if err != nil {
				t.Fatalf("boundSpans() refused an ordinary heredoc: %v", err)
			}
			if len(spans) != 1 {
				t.Errorf("got %d spans, want 1", len(spans))
			}
		})
	}
}

// TestBoundSpansCommentDoesNotMaskOpenParen guards the interaction between the
// two line-ending rules: a comment ends the line, but a `$(` opened before it
// still carries the line past its newline, so the comment must not be taken as
// the end on its own.
func TestBoundSpansCommentDoesNotMaskOpenParen(t *testing.T) {
	t.Parallel()

	in := "cat <<A $(echo # x\n) <<B\nq\nA\nconflicts=('o<=1.0-2')\nB\n"
	if _, err := boundSpans(in); err == nil {
		t.Errorf("boundSpans() let a comment hide an open command substitution:\n%s", in)
	}
}

// TestBoundSpansAllowsQuoteInComment is the other side of that rule: an
// apostrophe in a trailing comment is not an unterminated string, so the line
// ends where it appears to and the heredoc is ordinary.
func TestBoundSpansAllowsQuoteInComment(t *testing.T) {
	t.Parallel()

	in := "conflicts=('oldpkg<=1.0-2')\npackage() {\n  cat > f <<EOF # don't\nunrelated\nEOF\n}\n"
	spans, err := boundSpans(in)
	if err != nil {
		t.Fatalf("boundSpans() refused an apostrophe in a comment: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
}
