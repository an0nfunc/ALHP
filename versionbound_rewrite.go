package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Morganamilo/go-srcinfo"
	log "github.com/sirupsen/logrus"
)

// Rewriting the upper-bounded conflicts/replaces entries our pkgrel bump defeats.
//
// See versionbound.go for the failure this fixes. The transform is exact rather
// than a fudge: the only versions increasePkgRel publishes are V-R.N, so
//
//	name<=V-R   becomes   name<V-(R+1)
//
// which every build number satisfies (3.26.4-5.1 < 3.26.4-6) while upstream's
// own V-(R+1) stays excluded, because the operator is strict.
//
// PKGBUILD text is rewritten here, which the rest of ALHP deliberately avoids:
// the only other edit is rePkgRel, line-anchored on a variable every PKGBUILD
// must define. What makes this one acceptable is that the result is proven before
// the package can ship, by prepareBoundRewrite's three assertions and the
// artifact check in checkArtifactBounds. A rewrite that cannot be proven is
// reverted and the package builds exactly as it does today.
//
// Scope is deliberately narrow. Only `<=` is rewritten:
//
//   - `<` cannot be fixed. Against a fractional bound the version upstream
//     excludes and the version we publish are the same string.
//   - `=` would need an AND of two constraints, which a single pacman entry
//     cannot express.
//
// Both are also almost always written without a pkgrel, which makes them immune
// anyway: pacman compares only as far as the bound reaches, so a build number
// appended past it cannot change the result.

// errPkgbuildDirty reports a PKGBUILD left neither original nor proven, which is
// the one bound-rewrite failure the build must not continue through.
var errPkgbuildDirty = errors.New("PKGBUILD left in an unverified state")

// maxPkgRelDigits bounds the pkgrel rewriteLEBound will increment.
const maxPkgRelDigits = 9

// maxPkgbuildSize bounds the text boundSpans will scan. Its paren handling is
// quadratic on an unbalanced run, so the cap sets the worst case: a megabyte of
// "(" takes minutes of one core, 256 KiB well under a minute. The largest real
// PKGBUILD is an order of magnitude below this, so refusing above it costs
// nothing real.
const maxPkgbuildSize = 256 << 10

var (
	// reBoundSpan finds the head of a conflicts/replaces array assignment. Only
	// the head is matched here; boundSpans walks the parens itself, because an
	// array can span lines and carry quoted parens.
	// The optional suffix covers the arch-dependent form (conflicts_x86_64).
	// go-srcinfo resolves those into targets, so leaving them unscoped would make
	// a file carrying one fail assertion A and abandon its other bounds too
	reBoundSpan = regexp.MustCompile(`(?m)^[ \t]*(?:conflicts|replaces)(?:_[a-z0-9_]+)?[ \t]*\+?=[ \t]*`)
	// reDottedPkgRel matches a pkgrel we must refuse, see rewriteLEBound.
	reDottedPkgRel = regexp.MustCompile(`^\d+\.\d+$`)
	// reHeredoc matches a heredoc operator, capturing the tab-stripping dash and
	// the terminator. \\? accepts the backslash-quoted terminator form, which bash
	// treats exactly like a single-quoted one. A `<<<` herestring is excluded by
	// isHerestring rather than by a leading [^<] in the pattern: a group that
	// consumes the byte before the operator makes FindAll, which does not overlap
	// matches, skip the second operator of an abutting `<<A<<B`.
	reHeredoc = regexp.MustCompile(`<<(-?)[ \t]*(\\?[A-Za-z_][A-Za-z0-9_]*|'[^']+'|"[^"]+")`)
	// reHeredocAny matches a heredoc operator whatever its delimiter looks like,
	// so heredocRegions can tell "not a heredoc" from "a heredoc reHeredoc cannot
	// name". Same herestring handling as above. The class excludes only the
	// newline, which cannot start a delimiter, rather than \s: bash's blanks are
	// space and tab alone, so a form feed is an ordinary word character there and
	// a delimiter starting with one has to stay visible to this pass.
	reHeredocAny = regexp.MustCompile(`<<-?[ \t]*[^<\n]`)
)

// rewriteLEBound turns an upper bound into the strict bound one upstream pkgrel
// above it, reporting false for the bounds that must be left alone.
//
// The decomposition matches splitPkgRel and upstreamVersion, the last
// dot-separated component of pkgrel, so the increment and the build-number strip
// agree by construction. Splitting on the last dash leaves an epoch untouched,
// so "1:3.26.4-5" needs no special case.
//
// A bound whose pkgrel already carries a dot is refused, and this is the case
// worth stating plainly because the obvious generalization is wrong: we do not
// append a build number, increasePkgRel REPLACES the trailing component, so
// upstream 5.2 publishes as 5.N. "<1.2-5.3" therefore fails to cover our own
// 1.2-5.3, and no bound can separate our build from a version upstream
// deliberately excluded. makepkg's check_pkgrel permits only integer[.integer],
// so V-R.N is effectively ours alone, but the refusal has to be explicit.
func rewriteLEBound(bound string) (string, bool) {
	dash := strings.LastIndex(bound, "-")
	if dash < 0 {
		// no pkgrel to compare against, so our build number is invisible to it
		return "", false
	}

	pkgrel := bound[dash+1:]
	if reDottedPkgRel.MatchString(pkgrel) {
		return "", false
	}

	// Atoi accepts a pkgrel that wraps negative on +1, and the wrapped bound
	// carries no <= for assertion C to catch, so it would ship. No real pkgrel is
	// anywhere near this wide
	if len(pkgrel) > maxPkgRelDigits {
		return "", false
	}

	rel, err := strconv.Atoi(pkgrel)
	if err != nil {
		return "", false
	}

	return bound[:dash+1] + strconv.Itoa(rel+1), true
}

// rewrittenBound returns what a dependency entry becomes once its upper bound is
// rewritten, reporting false for the entries this must leave alone.
//
// Shared by the rewrite and the artifact check so the two cannot disagree about
// what counts as rewritable: the artifact check exists to flag a bound the
// rewrite should have caught, which it can only do if it recognizes the same set.
//
// A soname-shaped name is refused so an ELF class can never be read as a pkgrel.
// Nothing upstream currently needs it: soname entries are written with `=`
// (at-spi2-core ships `libatk-1.0.so=0-64`), so the `<=` split already excludes
// every one of them, and the live sync DBs carry no `<=` entry containing `.so`.
// It stays because the cost is one suffix test and the failure it prevents is a
// bound rewritten from an architecture.
func rewrittenBound(dep string) (string, bool) {
	name, bound, found := strings.Cut(dep, "<=")
	if !found || strings.HasSuffix(name, ".so") {
		return "", false
	}

	next, ok := rewriteLEBound(bound)
	if !ok {
		return "", false
	}

	return name + "<" + next, true
}

// boundTarget is one rewrite to perform: the literal as it appears in the
// PKGBUILD, what it becomes, and how many srcinfo entries carry it.
type boundTarget struct {
	old     string
	new     string
	entries int
}

// boundTargets reads the rewritable bounds out of a parsed srcinfo, keyed by the
// literal to replace. Derived from the srcinfo rather than the file text so the
// target set is a pure function of what makepkg resolved, which is what the
// assertions below can actually bind to.
func boundTargets(si *srcinfo.Srcinfo) map[string]*boundTarget {
	targets := make(map[string]*boundTarget)

	collect := func(deps []srcinfo.ArchString) {
		for _, dep := range deps {
			next, ok := rewrittenBound(dep.Value)
			if !ok {
				continue
			}

			if t, seen := targets[dep.Value]; seen {
				t.entries++
				continue
			}
			targets[dep.Value] = &boundTarget{old: dep.Value, new: next, entries: 1}
		}
	}

	collect(si.Conflicts)
	collect(si.Replaces)
	for i := range si.Packages {
		collect(si.Packages[i].Conflicts)
		collect(si.Packages[i].Replaces)
	}

	return targets
}

// boundSpans returns the byte ranges of every conflicts/replaces array value in
// the PKGBUILD, so a substitution can be confined to them.
//
// Scoping is what keeps the edit honest. The assertions below prove the METADATA
// came out right, and they cannot see a literal edited somewhere that produces no
// metadata at all: a heredoc the package installs, a sed pattern, a comment. One
// literal in a global helper array referenced by several split packages yields
// several srcinfo entries, which leaves the count assertion enough slack to admit
// a second edit elsewhere in the file. Confining the edit to these spans removes
// the places such an edit could hide, and costs no coverage: every bound upstream
// actually writes lives in one of these arrays.
//
// Scoping on the assignment head alone is not sufficient, because a heredoc body
// can contain a line that looks exactly like one. That shape produces no srcinfo
// entry, so no assertion downstream could catch it, which is why heredoc bodies
// are excluded here rather than left to the oracles.
//
// An unterminated span means the file is not shaped the way this assumes, so the
// caller refuses it rather than guessing.
//
// What this is NOT is a proof. reBoundSpan, reHeredoc, reHeredocAny and
// arithmeticRegions are separate passes over raw text that together approximate
// bash's lexer rather than implement it, so the set of constructs they mis-scan
// is open rather than enumerable. Any of them can leave a heredoc body inside a
// span, and a delimiter this does name is not guaranteed to be the one bash
// reads. What has been found so far:
//
//   - a `((` inside a string, paired with a later `))`, forms a false arithmetic
//     region that can hide a heredoc operator, leaving that body editable.
//   - reBoundSpan matches an assignment head wherever it sits, including inside a
//     multi-line string, so a conflicts= line in the middle of one reads as a real
//     array.
//   - a backtick or a `${` opened after an operator and closed on the next line
//     carries the logical line past what endsLogicalLine tracks, so a second
//     operator there is read as body text.
//   - the tag is normalized by stripping every leading and trailing quote and
//     backslash where bash removes one quoting layer, so `<<'EOF\'` is read as
//     EOF rather than EOF\ and the region ends at the wrong line.
//
// That list is what has been looked for, not what is there.
//
// The damage is bounded by the conditions rather than by the scan. Each of these
// needs a PKGBUILD written against it and enough srcinfo entry count to absorb the
// extra occurrences, which takes a derived array (`conflicts=("${replaces[@]}")`),
// and the worst it yields is `<=` to `<` with the pkgrel incremented, in text that
// same author wrote. That grants a hostile packager nothing: the host already
// sources their PKGBUILD as the daemon user on every build. For everyone else the
// scans fail closed, refusing the file byte-identical, which costs the fix for one
// package and nothing else. The guarantees the rewrite actually rests on are the
// srcinfo assertions and the artifact check, and none of them consult this.
//
// Closing the class rather than narrowing it means one left-to-right pass
// carrying quote, comment, heredoc and arithmetic state, emitting assignment
// heads only in command position. That is a rewrite of this function, not a
// patch to it, and it is the only route to an actual proof. Until then
// checkArtifactBounds and reportDefeatedBounds are the independent backstops:
// both read the built package rather than the recipe, so neither depends on any
// of this being right.
func boundSpans(text string) ([][2]int, error) {
	heredocs, err := heredocRegions(text)
	if err != nil {
		return nil, err
	}

	var spans [][2]int
	for _, head := range reBoundSpan.FindAllStringIndex(text, -1) {
		// an array assignment inside a heredoc body is data the package ships,
		// not metadata. It produces no srcinfo entry, so no assertion downstream
		// could notice it being edited
		if within(heredocs, head[0]) {
			return nil, fmt.Errorf("conflicts/replaces assignment at byte %d is inside a heredoc", head[0])
		}
		start := head[1]
		if start >= len(text) {
			return nil, fmt.Errorf("array assignment at byte %d has no value", head[0])
		}

		// a bare scalar assignment ends at the line
		if text[start] != '(' {
			end := strings.IndexByte(text[start:], '\n')
			if end < 0 {
				end = len(text) - start
			}
			spans = append(spans, [2]int{start, start + end})
			continue
		}

		end, err := scanArray(text, start)
		if err != nil {
			return nil, err
		}
		spans = append(spans, [2]int{start, end})
	}

	// substituteBounds walks these as disjoint and ascending, and slices
	// backwards if they are not. A nested assignment produces exactly that: a
	// head reached while scanArray is still inside an earlier array, e.g. inside
	// a command substitution. Refusing keeps a malformed shape from panicking a
	// daemon that has no recover anywhere
	for i := 1; i < len(spans); i++ {
		if spans[i][0] < spans[i-1][1] {
			return nil, fmt.Errorf("conflicts/replaces assignment at byte %d is nested inside the one at byte %d",
				spans[i][0], spans[i-1][0])
		}
	}

	return spans, nil
}

// endsLogicalLine reports whether the newline at nl terminates the logical line,
// rather than being escaped by a trailing backslash or swallowed by a quote or a
// `$(` still open on it. Bash chains heredoc bodies per logical line, so an
// operator past a continuation lands inside the first body's region, where it is
// skipped as ordinary text and its own body goes unprotected. Refusing costs
// nothing real: a heredoc operator on a continued line does not occur upstream.
func endsLogicalLine(text string, nl int) bool {
	start := strings.LastIndexByte(text[:nl], '\n') + 1

	var quote byte
	depth := 0
	commented := false

scan:
	for i := start; i < nl; i++ {
		c := text[i]

		switch quote {
		case '\'':
			if c == '\'' {
				quote = 0
			}

			continue
		case '"':
			switch c {
			case '\\':
				i++
			case '"':
				quote = 0
			}

			continue
		}

		switch c {
		case '\\':
			i++
		case '\'', '"':
			quote = c
		case '#':
			// the rest of the line is comment text, so nothing in it opens a quote
			// or a paren and an apostrophe there is not an unterminated string
			if i == start || text[i-1] == ' ' || text[i-1] == '\t' {
				commented = true

				break scan
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}

	// checked before the comment, not after: a `$(` opened ahead of the comment
	// still carries the line past its newline, so `cat <<A $(echo # x` continues
	if quote != 0 || depth > 0 {
		return false
	}

	// bash does not continue a comment line, so a trailing backslash inside one
	// escapes nothing
	if commented {
		return true
	}

	// an odd run of backslashes escapes the newline itself
	run := 0
	for i := nl - 1; i >= start && text[i] == '\\'; i-- {
		run++
	}

	return run%2 == 0
}

// endsWord reports whether the byte at i terminates a bash word, i.e. is one of
// the metacharacters or whitespace that delimit one. End of text counts.
func endsWord(text string, i int) bool {
	if i >= len(text) {
		return true
	}

	switch text[i] {
	case ' ', '\t', '\n', '\r', '|', '&', ';', '(', ')', '<', '>':
		return true
	}

	return false
}

// isHerestring reports whether the operator at i is really the tail of a `<<<`
// herestring, which takes its input from the word after it and has no body.
func isHerestring(text string, i int) bool {
	return i > 0 && text[i-1] == '<'
}

// heredocRegions returns the byte ranges of every heredoc body in the text.
//
// Recognizes `<<` and `<<-`, with the terminator bare, single- or double-quoted,
// or backslash-quoted. Three things are deliberately not heredocs and are
// excluded, because treating any of them as one refuses a whole package and names
// a construct that is not there:
//
//   - `<<<` herestrings, which isHerestring rules out.
//   - `<<` inside an arithmetic expansion, where it is a left shift. `1 << bits`
//     is otherwise indistinguishable from an operator followed by a terminator.
//   - `<<` inside a heredoc body already found, which is ordinary text there.
//
// An unterminated heredoc is an error rather than a guess, matching how scanArray
// treats an unterminated quote.
func heredocRegions(text string) ([][2]int, error) {
	arithmetic := arithmeticRegions(text)

	var regions [][2]int
	classified := make(map[int]struct{})
	// bodies of operators sharing one line are consecutive, not coincident: bash
	// reads the first body, then the next starts where it ended. Giving them all
	// the same start lets a line inside body A terminate region B, which leaves
	// the real body B editable while the file looks handled.
	var lineBody, prevEnd int
	for _, m := range reHeredoc.FindAllStringSubmatchIndex(text, -1) {
		operator := m[0]
		if isHerestring(text, operator) || within(arithmetic, operator) || within(regions, operator) {
			continue
		}
		// bash ends the delimiter at a metacharacter and applies quote removal to
		// the whole word, so anything else after the capture continues the token
		// and the capture named only its head: `<<E\OF`, `<<E'O'F` and `<<EOF-x`
		// are delimiters EOF, EOF and EOF-x, not E, E and EOF. Leave those
		// unclassified so the pass below refuses them, rather than protecting a
		// span that ends at the wrong line
		if !endsWord(text, m[5]) {
			continue
		}
		classified[operator] = struct{}{}

		// the first body on a line starts after it, each later one after its
		// predecessor's terminator
		nl := strings.IndexByte(text[m[1]:], '\n')
		if nl < 0 {
			return nil, fmt.Errorf("heredoc at byte %d has no body", operator)
		}
		if !endsLogicalLine(text, m[1]+nl) {
			return nil, fmt.Errorf("heredoc at byte %d sits on a continued line", operator)
		}
		start := m[1] + nl + 1
		if start == lineBody {
			start = prevEnd
		} else {
			lineBody = start
		}

		tag := strings.Trim(text[m[4]:m[5]], "'\"\\")
		end, err := heredocEnd(text, start, tag, text[m[2]:m[3]] == "-")
		if err != nil {
			return nil, err
		}
		prevEnd = end
		regions = append(regions, [2]int{start, end})
	}

	// A delimiter reHeredoc cannot name would otherwise fall through as "no
	// heredoc here" and leave the body editable, which is the one escape the
	// heredoc exclusion exists to close. Refuse the file instead. Covers both the
	// forms that never match, `<<$TAG`, and the ones the loop above dropped
	// because it could only name their head, `<<E\OF`.
	for _, m := range reHeredocAny.FindAllStringIndex(text, -1) {
		operator := m[0]
		if isHerestring(text, operator) || within(arithmetic, operator) || within(regions, operator) {
			continue
		}
		if _, ok := classified[operator]; !ok {
			return nil, fmt.Errorf("unrecognized heredoc delimiter at byte %d", operator)
		}
	}

	return regions, nil
}

// heredocEnd returns the offset just past the line closing a heredoc body that
// starts at body and terminates on tag. Only the `<<-` form permits the
// terminator to be indented, and only with tabs, so plain heredocs must match it
// exactly or the region ends early and leaves part of the body unprotected.
func heredocEnd(text string, body int, tag string, stripTabs bool) (int, error) {
	for at := body; at < len(text); {
		lineEnd := strings.IndexByte(text[at:], '\n')
		if lineEnd < 0 {
			lineEnd = len(text) - at
		}
		line := text[at : at+lineEnd]
		if stripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == tag {
			return at + lineEnd, nil
		}
		at += lineEnd + 1
	}

	return 0, fmt.Errorf("heredoc body at byte %d is never terminated by %q", body, tag)
}

// arithmeticRegions returns the ranges of arithmetic expansions, $(( )) and
// (( )), where `<<` is a left shift rather than a heredoc operator. scanArray
// does the paren matching, so quoting inside the expansion is handled the same
// way it is for an array.
//
// The entry condition is raw text: a `((` inside a string counts, so a quoted
// `((` paired with a later `))` forms a region that is not an expansion at all.
// That can only mask a heredoc operator, never reveal one, so it fails toward
// editing rather than refusing. See the residual note on boundSpans.
func arithmeticRegions(text string) [][2]int {
	var regions [][2]int
	for i := 0; i+1 < len(text); i++ {
		if text[i] != '(' || text[i+1] != '(' {
			continue
		}
		end, err := scanArray(text, i)
		if err != nil {
			// an unbalanced paren here is not ours to reject: boundSpans refuses
			// only on the arrays it actually needs to delimit
			continue
		}
		regions = append(regions, [2]int{i, end})
		i = end - 1
	}

	return regions
}

// within reports whether offset falls inside any of the regions.
func within(regions [][2]int, offset int) bool {
	for _, r := range regions {
		if offset >= r[0] && offset < r[1] {
			return true
		}
	}

	return false
}

// scanArray returns the offset just past the parenthesis closing the array that
// opens at text[open], honoring both quoting styles and comments so a paren
// inside them cannot end the span early.
func scanArray(text string, open int) (int, error) {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '\'':
			next := strings.IndexByte(text[i+1:], '\'')
			if next < 0 {
				return 0, fmt.Errorf("unterminated single quote at byte %d", i)
			}
			i += next + 1
		case '"':
			closing := closingDoubleQuote(text, i)
			if closing < 0 {
				return 0, fmt.Errorf("unterminated double quote at byte %d", i)
			}
			i = closing
		case '#':
			// only a comment at a word boundary, so a '#' inside a version is safe.
			// '(' is one of them: bash treats it as a metacharacter and `((#` is
			// not valid bash, so a '#' directly after one always opens a comment.
			// Reading it as content instead flips quote parity and runs the span
			// past the array's own close
			if i == 0 || text[i-1] == ' ' || text[i-1] == '\t' || text[i-1] == '\n' || text[i-1] == '(' {
				next := strings.IndexByte(text[i:], '\n')
				if next < 0 {
					return 0, fmt.Errorf("unterminated comment at byte %d", i)
				}
				i += next
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}

	return 0, fmt.Errorf("unterminated array opening at byte %d", open)
}

// closingDoubleQuote returns the offset of the '"' closing the one at open, or -1
// if the string never closes. Backslash escapes count inside double quotes,
// unlike single, so an escaped quote does not end the string.
func closingDoubleQuote(text string, open int) int {
	for i := open + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}

	return -1
}

// substituteBounds rewrites every target inside the given spans and reports how
// many replacements each one took.
//
// Matching is delimiter-anchored, which is not defensive but load-bearing: a
// plain replace of "geocode-glib-2<=3.26.4-5" also eats the prefix of
// "geocode-glib-2<=3.26.4-51", and vercmp puts 3.26.4-51 above 3.26.4-5, so that
// would silently loosen a bound to a version it was written to exclude.
func substituteBounds(text string, spans [][2]int,
	targets map[string]*boundTarget,
) (rewritten string, counts map[string]int) {
	counts = make(map[string]int, len(targets))
	var out strings.Builder
	prev := 0

	// sorted, so two targets that can overlap resolve the same way every run.
	// Overlap needs a pkgname starting with a delimiter, which pacman forbids, but
	// map order would make any such case irreproducible
	old := slices.Sorted(maps.Keys(targets))

	for _, span := range spans {
		out.WriteString(text[prev:span[0]])
		segment := text[span[0]:span[1]]
		for _, key := range old {
			t := targets[key]
			var n int
			segment, n = replaceDelimited(segment, t.old, t.new)
			counts[t.old] += n
		}
		out.WriteString(segment)
		prev = span[1]
	}
	out.WriteString(text[prev:])

	return out.String(), counts
}

// replaceDelimited replaces old with next wherever old is a whole token, meaning
// bounded on each side by a quote, a paren, whitespace, or the segment edge.
func replaceDelimited(segment, old, next string) (result string, count int) {
	var out strings.Builder
	prev := 0

	for {
		idx := strings.Index(segment[prev:], old)
		if idx < 0 {
			break
		}
		at := prev + idx
		end := at + len(old)

		if isBoundEdge(segment, at-1) && isBoundEdge(segment, end) {
			out.WriteString(segment[prev:at])
			out.WriteString(next)
			count++
		} else {
			out.WriteString(segment[prev:end])
		}
		prev = end
	}
	out.WriteString(segment[prev:])

	return out.String(), count
}

// isBoundEdge reports whether the byte at i ends a dependency token. Out of range
// counts as an edge, so a bound flush against the start or end of a span matches.
func isBoundEdge(segment string, i int) bool {
	if i < 0 || i >= len(segment) {
		return true
	}
	switch segment[i] {
	case '\'', '"', '(', ')', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

// wantSrcinfo builds the srcinfo the rewrite is supposed to produce: before, with
// the target literals replaced in conflicts and replaces and nowhere else.
//
// Only conflicts and replaces are recomputed, everything else is carried over
// from before as it stands; comparing that against the real thing is what proves
// nothing else moved. Packages is copied first because before is the comparison
// baseline, so assigning the per-split fields in place would mutate it.
func wantSrcinfo(before *srcinfo.Srcinfo, targets map[string]*boundTarget) *srcinfo.Srcinfo {
	want := *before
	want.Conflicts = rewriteArchStrings(before.Conflicts, targets)
	want.Replaces = rewriteArchStrings(before.Replaces, targets)

	want.Packages = make([]srcinfo.Package, len(before.Packages))
	copy(want.Packages, before.Packages)
	for i := range want.Packages {
		want.Packages[i].Conflicts = rewriteArchStrings(before.Packages[i].Conflicts, targets)
		want.Packages[i].Replaces = rewriteArchStrings(before.Packages[i].Replaces, targets)
	}

	return &want
}

// rewriteArchStrings maps a dependency list through the targets, preserving a nil
// slice as nil. That distinction matters: reflect.DeepEqual treats nil and an
// empty slice as different, so returning an empty slice where the parser left nil
// fails the comparison for every package.
func rewriteArchStrings(deps []srcinfo.ArchString, targets map[string]*boundTarget) []srcinfo.ArchString {
	if deps == nil {
		return nil
	}

	out := make([]srcinfo.ArchString, len(deps))
	for i, dep := range deps {
		if t, ok := targets[dep.Value]; ok {
			dep.Value = t.new
		}
		out[i] = dep
	}

	return out
}

// prepareBoundRewrite rewrites the upper-bounded conflicts/replaces entries in
// this package's PKGBUILD, keeping the result only if it can be proven correct.
//
// Must run before increasePkgRel, so the bound edit is the only one in flight,
// and before nextBuildNo, so a refusal costs no build number.
//
// The "before" snapshot is whatever p.Srcinfo already holds, which in production
// is the committed .SRCINFO genQueue fetched over HTTP rather than output from
// genSrcinfo. Assertion B therefore compares two producers, and a push landing
// between that fetch and the clone shows up as "changed more than the bounds"
// rather than as the version skew it really is. That fails closed, which is why
// it is acceptable, but it is the first thing to check when the message appears.
//
// A refusal is not an error: the package builds exactly as it does today, which
// is a package that still carries the bug and gets reported by
// reportDefeatedBounds rather than a package that goes missing.
func (p *ProtoPackage) prepareBoundRewrite(ctx context.Context) error {
	if p.Srcinfo == nil {
		if err := p.genSrcinfo(ctx); err != nil {
			return fmt.Errorf("error generating srcinfo: %w", err)
		}
	}

	targets := boundTargets(p.Srcinfo)
	if len(targets) == 0 {
		return nil
	}

	// stat first, so an oversize PKGBUILD is refused before it is allocated
	info, err := os.Stat(p.Pkgbuild)
	if err != nil {
		return err
	}
	if info.Size() > maxPkgbuildSize {
		return fmt.Errorf("PKGBUILD is %d bytes, above the %d the bound scan will read", info.Size(), maxPkgbuildSize)
	}

	original, err := os.ReadFile(p.Pkgbuild)
	if err != nil {
		return err
	}
	if len(original) > maxPkgbuildSize {
		return fmt.Errorf("PKGBUILD grew to %d bytes, above the %d the bound scan will read", len(original), maxPkgbuildSize)
	}

	spans, err := boundSpans(string(original))
	if err != nil {
		return fmt.Errorf("cannot delimit conflicts/replaces arrays: %w", err)
	}

	rewritten, counts := substituteBounds(string(original), spans, targets)

	// assertion A: every target was found, and never more often than the srcinfo
	// says it occurs. More textual hits than entries means the literal also lives
	// somewhere the srcinfo cannot see, so the proof below would not cover it
	for _, t := range targets {
		switch {
		case counts[t.old] == 0:
			return fmt.Errorf("bound %q resolved by makepkg but not found in the PKGBUILD text", t.old)
		case counts[t.old] > t.entries:
			return fmt.Errorf("bound %q replaced %d times but carries only %d srcinfo entries",
				t.old, counts[t.old], t.entries)
		}
	}

	// defined before the write, because os.WriteFile truncates before it writes:
	// a failure partway leaves the PKGBUILD destroyed, and building against that
	// fails the package and purges what is published
	revert := func(cause error) error {
		if err := os.WriteFile(p.Pkgbuild, original, 0o644); err != nil { //nolint:gosec
			// the PKGBUILD is now neither the original nor a proven rewrite, so
			// the build must not proceed against it
			return fmt.Errorf("%w: %w (reverting it failed: %w)", errPkgbuildDirty, cause, err)
		}

		return cause
	}

	if err := os.WriteFile(p.Pkgbuild, []byte(rewritten), 0o644); err != nil { //nolint:gosec
		return revert(err)
	}

	after, err := p.reparseSrcinfo(ctx)
	if err != nil {
		return revert(err)
	}

	// assertion B: conflicts and replaces carry the rewritten bounds and every
	// other field, per-split and per-arch overrides included, is untouched
	if want := wantSrcinfo(p.Srcinfo, targets); !reflect.DeepEqual(want, after) {
		return revert(fmt.Errorf("rewrite changed more than the bounds in %s", p.Pkgbase))
	}

	// assertion C: nothing rewritable is left. Redundant given B, since want is
	// before with every <= form replaced by a < form and rewrittenBound never
	// matches those, so it is kept only as a cheap independent check that does
	// not share B's comparison
	if leftover := boundTargets(after); len(leftover) > 0 {
		return revert(fmt.Errorf("%d bound(s) in %s survived the rewrite", len(leftover), p.Pkgbase))
	}

	for _, t := range targets {
		log.Infof("[P] %s->%s rewrote bound %s -> %s", p.FullRepo, p.Pkgbase, t.old, t.new)
	}
	p.Srcinfo = after

	return nil
}

// reparseSrcinfo reads the srcinfo of the PKGBUILD as it stands now. genSrcinfo
// cannot be used because it caches on p.Srcinfo, which still holds the snapshot
// the comparison needs.
func (p *ProtoPackage) reparseSrcinfo(ctx context.Context) (*srcinfo.Srcinfo, error) {
	return printSrcinfo(ctx, p.Pkgbuild)
}

// artifactBounds reads the conflicts and replaces entries out of a built
// artifact's .PKGINFO.
//
// Key names differ from the srcinfo: pacman writes `conflict` singular and
// `replaces` plural. Both are read in one pass, since the cost here is
// decompressing the archive rather than matching the lines.
func artifactBounds(pkgFile string) ([]string, error) {
	values, err := Package(pkgFile).pkginfoValues("conflict", "replaces")
	if err != nil {
		return nil, err
	}

	return append(values["conflict"], values["replaces"]...), nil
}

// checkArtifactBounds reports rewritable bounds that survived into the built
// artifacts, and returns how many it found.
//
// This is the only check that sees the real bash evaluation. `makepkg
// --printsrcinfo` is a lint-grade approximation: extract_function_variable greps
// the `declare -f` body and evals each assignment in the PKGBUILD's GLOBAL scope,
// so a function-local variable resolves empty and a bound built from one is
// reported truncated at exit 0. prepareBoundRewrite's assertions all pass on such
// a package, because the bound it can see is not rewritable, while the artifact
// carries the real one.
//
// Reports without discarding, deliberately. A surviving bound means the artifact
// is what ALHP ships today, so removing it costs users a package and a rebuild
// would produce the same thing. Partial rewrites need no special handling either:
// pacman treats every partial state as at least as good as none. A rewritten
// replaces with a stale conflicts still removes the old package, and a rewritten
// conflicts with a stale replaces turns a mid-transaction file conflict into a
// prompt before anything is downloaded.
func (p *ProtoPackage) checkArtifactBounds() int {
	found := 0
	for _, pkgFile := range p.runtimePkgFiles() {
		bounds, err := artifactBounds(pkgFile)
		if err != nil {
			log.Warningf("[P] %s->%s unable to read artifact bounds: %v", p.FullRepo, p.Pkgbase, err)
			continue
		}

		for _, bound := range bounds {
			if next, ok := rewrittenBound(bound); ok {
				found++
				log.Warningf("[P] %s->%s published %s with %q, which our build numbers defeat; "+
					"expected %s", p.FullRepo, p.Pkgbase, filepath.Base(pkgFile), bound, next)
			}
		}
	}

	return found
}
