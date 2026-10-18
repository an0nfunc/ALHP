package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testRef is the tag the tests clone and fetch.
const testRef = "1-1"

const testSrcinfo = `pkgbase = libsigc++
	pkgver = 2.12.1
	pkgrel = 1
	arch = x86_64
	depends = glibc

pkgname = libsigc++
`

// testUpstream is newUpstream without the global conf, so tests can run in
// parallel.
func testUpstream(t *testing.T, baseURL string, clone func(ctx context.Context, url, ref, dir string) error) *upstream {
	t.Helper()

	return &upstream{
		baseURL:    baseURL,
		client:     &http.Client{Timeout: srcinfoTimeout},
		clone:      clone,
		cacheDir:   t.TempDir(),
		maxRetries: 3,
		baseDelay:  time.Millisecond,
		srcinfos:   make(map[string]*onceResult),
		trees:      make(map[string]*onceResult),
	}
}

// fakeClone stands in for git: it writes a PKGBUILD into dir and counts calls.
func fakeClone(calls *atomic.Int64) func(ctx context.Context, url, ref, dir string) error {
	return func(_ context.Context, _, ref, dir string) error {
		calls.Add(1)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}

		return os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgver="+ref+"\n"), 0o600)
	}
}

// TestGitCommandIdentifiesALHP pins what every git call to gitlab.archlinux.org
// carries: the User-Agent, no credential prompt to hang on, and a cancel that
// reaches git-remote-https rather than only git itself.
func TestGitCommandIdentifiesALHP(t *testing.T) {
	t.Parallel()

	cmd := gitCommand(t.Context(), "/nonexistent", "status")
	for _, want := range []string{"GIT_HTTP_USER_AGENT=" + upstreamUserAgent, "GIT_TERMINAL_PROMPT=0"} {
		if !slices.Contains(cmd.Env, want) {
			t.Errorf("git environment lacks %q", want)
		}
	}
	if cmd.Dir != "/nonexistent" {
		t.Errorf("Dir = %q, want /nonexistent", cmd.Dir)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.Cancel == nil || cmd.WaitDelay == 0 {
		t.Error("git does not run in its own process group with a group kill on cancel and a WaitDelay")
	}
}

func TestFetchSrcinfo(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		requests []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		if got := r.Header.Get("User-Agent"); got != upstreamUserAgent {
			t.Errorf("User-Agent = %q, want %q", got, upstreamUserAgent)
		}
		_, _ = w.Write([]byte(testSrcinfo))
	}))
	defer srv.Close()

	u := testUpstream(t, srv.URL, nil)

	first, err := u.fetchSrcinfo(t.Context(), "libsigc++", "2.12.1-1")
	if err != nil {
		t.Fatalf("fetchSrcinfo: %v", err)
	}
	second, err := u.fetchSrcinfo(t.Context(), "libsigc++", "2.12.1-1")
	if err != nil {
		t.Fatalf("second fetchSrcinfo: %v", err)
	}
	if _, err := u.fetchSrcinfo(t.Context(), "libsigc++", "main"); err != nil {
		t.Fatalf("fetchSrcinfo at another ref: %v", err)
	}

	want := []string{"/libsigcplusplus/-/raw/2.12.1-1/.SRCINFO", "/libsigcplusplus/-/raw/main/.SRCINFO"}
	mu.Lock()
	if !slices.Equal(requests, want) {
		t.Errorf("requests = %q, want %q", requests, want)
	}
	mu.Unlock()

	// each march gets its own struct, since build() goes on working on it
	first.Depends[0].Value = "changed"
	first.Pkgver = "changed"
	if second.Pkgver != "2.12.1" || second.Depends[0].Value != "glibc" {
		t.Errorf("changing one caller's srcinfo reached another's: %+v", second.PackageBase)
	}
}

func TestFetchSrcinfoRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxSrcinfoSize+1))
	}))
	defer srv.Close()

	if _, err := testUpstream(t, srv.URL, nil).fetchSrcinfo(t.Context(), "pkg", testRef); err == nil {
		t.Fatal("fetchSrcinfo accepted a body over maxSrcinfoSize")
	}
}

func TestFetchSrcinfoRefusesInvalidMeta(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(testSrcinfo))
	}))
	defer srv.Close()

	u := testUpstream(t, srv.URL, nil)
	for _, tc := range []struct{ pkgbase, ref string }{{"..", testRef}, {testPkgbase, "../../x"}, {testPkgbase, "a?b"}} {
		if _, err := u.fetchSrcinfo(t.Context(), tc.pkgbase, tc.ref); !errors.Is(err, ErrInvalidMeta) {
			t.Errorf("fetchSrcinfo(%q, %q) = %v, want ErrInvalidMeta", tc.pkgbase, tc.ref, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("invalid meta reached gitlab %d times", n)
	}
}

func TestTreeClonesOncePerKey(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", fakeClone(&calls))

	var wg sync.WaitGroup
	dirs := make([]string, 8)
	for i := range dirs {
		wg.Go(func() {
			dir, err := u.tree(t.Context(), "pkg", testRef)
			if err != nil {
				t.Errorf("tree: %v", err)
			}
			dirs[i] = dir
		})
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Errorf("%d concurrent callers on one key cloned %d times, want 1", len(dirs), n)
	}
	if want := filepath.Join(u.cacheDir, "pkg", testRef); slices.ContainsFunc(dirs, func(d string) bool { return d != want }) {
		t.Errorf("tree dirs = %q, want all %q", dirs, want)
	}

	if _, err := u.tree(t.Context(), "pkg", "main"); err != nil {
		t.Fatalf("tree at another ref: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("another ref cloned %d times in total, want 2", n)
	}
}

func TestTreeCachesFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", func(context.Context, string, string, string) error {
		calls.Add(1)
		return errors.New("fatal: unable to access")
	})
	u.maxRetries = 0

	for range 3 {
		if _, err := u.tree(t.Context(), "pkg", testRef); err == nil {
			t.Fatal("tree succeeded on a failing clone")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("a failed key was cloned %d times, want 1", n)
	}
}

func TestTreeRefusesInvalidMeta(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", fakeClone(&calls))

	for _, tc := range []struct{ pkgbase, ref string }{{"..", testRef}, {"pkg", "../../x"}, {"pkg", ""}} {
		_, err := u.tree(t.Context(), tc.pkgbase, tc.ref)
		if !errors.Is(err, ErrInvalidMeta) {
			t.Errorf("tree(%q, %q) = %v, want ErrInvalidMeta", tc.pkgbase, tc.ref, err)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("invalid meta reached the clone %d times", n)
	}
}

// TestSetupBuildDirCopiesCachedTree covers what the per-march copy exists for:
// the build edits its tree in place, and the cached checkout every other march
// copies from must not see it.
// not parallel: withConf mutates the package-level conf
func TestSetupBuildDirCopiesCachedTree(t *testing.T) { //nolint:paralleltest
	withConf(t, nil)
	conf.Basedir.Work = t.TempDir()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", fakeClone(&calls))

	setup := func(march string) string {
		t.Helper()
		p := &ProtoPackage{Pkgbase: "pkg", Version: testRef, March: march, State: &StateInfo{TagVer: testRef}}
		dir, err := p.setupBuildDir(t.Context(), u)
		if err != nil {
			t.Fatalf("setupBuildDir(%s): %v", march, err)
		}
		if p.Pkgbuild != filepath.Join(dir, "PKGBUILD") {
			t.Errorf("Pkgbuild = %q, want it inside %q", p.Pkgbuild, dir)
		}

		return dir
	}

	v3 := setup("x86-64-v3")
	if want := filepath.Join(conf.Basedir.Work, buildDir, "x86-64-v3", "pkg-"+testRef); v3 != want {
		t.Errorf("build dir = %q, want %q", v3, want)
	}
	if err := os.Truncate(filepath.Join(v3, "PKGBUILD"), 0); err != nil {
		t.Fatal(err)
	}

	cached, err := os.ReadFile(filepath.Join(u.cacheDir, "pkg", testRef, "PKGBUILD"))
	if err != nil || len(cached) == 0 {
		t.Fatalf("editing a march's PKGBUILD reached the cached checkout (%q, %v)", cached, err)
	}

	v4 := setup("x86-64-v4")
	if got, err := os.ReadFile(filepath.Join(v4, "PKGBUILD")); err != nil || !bytes.Equal(got, cached) {
		t.Errorf("second march's PKGBUILD = %q, %v; want %q", got, err, cached)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("two marches cloned %d times, want 1", n)
	}
}

// not parallel: withConf mutates the package-level conf
func TestNewUpstreamStartsEmpty(t *testing.T) { //nolint:paralleltest
	withConf(t, nil)

	dir := filepath.Join(t.TempDir(), sourceCacheDir)
	stale := filepath.Join(dir, "pkg", testRef)
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}

	u, err := newUpstream(dir)
	if err != nil {
		t.Fatalf("newUpstream: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("newUpstream kept a stale checkout: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("newUpstream did not create its dir: %v", err)
	}

	u.close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("close left the cache dir behind: %v", err)
	}
}
