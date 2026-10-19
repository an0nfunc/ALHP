package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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
		baseURL:        baseURL,
		client:         newSrcinfoClient(),
		clone:          clone,
		cacheDir:       t.TempDir(),
		maxRetries:     3,
		attemptTimeout: time.Second,
		maxDuration:    time.Minute,
		maxDelay:       time.Millisecond,
		baseDelay:      time.Millisecond,
		cloneSlots:     make(chan struct{}, maxConcurrentClones),
		srcinfos:       make(map[string]*onceResult),
		trees:          make(map[string]*onceResult),
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
// carries: the User-Agent, no credential prompt to hang on, the locale the
// markers match, and a cancel that reaches git-remote-https rather than only git.
func TestGitCommandIdentifiesALHP(t *testing.T) {
	t.Parallel()

	cmd := gitCommand(t.Context(), "/nonexistent", "status")
	for _, want := range []string{"GIT_HTTP_USER_AGENT=" + upstreamUserAgent, "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "LC_ALL=C"} {
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

	if _, err := testUpstream(t, srv.URL, nil).fetchSrcinfo(t.Context(), testPkgbase, testRef); err == nil {
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
			dir, err := u.tree(t.Context(), testPkgbase, testRef)
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
	if want := filepath.Join(u.cacheDir, testPkgbase, testRef); slices.ContainsFunc(dirs, func(d string) bool { return d != want }) {
		t.Errorf("tree dirs = %q, want all %q", dirs, want)
	}

	if _, err := u.tree(t.Context(), testPkgbase, "main"); err != nil {
		t.Fatalf("tree at another ref: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("another ref cloned %d times in total, want 2", n)
	}
}

func TestTreeCachesFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", transientClone(&calls))
	u.maxRetries = 0

	for range 3 {
		if _, err := u.tree(t.Context(), testPkgbase, testRef); err == nil {
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

	for _, tc := range []struct{ pkgbase, ref string }{{"..", testRef}, {testPkgbase, "../../x"}, {testPkgbase, ""}} {
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
		p := &ProtoPackage{Pkgbase: testPkgbase, Version: testRef, March: march, State: &StateInfo{TagVer: testRef}}
		dir, err := p.setupBuildDir(t.Context(), u)
		if err != nil {
			t.Fatalf("setupBuildDir(%s): %v", march, err)
		}
		if p.Pkgbuild != filepath.Join(dir, "PKGBUILD") {
			t.Errorf("Pkgbuild = %q, want it inside %q", p.Pkgbuild, dir)
		}

		return dir
	}

	v3 := setup(testMarchV3)
	if want := filepath.Join(conf.Basedir.Work, buildDir, testMarchV3, testPkgbase+"-"+testRef); v3 != want {
		t.Errorf("build dir = %q, want %q", v3, want)
	}
	if err := os.Truncate(filepath.Join(v3, "PKGBUILD"), 0); err != nil {
		t.Fatal(err)
	}

	cached, err := os.ReadFile(filepath.Join(u.cacheDir, testPkgbase, testRef, "PKGBUILD"))
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
	stale := filepath.Join(dir, testPkgbase, testRef)
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
	if u.pace.interval != srcinfoInterval {
		t.Errorf("newUpstream paces .SRCINFO requests %s apart, want %s", u.pace.interval, srcinfoInterval)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("newUpstream did not create its dir: %v", err)
	}

	u.close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("close left the cache dir behind: %v", err)
	}
}

// statusServer answers every request with the status in status and counts them.
func statusServer(t *testing.T, status, requests *atomic.Int64) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)

	return srv
}

// TestFetchSrcinfoNotFoundIsAnAnswer guards the breaker against packages
// upstream has dropped: a 404 is gitlab answering, so it resets the count
// instead of adding to it.
func TestFetchSrcinfoNotFoundIsAnAnswer(t *testing.T) {
	t.Parallel()

	var status atomic.Int64
	u := testUpstream(t, statusServer(t, &status, new(atomic.Int64)).URL, nil)
	fetch := func(ref int) error {
		_, err := u.fetchSrcinfo(t.Context(), testPkgbase, strconv.Itoa(ref))
		return err
	}

	status.Store(http.StatusServiceUnavailable)
	for i := range maxUpstreamFailures - 1 {
		_ = fetch(i)
	}
	status.Store(http.StatusNotFound)
	if err := fetch(100); !errors.Is(err, errSourceUnavailable) {
		t.Errorf("404 = %v, want errSourceUnavailable", err)
	}
	status.Store(http.StatusServiceUnavailable)
	for i := range maxUpstreamFailures - 1 {
		_ = fetch(200 + i)
	}

	if u.open.Load() {
		t.Error("a 404 between failures did not reset the breaker")
	}
}

func TestFetchSrcinfoBreakerOpens(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		closed bool
	}{
		{"service unavailable", false},
		{"connection refused", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var status, requests atomic.Int64
			status.Store(http.StatusServiceUnavailable)
			srv := statusServer(t, &status, &requests)
			if tc.closed {
				srv.Close()
			}
			u := testUpstream(t, srv.URL, nil)

			for i := range maxUpstreamFailures {
				if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, strconv.Itoa(i)); errors.Is(err, ErrUpstreamUnavailable) {
					t.Fatalf("breaker open after %d failures, want %d", i, maxUpstreamFailures)
				}
			}
			sent := requests.Load()

			_, err := u.fetchSrcinfo(t.Context(), testPkgbase, "next")
			if !errors.Is(err, ErrUpstreamUnavailable) || !errors.Is(err, errSourceUnavailable) {
				t.Errorf("fetch after %d failures = %v, want ErrUpstreamUnavailable", maxUpstreamFailures, err)
			}
			if requests.Load() != sent {
				t.Error("an open breaker still sent a request")
			}
		})
	}
}

// failClone stands in for a git that fails every clone with msg.
func failClone(calls *atomic.Int64, msg string) func(ctx context.Context, url, ref, dir string) error {
	return func(context.Context, string, string, string) error {
		calls.Add(1)
		return errors.New(msg)
	}
}

// transientClone fails the way a network outage does.
func transientClone(calls *atomic.Int64) func(ctx context.Context, url, ref, dir string) error {
	return failClone(calls, "fatal: unable to access 'https://gitlab.archlinux.org/': Could not resolve host: gitlab.archlinux.org")
}

var (
	answeredMessages = []string{
		"fatal: Remote branch 1-1 not found in upstream origin",
		"fatal: repository 'https://gitlab.archlinux.org/archlinux/packaging/packages/gone.git/' not found",
		"fatal: could not read Username for 'https://gitlab.archlinux.org': No such device or address",
		"fatal: could not read Password: terminal prompts disabled",
		"fatal: unable to access 'https://gitlab.archlinux.org/': The requested URL returned error: 401",
		"fatal: unable to access 'https://gitlab.archlinux.org/': The requested URL returned error: 404",
	}
	refusedMessages = []string{
		"fatal: unable to access 'https://gitlab.archlinux.org/': The requested URL returned error: 403",
		"fatal: unable to access 'https://gitlab.archlinux.org/': The requested URL returned error: 429",
	}
)

// TestGitlabMarkersDisjoint keeps an answer from also reading as a refusal, and
// the reverse: one resets the breaker and the other opens it.
func TestGitlabMarkersDisjoint(t *testing.T) {
	t.Parallel()

	for _, msg := range answeredMessages {
		if !reGitlabAnswered.MatchString(msg) || reGitlabRefused.MatchString(msg) {
			t.Errorf("%q must be an answer and only an answer", msg)
		}
	}
	for _, msg := range refusedMessages {
		if !reGitlabRefused.MatchString(msg) || reGitlabAnswered.MatchString(msg) {
			t.Errorf("%q must be a refusal and only a refusal", msg)
		}
	}
}

// TestTreeAnsweredIsNotRetried covers each reGitlabAnswered marker: neither
// retried, since gitlab will say the same again, nor counted toward the breaker,
// which it resets.
func TestTreeAnsweredIsNotRetried(t *testing.T) {
	t.Parallel()

	for _, msg := range answeredMessages {
		t.Run(msg, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int64
			u := testUpstream(t, "https://example.invalid", failClone(&calls, msg))
			u.failures.Store(maxUpstreamFailures - 1)

			if _, err := u.tree(t.Context(), testPkgbase, testRef); !errors.Is(err, errSourceUnavailable) {
				t.Errorf("tree = %v, want errSourceUnavailable", err)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("cloned %d times, want 1", n)
			}
			if n := u.failures.Load(); n != 0 || u.open.Load() {
				t.Errorf("failures = %d, open = %v; want 0, false", n, u.open.Load())
			}
		})
	}
}

func TestTreeRetriesTransientFailure(t *testing.T) {
	t.Parallel()

	var calls, failed atomic.Int64
	fail, succeed := transientClone(&failed), fakeClone(&calls)
	u := testUpstream(t, "https://example.invalid", func(ctx context.Context, url, ref, dir string) error {
		if failed.Load() < 2 {
			return fail(ctx, url, ref, dir)
		}
		return succeed(ctx, url, ref, dir)
	})

	if _, err := u.tree(t.Context(), testPkgbase, testRef); err != nil {
		t.Fatalf("tree after two transient failures: %v", err)
	}
	if calls.Load() != 1 || failed.Load() != 2 {
		t.Errorf("attempts: %d failed, %d succeeded; want 2, 1", failed.Load(), calls.Load())
	}
	if n := u.failures.Load(); n != 0 {
		t.Errorf("failures = %d after a success, want 0", n)
	}
}

// TestTreeBreakerStopsRetries pins the bound on outbound load during an outage:
// maxUpstreamFailures attempts in all, across retries, keys and .SRCINFO fetches.
func TestTreeBreakerStopsRetries(t *testing.T) {
	t.Parallel()

	var status, requests, calls atomic.Int64
	status.Store(http.StatusOK)
	u := testUpstream(t, statusServer(t, &status, &requests).URL, transientClone(&calls))
	u.maxRetries = 100

	if _, err := u.tree(t.Context(), testPkgbase, testRef); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Errorf("tree = %v, want ErrUpstreamUnavailable", err)
	}
	if n := calls.Load(); n != maxUpstreamFailures {
		t.Errorf("cloned %d times, want %d", n, maxUpstreamFailures)
	}

	if _, err := u.tree(t.Context(), "other", testRef); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Errorf("tree of another package = %v, want ErrUpstreamUnavailable", err)
	}
	if _, err := u.fetchSrcinfo(t.Context(), "other", testRef); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Errorf("fetchSrcinfo = %v, want ErrUpstreamUnavailable", err)
	}
	if calls.Load() != maxUpstreamFailures || requests.Load() != 0 {
		t.Errorf("an open breaker still reached gitlab: %d clones, %d requests", calls.Load(), requests.Load())
	}
}

// TestTreeErrorContract pins what keeps an outage from purging published builds:
// every way tree gives up is errSourceUnavailable, which build() turns into a
// delay. An invalid name is the exception, since it is about the package.
func TestTreeErrorContract(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pkgbase string
		setup   func(u *upstream)
		want    []error
		notWant error
	}{
		// these two must give up before the breaker would, so it cannot mask them
		{"retries exhausted", testPkgbase, func(u *upstream) {
			u.maxRetries = 1
		}, []error{errSourceUnavailable}, ErrUpstreamUnavailable},
		{"max duration", testPkgbase, func(u *upstream) {
			u.maxRetries = 100
			u.maxDuration = time.Millisecond
			transient := u.clone
			u.clone = func(ctx context.Context, url, ref, dir string) error {
				time.Sleep(5 * time.Millisecond)
				return transient(ctx, url, ref, dir)
			}
		}, []error{errSourceUnavailable}, ErrUpstreamUnavailable},
		{"attempt timeout", testPkgbase, func(u *upstream) {
			u.maxRetries = 0
			u.attemptTimeout = 10 * time.Millisecond
			u.clone = func(ctx context.Context, _, _, _ string) error {
				<-ctx.Done()
				return ctx.Err()
			}
		}, []error{errSourceUnavailable, context.DeadlineExceeded}, nil},
		{"breaker open", testPkgbase, func(u *upstream) {
			u.open.Store(true)
		}, []error{errSourceUnavailable, ErrUpstreamUnavailable}, nil},
		{"answered", testPkgbase, func(u *upstream) {
			u.clone = failClone(new(atomic.Int64), "fatal: Remote branch 1-1 not found in upstream origin")
		}, []error{errSourceUnavailable}, nil},
		{"invalid meta", "a/b", func(*upstream) {}, []error{ErrInvalidMeta}, errSourceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := testUpstream(t, "https://example.invalid", transientClone(new(atomic.Int64)))
			tc.setup(u)

			_, err := u.tree(t.Context(), tc.pkgbase, testRef)
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("tree = %v, want it to wrap %v", err, want)
				}
			}
			if tc.notWant != nil && errors.Is(err, tc.notWant) {
				t.Errorf("tree = %v, must not wrap %v", err, tc.notWant)
			}
		})
	}
}

// TestRefusalOpensBreaker covers a blocklist or rate limiter answering: one 403,
// even one with a Retry-After, or a 429 without one, stops all gitlab traffic,
// with no retry, on either path.
func TestRefusalOpensBreaker(t *testing.T) {
	t.Parallel()

	for i, status := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				if status == http.StatusForbidden {
					w.Header().Set("Retry-After", "1")
				}
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)
			u := testUpstream(t, srv.URL, nil)

			if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, testRef); !errors.Is(err, errSourceUnavailable) {
				t.Errorf("fetchSrcinfo = %v, want errSourceUnavailable", err)
			}
			if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, "next"); !errors.Is(err, ErrUpstreamUnavailable) {
				t.Errorf("fetchSrcinfo after a refusal = %v, want ErrUpstreamUnavailable", err)
			}
			if n := requests.Load(); n != 1 {
				t.Errorf("sent %d requests, want 1", n)
			}
		})
		t.Run("clone "+http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int64
			u := testUpstream(t, "https://example.invalid", failClone(&calls, refusedMessages[i]))

			if _, err := u.tree(t.Context(), testPkgbase, testRef); !errors.Is(err, errSourceUnavailable) {
				t.Errorf("tree = %v, want errSourceUnavailable", err)
			}
			if _, err := u.tree(t.Context(), "other", testRef); !errors.Is(err, ErrUpstreamUnavailable) {
				t.Errorf("tree after a refusal = %v, want ErrUpstreamUnavailable", err)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("cloned %d times, want 1", n)
			}
		})
	}
}

// rateLimitServer answers 429 with retryAfter to the first limited requests and
// testSrcinfo after, and logs when each request came.
func rateLimitServer(t *testing.T, limited int, retryAfter string) (srv *httptest.Server, seen func() []time.Time) {
	t.Helper()

	var (
		mu    sync.Mutex
		times []time.Time
	)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		n := len(times)
		mu.Unlock()
		if n <= limited {
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(testSrcinfo))
	}))
	t.Cleanup(srv.Close)

	return srv, func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(times)
	}
}

// TestFetchSrcinfoWaitsOutRateLimit covers gitlab's web limit running out
// mid-genQueue: the request waits for the reset and goes again, and the
// breaker stays closed.
func TestFetchSrcinfoWaitsOutRateLimit(t *testing.T) {
	t.Parallel()

	srv, seen := rateLimitServer(t, 1, "1")
	u := testUpstream(t, srv.URL, nil)

	if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, testRef); err != nil {
		t.Fatalf("fetchSrcinfo = %v, want the retry after the wait to succeed", err)
	}
	if u.open.Load() {
		t.Error("a 429 with a Retry-After opened the breaker")
	}
	got := seen()
	if len(got) != 2 {
		t.Fatalf("sent %d requests, want 2", len(got))
	}
	if gap := got[1].Sub(got[0]); gap < time.Second {
		t.Errorf("retried %s after the 429, want the 1s Retry-After", gap)
	}
}

// TestFetchSrcinfoRateLimitedTooOften covers a budget spent again right after
// each reset: maxRateLimited 429s for one .SRCINFO open the breaker.
func TestFetchSrcinfoRateLimitedTooOften(t *testing.T) {
	t.Parallel()

	srv, seen := rateLimitServer(t, maxRateLimited+1, "0")
	u := testUpstream(t, srv.URL, nil)

	if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, testRef); !errors.Is(err, errSourceUnavailable) {
		t.Errorf("fetchSrcinfo = %v, want errSourceUnavailable", err)
	}
	if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, "next"); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Errorf("fetchSrcinfo after %d 429s = %v, want ErrUpstreamUnavailable", maxRateLimited, err)
	}
	if n := len(seen()); n != maxRateLimited {
		t.Errorf("sent %d requests, want %d", n, maxRateLimited)
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		header string
		want   time.Duration
		ok     bool
	}{
		{"0", 0, true},
		{"120", 2 * time.Minute, true},
		{"900", maxRateLimitWait, true},
		{"901", 0, false},
		{"", 0, false},
		{"-1", 0, false},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0, false},
		{"99999999999999999999", 0, false},
	} {
		h := http.Header{}
		if tc.header != "" {
			h.Set("Retry-After", tc.header)
		}
		if got, ok := retryAfter(h); got != tc.want || ok != tc.ok {
			t.Errorf("retryAfter(%q) = %s, %t, want %s, %t", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPacerSpacesAndHolds pins the slots genQueue's .SRCINFO requests take:
// interval apart, none before a hold ends, and a wait that ends with its
// context.
func TestPacerSpacesAndHolds(t *testing.T) {
	t.Parallel()

	const interval = 20 * time.Millisecond
	p := pacer{interval: interval}
	start := time.Now()
	for range 3 {
		if err := p.wait(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 2*interval {
		t.Errorf("3 slots took %s, want at least %s", d, 2*interval)
	}

	until := time.Now().Add(100 * time.Millisecond)
	p.holdUntil(until)
	p.holdUntil(time.Now())
	if err := p.wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if now := time.Now(); now.Before(until) {
		t.Errorf("slot given %s before the hold ended", until.Sub(now))
	}

	p.holdUntil(time.Now().Add(time.Hour))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := p.wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("wait during a hold = %v, want the context's deadline", err)
	}
}

// TestFetchSrcinfoDoesNotFollowRedirect covers how gitlab answers a raw URL for
// a missing project: a redirect to its sign-in page, which is an answer.
func TestFetchSrcinfoDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()

	var followed atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/sign_in" {
			followed.Add(1)
			_, _ = w.Write([]byte("<html></html>"))
			return
		}
		http.Redirect(w, r, "/users/sign_in", http.StatusFound)
	}))
	defer srv.Close()

	u := testUpstream(t, srv.URL, nil)
	u.failures.Store(maxUpstreamFailures - 1)

	if _, err := u.fetchSrcinfo(t.Context(), testPkgbase, testRef); !errors.Is(err, errSourceUnavailable) {
		t.Errorf("fetchSrcinfo = %v, want errSourceUnavailable", err)
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("the redirect was followed %d times", n)
	}
	if n := u.failures.Load(); n != 0 || u.open.Load() {
		t.Errorf("failures = %d, open = %v after a redirect; want 0, false", n, u.open.Load())
	}
}

// TestCloneSlotsCapConcurrency covers the bound on simultaneous clones, which
// buildQueue's admission does not provide.
func TestCloneSlotsCapConcurrency(t *testing.T) {
	t.Parallel()

	const slots = 2
	var inFlight, peak, calls atomic.Int64
	write := fakeClone(&calls)
	u := testUpstream(t, "https://example.invalid", func(ctx context.Context, url, ref, dir string) error {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			if p := peak.Load(); n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)

		return write(ctx, url, ref, dir)
	})
	u.cloneSlots = make(chan struct{}, slots)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			if _, err := u.tree(t.Context(), testPkgbase, strconv.Itoa(i)); err != nil {
				t.Errorf("tree: %v", err)
			}
		})
	}
	wg.Wait()

	if n := peak.Load(); n != slots {
		t.Errorf("peak concurrent clones = %d, want %d", n, slots)
	}
}

// TestCloneSlotRechecksBreaker covers an attempt that waited for a slot while
// the breaker opened: it must not clone once it gets one.
func TestCloneSlotRechecksBreaker(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	u := testUpstream(t, "https://example.invalid", fakeClone(&calls))
	u.cloneSlots = make(chan struct{}, 1)
	u.cloneSlots <- struct{}{}

	done := make(chan error, 1)
	go func() {
		_, err := u.tree(t.Context(), testPkgbase, testRef)
		done <- err
	}()
	// long enough for tree to pass its first breaker check and park on the slot
	time.Sleep(50 * time.Millisecond)
	u.open.Store(true)
	<-u.cloneSlots

	if err := <-done; !errors.Is(err, ErrUpstreamUnavailable) {
		t.Errorf("tree = %v, want ErrUpstreamUnavailable", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("cloned %d times after the breaker opened, want 0", n)
	}
}

// TestSetupBuildDirHostFault covers the local steps after the fetch: a host that
// cannot create the build dir says nothing about the package, so it must neither
// purge nor read as an outage.
// not parallel: withConf mutates the package-level conf
func TestSetupBuildDirHostFault(t *testing.T) { //nolint:paralleltest
	withConf(t, nil)
	conf.Basedir.Work = t.TempDir()
	if err := os.WriteFile(filepath.Join(conf.Basedir.Work, buildDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	u := testUpstream(t, "https://example.invalid", fakeClone(new(atomic.Int64)))
	p := &ProtoPackage{Pkgbase: testPkgbase, Version: testRef, March: testMarchV3, State: &StateInfo{TagVer: testRef}}
	_, err := p.setupBuildDir(t.Context(), u)

	if !errors.Is(err, ErrorNotEligible) || errors.Is(err, errSourceUnavailable) {
		t.Errorf("setupBuildDir = %v, want ErrorNotEligible and not errSourceUnavailable", err)
	}
	if got := classifySetupErr(t.Context(), err); got != setupNotEligible {
		t.Errorf("classifySetupErr(%v) = %d, want setupNotEligible", err, got)
	}
}

// not parallel: withConf mutates the package-level conf
func TestSetupBuildDirLeavesNothingOnFetchFailure(t *testing.T) { //nolint:paralleltest
	withConf(t, nil)
	conf.Basedir.Work = t.TempDir()

	u := testUpstream(t, "https://example.invalid", transientClone(new(atomic.Int64)))
	u.maxRetries = 0

	p := &ProtoPackage{Pkgbase: testPkgbase, Version: testRef, March: testMarchV3, State: &StateInfo{TagVer: testRef}}
	_, err := p.setupBuildDir(t.Context(), u)
	if got := classifySetupErr(t.Context(), err); got != setupSourceDelayed {
		t.Errorf("classifySetupErr(%v) = %d, want setupSourceDelayed", err, got)
	}
	if _, err := os.Stat(filepath.Join(conf.Basedir.Work, buildDir, testMarchV3)); !os.IsNotExist(err) {
		t.Errorf("a failed fetch left a build dir behind: %v", err)
	}
}

// isolateGit keeps the host's git config and proxy settings out of tests that
// run the real git.
func isolateGit(t *testing.T) {
	t.Helper()

	for key, value := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1",
		"http_proxy": "", "https_proxy": "", "all_proxy": "", "ALL_PROXY": "",
	} {
		t.Setenv(key, value)
	}
}

// not parallel: isolateGit sets the environment
func TestTreeClonesTagWithGit(t *testing.T) { //nolint:paralleltest
	isolateGit(t)

	base := t.TempDir()
	repo := filepath.Join(base, gitlabProject(testPkgbase)+".git")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		args = append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v: %s", args, err, out)
		}
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, "PKGBUILD"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	write("pkgver=1\n")
	git("add", "PKGBUILD")
	git("commit", "-q", "-m", "1")
	git("tag", testRef)
	write("pkgver=2\n")
	git("commit", "-q", "-am", "2")

	u := testUpstream(t, "file://"+base, gitClone)

	dir, err := u.tree(t.Context(), testPkgbase, testRef)
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "PKGBUILD")); err != nil || string(got) != "pkgver=1\n" {
		t.Errorf("PKGBUILD at %s = %q, %v; want the tagged one", testRef, got, err)
	}

	// git's own wording for a missing tag, which reGitlabAnswered has to match
	if _, err := u.tree(t.Context(), testPkgbase, "9-9"); !errors.Is(err, errSourceUnavailable) {
		t.Errorf("tree at a missing tag = %v, want errSourceUnavailable", err)
	}
	if n := u.failures.Load(); n != 0 {
		t.Errorf("a missing tag counted as %d failures, want 0", n)
	}
}

// TestTreeHungServerTimesOut runs git against a server that accepts and never
// answers, which is what a dropped route or a silent ban looks like. The attempt
// deadline has to end it, git-remote-http included (see gitCommand).
// not parallel: isolateGit sets the environment
func TestTreeHungServerTimesOut(t *testing.T) { //nolint:paralleltest
	isolateGit(t)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})

	u := testUpstream(t, "http://"+ln.Addr().String(), gitClone)
	u.maxRetries = 0
	u.attemptTimeout = 200 * time.Millisecond

	start := time.Now()
	_, err = u.tree(t.Context(), testPkgbase, testRef)
	elapsed := time.Since(start)

	if !errors.Is(err, errSourceUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("tree against a hung server = %v, want errSourceUnavailable from the attempt deadline", err)
	}
	// WaitDelay is the second, the rest is slack for a loaded machine
	if limit := u.attemptTimeout + time.Second + 3*time.Second; elapsed > limit {
		t.Errorf("tree took %s against a hung server, want under %s", elapsed, limit)
	}
	if n := u.failures.Load(); n != 1 {
		t.Errorf("a timed out attempt counted as %d failures, want 1", n)
	}

	// git-remote-http is the one holding the connection, and killing only git
	// would leave it behind
	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for left := processesMentioning(t, addr); len(left) > 0; left = processesMentioning(t, addr) {
		if time.Now().After(deadline) {
			t.Fatalf("processes still talking to %s after tree returned: %q", addr, left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// processesMentioning returns the command lines in /proc that contain s.
func processesMentioning(t *testing.T, s string) []string {
	t.Helper()

	cmdlines, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, path := range cmdlines {
		// a process that exits between the glob and the read is gone, which is fine
		if raw, err := os.ReadFile(path); err == nil && bytes.Contains(raw, []byte(s)) {
			found = append(found, string(bytes.ReplaceAll(raw, []byte{0}, []byte{' '})))
		}
	}

	return found
}
