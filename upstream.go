package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// upstreamUserAgent names ALHP on every request to gitlab.archlinux.org, HTTP and
// git alike, so the people running it can tell this traffic apart and know whom to
// ask about it rather than having only an address to block.
const upstreamUserAgent = "ALHP.GO (+https://alhp.dev; https://somegit.dev/ALHP/ALHP.GO)"

const (
	upstreamBaseURL = "https://gitlab.archlinux.org/archlinux/packaging/packages"
	// srcinfoTimeout bounds a whole .SRCINFO request, body included. genQueue
	// fetches them one after another, so without it a single hung connection would
	// hold the whole queue until the kernel gave up on it.
	srcinfoTimeout = 30 * time.Second
	// maxSrcinfoSize caps what a .SRCINFO read may buffer. Real ones are a few KiB.
	maxSrcinfoSize = 1 << 20
	// A clone is bounded per attempt and in total, so an outage costs a build
	// slot minutes. Unbounded, a retry could hold both unknown-memory slots for
	// hours and keep the cycle, and with it publishing, from ending.
	cloneAttemptTimeout = 3 * time.Minute
	cloneMaxDuration    = 10 * time.Minute
	cloneMaxDelay       = time.Minute
	cloneBaseDelay      = 10 * time.Second
	// maxUpstreamFailures consecutive failures stop all gitlab traffic for the
	// rest of the cycle, so an outage drains the queue as delayed packages
	// instead of every queue entry retrying on its own.
	maxUpstreamFailures = 5
	// maxConcurrentClones caps clones in flight. buildQueue admits every package
	// that fits under memory_limit and each build starts with a clone, so without
	// it dozens would reach gitlab at once.
	maxConcurrentClones = 4
)

var (
	// errSourceUnavailable marks a fetch or clone that failed for want of an
	// answer from gitlab. It says nothing about the package, so build() maps it
	// to a delay rather than to the purge a plain error gets.
	errSourceUnavailable = errors.New("source unavailable")
	// ErrUpstreamUnavailable is what every request gets once the breaker is open.
	ErrUpstreamUnavailable = errors.New("gitlab stopped answering, not asking again this cycle")
	// reGitlabAnswered matches clone failures that are gitlab's answer about the
	// package rather than a failure to get one: a missing tag or branch, or a
	// missing project, which gitlab answers with a 401 and git turns into a
	// credential prompt. Retrying those cannot help, and counting them would let
	// a few renamed packages stop the cycle.
	reGitlabAnswered = regexp.MustCompile(`not found in upstream|repository '[^']*' not found|` +
		`could not read Username|terminal prompts disabled|The requested URL returned error: 40[14]\b`)
	// reGitlabRefused matches gitlab refusing ALHP itself, which is how a
	// blocklist or a rate limiter answers. Retrying that, while other clones'
	// successes keep resetting the count, is what gets an address banned, so it
	// opens the breaker at once.
	reGitlabRefused = regexp.MustCompile(`The requested URL returned error: (403|429)\b`)
)

// upstream is one build cycle's view of gitlab.archlinux.org. genQueue asks for a
// .SRCINFO and buildQueue for a checkout once per march, and every march of a
// pkgbase wants the same (pkgbase, ref), so each is fetched once and shared. A
// new upstream per cycle is what keeps a cached main from going stale.
type upstream struct {
	baseURL  string
	client   *http.Client
	clone    func(ctx context.Context, url, ref, dir string) error
	cacheDir string

	maxRetries     uint64
	attemptTimeout time.Duration
	maxDuration    time.Duration
	maxDelay       time.Duration
	baseDelay      time.Duration

	// failures counts gitlab requests in a row that got no answer; open is set
	// once it reaches maxUpstreamFailures and stays set for the cycle
	failures atomic.Int64
	open     atomic.Bool
	// cloneSlots holds one token per clone in flight
	cloneSlots chan struct{}

	mu sync.Mutex
	// srcinfos holds the raw text rather than the parsed struct: build() goes on
	// using the struct genQueue assigned, appending to its slices among other
	// things, so marches must not share one.
	srcinfos map[string]*onceResult
	trees    map[string]*onceResult
}

type onceResult struct {
	once sync.Once
	val  string
	err  error
}

// cached runs fn once per key and hands every caller its result, failures
// included, so a package that cannot be fetched costs one attempt per cycle
// rather than one per march.
func (u *upstream) cached(results map[string]*onceResult, key string, fn func() (string, error)) (string, error) {
	u.mu.Lock()
	r, ok := results[key]
	if !ok {
		r = new(onceResult)
		results[key] = r
	}
	u.mu.Unlock()

	r.once.Do(func() { r.val, r.err = fn() })

	return r.val, r.err
}

func upstreamKey(pkgbase, ref string) string {
	return pkgbase + "\x00" + ref
}

// newUpstream starts with an empty dir, which also clears whatever a crashed
// cycle left behind.
func newUpstream(dir string) (*upstream, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("clearing source cache %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating source cache %s: %w", dir, err)
	}

	return &upstream{
		baseURL:        upstreamBaseURL,
		client:         newSrcinfoClient(),
		clone:          gitClone,
		cacheDir:       dir,
		maxRetries:     conf.MaxCloneRetries,
		attemptTimeout: cloneAttemptTimeout,
		maxDuration:    cloneMaxDuration,
		maxDelay:       cloneMaxDelay,
		baseDelay:      cloneBaseDelay,
		cloneSlots:     make(chan struct{}, maxConcurrentClones),
		srcinfos:       make(map[string]*onceResult),
		trees:          make(map[string]*onceResult),
	}, nil
}

// record feeds one gitlab request into the breaker. answered is any response
// that is gitlab's own word on the package, a 404 included.
func (u *upstream) record(answered bool) {
	if answered {
		u.failures.Store(0)
		return
	}
	if u.failures.Add(1) >= maxUpstreamFailures {
		u.trip(fmt.Sprintf("%d gitlab requests in a row failed", maxUpstreamFailures))
	}
}

// trip opens the breaker for the rest of the cycle, logging why once.
func (u *upstream) trip(why string) {
	if u.open.CompareAndSwap(false, true) {
		log.Errorf("%s, not contacting gitlab again this cycle", why)
	}
}

// newSrcinfoClient follows no redirects: gitlab answers a raw URL for a missing
// project with a 302 to its sign-in page, whose HTML would otherwise cost a
// second request and then be parsed as a .SRCINFO.
func newSrcinfoClient() *http.Client {
	return &http.Client{
		Timeout: srcinfoTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (u *upstream) close() {
	if err := os.RemoveAll(u.cacheDir); err != nil {
		log.Warningf("error removing source cache %s: %v", u.cacheDir, err)
	}
}

// gitlabProject maps a pkgbase to its project name on gitlab.archlinux.org, which
// allows neither "+" nor a project called "tree".
func gitlabProject(pkgbase string) string {
	project := reReplaceSinglePlus.ReplaceAllString(pkgbase, "$1-$2")
	project = reReplaceRemainingPlus.ReplaceAllString(project, "plus")
	project = reReplaceSpecialChars.ReplaceAllString(project, "-")
	project = reReplaceUnderscore.ReplaceAllString(project, "-")

	return reReplaceTree.ReplaceAllString(project, "unix-tree")
}

// checkPkgRef vets what fetchSrcinfo and tree build URLs and cache paths from.
func checkPkgRef(pkgbase, ref string) error {
	if err := checkMetaName("pkgbase", pkgbase); err != nil {
		return err
	}

	return checkMetaName("ref", ref)
}

// fetchSrcinfo returns the .SRCINFO of pkgbase at ref, parsed afresh for every
// caller.
func (u *upstream) fetchSrcinfo(ctx context.Context, pkgbase, ref string) (*srcinfo.Srcinfo, error) {
	if err := checkPkgRef(pkgbase, ref); err != nil {
		return nil, err
	}

	body, err := u.cached(u.srcinfos, upstreamKey(pkgbase, ref), func() (string, error) {
		return u.getSrcinfo(ctx, pkgbase, ref)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSourceUnavailable, err)
	}

	return srcinfo.Parse(body)
}

func (u *upstream) getSrcinfo(ctx context.Context, pkgbase, ref string) (string, error) {
	if u.open.Load() {
		return "", ErrUpstreamUnavailable
	}

	url := fmt.Sprintf("%s/%s/-/raw/%s/.SRCINFO", u.baseURL, gitlabProject(pkgbase), ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", upstreamUserAgent)

	resp, err := u.client.Do(req)
	if err != nil {
		u.record(false)
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		u.trip(fmt.Sprintf("gitlab refused %s with %s", url, resp.Status))
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	default:
		u.record(resp.StatusCode == http.StatusNotFound || resp.StatusCode/100 == 3)
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}

	// one byte over the cap, so an oversized body is an error rather than a
	// truncated .SRCINFO that happens to parse
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSrcinfoSize+1))
	u.record(err == nil)
	if err != nil {
		return "", fmt.Errorf("%s: %w", url, err)
	}
	if len(body) > maxSrcinfoSize {
		return "", fmt.Errorf("%s: .SRCINFO exceeds %d bytes", url, maxSrcinfoSize)
	}

	return string(body), nil
}

// tree returns a checkout of pkgbase at ref under the cache dir. Callers copy it
// before building, since builds edit the PKGBUILD in place.
func (u *upstream) tree(ctx context.Context, pkgbase, ref string) (string, error) {
	if err := checkPkgRef(pkgbase, ref); err != nil {
		return "", err
	}

	return u.cached(u.trees, upstreamKey(pkgbase, ref), func() (string, error) {
		dir := filepath.Join(u.cacheDir, pkgbase, ref)
		url := fmt.Sprintf("%s/%s.git", u.baseURL, gitlabProject(pkgbase))
		// built here because WithMaxDuration's clock starts when it is built. It
		// never interrupts a running attempt, hence the per-attempt deadline.
		backoff := retry.WithMaxRetries(u.maxRetries, retry.WithMaxDuration(u.maxDuration,
			retry.WithCappedDuration(u.maxDelay, retry.NewFibonacci(u.baseDelay))))

		err := retry.Do(ctx, backoff, func(ctx context.Context) error {
			if u.open.Load() {
				return ErrUpstreamUnavailable
			}
			// before the attempt deadline starts, so waiting for a slot costs none
			// of it
			select {
			case u.cloneSlots <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			defer func() { <-u.cloneSlots }()
			// the breaker may have opened while this attempt waited
			if u.open.Load() {
				return ErrUpstreamUnavailable
			}
			if err := os.RemoveAll(dir); err != nil {
				return err
			}

			attemptCtx, cancel := context.WithTimeout(ctx, u.attemptTimeout)
			defer cancel()
			err := u.clone(attemptCtx, url, ref, dir)
			if err != nil && reGitlabRefused.MatchString(err.Error()) {
				u.trip("gitlab refused a clone: " + err.Error())
				return err
			}
			answered := err == nil || reGitlabAnswered.MatchString(err.Error())
			u.record(answered)
			if answered {
				return err
			}

			return retry.RetryableError(err)
		})
		if err != nil {
			return "", fmt.Errorf("%w: cloning %s at %s: %w", errSourceUnavailable, pkgbase, ref, err)
		}

		return dir, nil
	})
}

// gitClone is upstream's clone outside of tests.
func gitClone(ctx context.Context, url, ref, dir string) error {
	res, err := gitCommand(ctx, "", "clone", "--depth", "1", "--branch", ref, url, dir).CombinedOutput()
	log.Debug(string(res))
	if err != nil {
		// a killed git reports only "signal: killed"
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("git clone did not finish: %w", ctxErr)
		}

		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res)))
	}

	return nil
}

// gitCommand runs git with ALHP's User-Agent and no prompt of any kind, in the C
// locale the reGitlab* markers are written against, and in its own process group.
// git hands HTTP to a git-remote-https child that holds the output pipe, so a
// deadline has to kill the group, and WaitDelay stops CombinedOutput waiting on
// the pipe after that.
func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	// GIT_ASKPASS set but empty stops git falling back to core.askPass or
	// SSH_ASKPASS, which would replace the "terminal prompts disabled" failure
	cmd.Env = append(os.Environ(), "GIT_HTTP_USER_AGENT="+upstreamUserAgent, "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=", "LC_ALL=C")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = killProcessGroup(cmd)
	cmd.WaitDelay = time.Second

	return cmd
}
