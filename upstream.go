package main

import (
	"context"
	"fmt"
	"github.com/Morganamilo/go-srcinfo"
	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	cloneBaseDelay = 10 * time.Second
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

	maxRetries uint64
	baseDelay  time.Duration

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
		baseURL:    upstreamBaseURL,
		client:     &http.Client{Timeout: srcinfoTimeout},
		clone:      gitClone,
		cacheDir:   dir,
		maxRetries: conf.MaxCloneRetries,
		baseDelay:  cloneBaseDelay,
		srcinfos:   make(map[string]*onceResult),
		trees:      make(map[string]*onceResult),
	}, nil
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
		return nil, err
	}

	return srcinfo.Parse(body)
}

func (u *upstream) getSrcinfo(ctx context.Context, pkgbase, ref string) (string, error) {
	url := fmt.Sprintf("%s/%s/-/raw/%s/.SRCINFO", u.baseURL, gitlabProject(pkgbase), ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", upstreamUserAgent)

	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}

	// one byte over the cap, so an oversized body is an error rather than a
	// truncated .SRCINFO that happens to parse
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSrcinfoSize+1))
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
		backoff := retry.WithMaxRetries(u.maxRetries, retry.NewFibonacci(u.baseDelay))

		err := retry.Do(ctx, backoff, func(ctx context.Context) error {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}

			return retry.RetryableError(u.clone(ctx, url, ref, dir))
		})
		if err != nil {
			return "", fmt.Errorf("cloning %s at %s: %w", pkgbase, ref, err)
		}

		return dir, nil
	})
}

// gitClone is upstream's clone outside of tests.
func gitClone(ctx context.Context, url, ref, dir string) error {
	res, err := gitCommand(ctx, "", "clone", "--depth", "1", "--branch", ref, url, dir).CombinedOutput()
	log.Debug(string(res))
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res)))
	}

	return nil
}

// gitCommand runs git with ALHP's User-Agent and no terminal prompt, in its own
// process group. git hands HTTP to a git-remote-https child that holds the output
// pipe, so a deadline has to kill the group, and WaitDelay stops CombinedOutput
// waiting on the pipe after that.
func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_HTTP_USER_AGENT="+upstreamUserAgent, "GIT_TERMINAL_PROMPT=0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = killProcessGroup(cmd)
	cmd.WaitDelay = time.Second

	return cmd
}
