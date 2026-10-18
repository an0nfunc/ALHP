package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// upstreamUserAgent names ALHP on every request to gitlab.archlinux.org, HTTP and
// git alike, so the people running it can tell this traffic apart and know whom to
// ask about it rather than having only an address to block.
const upstreamUserAgent = "ALHP.GO (+https://alhp.dev; https://somegit.dev/ALHP/ALHP.GO)"

const (
	// srcinfoTimeout bounds a whole .SRCINFO request, body included. genQueue
	// fetches them one after another, so without it a single hung connection would
	// hold the whole queue until the kernel gave up on it.
	srcinfoTimeout = 30 * time.Second
	// maxSrcinfoSize caps what a .SRCINFO read may buffer. Real ones are a few KiB.
	maxSrcinfoSize = 1 << 20
)

var srcinfoClient = &http.Client{Timeout: srcinfoTimeout}

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
