package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// absolute: sudo is the trust anchor of the whole chain, and systemd's default
	// PATH puts /usr/local/bin (where alhp-netns is installed) ahead of /usr/bin
	sudoBin          = "/usr/bin/sudo"
	makechrootpkgBin = "/usr/bin/makechrootpkg"

	// chrootName and netnsName are two renderings of one build id, never parsed
	// out of each other: recovering the id by trimming the chroot prefix couples
	// the two through a string literal, and a drift there would be caught only by
	// the helper's name validation, per build, in production.
	chrootPrefix = "build_"
	netnsPrefix  = "alhp-"
)

// alhpNetnsBin is kept a var so it can be overridden in tests.
var alhpNetnsBin = "/usr/local/bin/alhp-netns"

// exitIsolationSetup is the helper's exit code for "setup failed, no build ran".
// It must stay in sync with EXIT_SETUP in alhp-netns.
const exitIsolationSetup = 121

// lastLine returns the final non-empty line of s, which for a failed helper run is
// its diagnostic.
func lastLine(s string) string {
	for _, line := range slices.Backward(strings.Split(strings.TrimRight(s, "\n"), "\n")) {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}

	return ""
}

// netnsHelperTimeout bounds how long we wait for the helper, not the helper
// itself. The helper runs as root, so canceling the context would only reach
// os/exec's default Cancel, which is Process.Kill against a root-owned sudo:
// EPERM, and Wait stays parked in Process.Wait. Waiting with a select instead
// means a wedged helper costs a failed preflight rather than a hung main, which
// matters because the preflight runs before the signal loop starts.
const netnsHelperTimeout = 2 * time.Minute

// chrootName renders a build id as the makechrootpkg working-copy name.
func chrootName(buildID string) string { return chrootPrefix + buildID }

// netnsName renders a build id as the network namespace name. Must match the
// helper's own validation pattern.
func netnsName(buildID string) string { return netnsPrefix + buildID }

// networkIsolationEnabled reports whether builds run in their own network
// namespace. Absent config means enabled; see Conf.Build.NetworkIsolation for why
// the field is a pointer.
func networkIsolationEnabled() bool {
	return conf.Build.NetworkIsolation == nil || *conf.Build.NetworkIsolation
}

// setupNetworkIsolation reclaims namespaces left by a previous run and proves the
// mechanism works, so a broken or missing helper fails at startup rather than
// silently dropping isolation on every build.
func setupNetworkIsolation(ctx context.Context) error {
	// sequential, not concurrent: selftest builds a fixed-name namespace that a
	// concurrent sweep would race
	for _, verb := range []string{"sweep", "selftest"} {
		if err := runNetnsHelper(ctx, verb); err != nil {
			return err
		}
	}
	log.Debug("network isolation preflight ok")

	return nil
}

// sweepNetns reclaims namespaces orphaned by a helper that was killed before it
// could tear its own down. Called every sync cycle, not only at startup: the
// helper's non-convergence path deliberately leaves a namespace behind for sweep,
// and a startup-only sweep would leak it plus its pasta process, which holds a
// host socket, for the lifetime of the process.
func sweepNetns(ctx context.Context) {
	if !networkIsolationEnabled() {
		return
	}
	if err := runNetnsHelper(ctx, "sweep"); err != nil {
		log.Warningf("netns sweep failed: %v", err)
	}
}

func runNetnsHelper(ctx context.Context, verb string) error {
	cmd := exec.CommandContext(ctx, sudoBin, "-n", alhpNetnsBin, verb)

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return fmt.Errorf("alhp-netns %s failed: %w: %s", verb, r.err, strings.TrimSpace(string(r.out)))
		}

		return nil
	case <-time.After(netnsHelperTimeout):
		// deliberately orphaned rather than killed; see netnsHelperTimeout. sweep
		// and selftest bound themselves internally, so this is a backstop.
		return fmt.Errorf("alhp-netns %s did not finish within %s", verb, netnsHelperTimeout)
	}
}

// buildCommand assembles the makechrootpkg invocation for a build.
//
// With isolation enabled it is wrapped in the alhp-netns helper, which owns both
// the namespace and the kill path: ALHP is unprivileged and the build tree is
// root-owned, so ALHP cannot signal it directly. Cancellation is therefore a pipe
// on the helper's stdin, and closing it is what triggers the kill.
//
// The returned cleanup must run after Wait.
func buildCommand(ctx context.Context, p *ProtoPackage, buildID, makepkgFile string) (*exec.Cmd, func(), error) {
	args := []string{
		makechrootpkgBin, "-c",
		"-D", filepath.Join(conf.Basedir.Work, makepkgDir),
		"-l", chrootName(buildID),
		"-r", filepath.Join(conf.Basedir.Work, chrootDir),
		"--", "-m", "--noprogressbar",
		"--config", filepath.Join(conf.Basedir.Work, makepkgDir, fmt.Sprintf(makepkgFile, p.March)),
	}
	isolated := networkIsolationEnabled()
	if isolated {
		// sudo -n: with a pipe on stdin, a sudoers rule that failed to match would
		// leave sudo waiting on the very descriptor the cancel path needs.
		args = append([]string{sudoBin, "-n", alhpNetnsBin, "run", netnsName(buildID), "--"}, args...)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
	prepareBuildCmd(cmd, p)

	if !isolated {
		cmd.Cancel = killProcessGroup(cmd)

		return cmd, func() {}, nil
	}

	release, err := attachCancelPipe(cmd)
	if err != nil {
		return nil, nil, err
	}

	return cmd, release, nil
}

// attachCancelPipe makes cancellation a closed pipe rather than a signal, which is
// the only thing that works when the tree being canceled is root-owned and we are
// not. The helper on the other end treats EOF on its stdin as "kill everything".
//
// The returned release must run after Wait.
func attachCancelPipe(cmd *exec.Cmd) (func(), error) {
	// An *os.File on Stdin is handed to the child as fd 0 directly, with no copy
	// goroutine, and os/exec does not register it for closing; both ends are ours
	// to close. fd 0 is also the only channel that survives sudo, whose closefrom
	// defaults to 3.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("error creating cancel pipe: %w", err)
	}
	cmd.Stdin = pipeR

	// Idempotent: Cancel does not run on a successful build, so release is what
	// normally closes the write end, and a Cancel landing afterwards must not
	// return an error. os/exec would wrap it as "exec: canceling Cmd: file already
	// closed" and it would mask ctx.Err().
	var once sync.Once
	closeWrite := func() { once.Do(func() { _ = pipeW.Close() }) }
	cmd.Cancel = func() error {
		closeWrite()

		return nil
	}

	return func() {
		closeWrite()
		_ = pipeR.Close()
	}, nil
}

// prepareBuildCmd applies the settings shared by both branches.
func prepareBuildCmd(cmd *exec.Cmd, p *ProtoPackage) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = filepath.Dir(p.Pkgbuild)
	// the output pipe stays open as long as any process in the group holds it, so
	// bound how long Wait may block on a leaked child after the kill
	cmd.WaitDelay = buildKillGrace
}
