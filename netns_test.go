package main

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestCancelPipeReachesGrandchild is the sibling of TestKillProcessGroup for the
// network-isolated branch, where cancellation is a closed pipe rather than a
// signal: ALHP is unprivileged and cannot signal the root-owned build tree, so the
// helper does the killing and EOF on its stdin is the only trigger. The property
// is the same one: killing a build must take its grandchildren with it.
func TestCancelPipeReachesGrandchild(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// stands in for alhp-netns: waits for EOF on stdin, then kills its own process
	// group, which is what the real helper does by namespace membership
	script := `sleep 300 &
echo $!
cat >/dev/null
kill -KILL 0`
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second

	// the production wiring, not a copy of it
	release, err := attachCancelPipe(cmd)
	if err != nil {
		t.Fatalf("attachCancelPipe: %v", err)
	}
	defer release()

	grandchild := startGrandchildTree(t, cmd)
	cancel()

	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("Wait returned no error for a canceled process")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Wait did not return after cancel")
	}

	requireGone(t, grandchild)
}

// testBuildID stands in for the uuid build() mints per build.
const testBuildID = "0f9e8d7c-6b5a-4938-8271-605f4e3d2c1b"

// withConf installs a throwaway config for tests. conf is a package-level *Conf
// that only main() populates, so it is nil under go test; callers must not run in
// parallel with each other.
func withConf(t *testing.T, isolation *bool) {
	t.Helper()

	prev := conf
	conf = &Conf{}
	conf.Build.NetworkIsolation = isolation
	t.Cleanup(func() { conf = prev })
}

// TestBuildCommandCancelIsIdempotent covers the case os/exec makes easy to get
// wrong: on a successful build Cancel never runs, so the cleanup closes the write
// end, and a Cancel landing afterwards must still report success. A non-nil error
// there is wrapped as "exec: canceling Cmd: file already closed" and masks
// ctx.Err().
// not parallel: withConf mutates the package-level conf
func TestBuildCommandCancelIsIdempotent(t *testing.T) { //nolint:paralleltest
	enabled := true
	withConf(t, &enabled)

	pkg := &ProtoPackage{March: testMarchV3, Pkgbuild: "/tmp/pkg/PKGBUILD"}
	cmd, release, err := buildCommand(t.Context(), pkg, testBuildID, "makepkg-%s.conf")
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}

	release()
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("Cancel after release returned %v, want nil", err)
	}
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("second Cancel returned %v, want nil", err)
	}
	release()
}

// TestBuildCommandWrapsInHelper pins the argv contract the helper validates: it
// refuses anything whose first post-`--` argument is not the absolute
// makechrootpkg path, so a change here silently breaks every build.
// not parallel: withConf mutates the package-level conf
func TestBuildCommandWrapsInHelper(t *testing.T) { //nolint:paralleltest
	enabled := true
	withConf(t, &enabled)

	pkg := &ProtoPackage{March: testMarchV3, Pkgbuild: "/tmp/pkg/PKGBUILD"}
	cmd, release, err := buildCommand(t.Context(), pkg, testBuildID, "makepkg-%s.conf")
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	defer release()

	want := []string{sudoBin, "-n", alhpNetnsBin, "run", netnsPrefix + testBuildID, "--", makechrootpkgBin}
	if len(cmd.Args) < len(want) {
		t.Fatalf("argv too short: %v", cmd.Args)
	}
	for i, arg := range want {
		if cmd.Args[i] != arg {
			t.Errorf("argv[%d] = %q, want %q", i, cmd.Args[i], arg)
		}
	}
	if cmd.Stdin == nil {
		t.Error("isolated build has no cancel pipe on stdin")
	}
}

// TestBuildCommandWithoutIsolation keeps the fallback honest: no helper, no pipe,
// and stdin left nil so os/exec still opens /dev/null. Handing that tree a pipe
// with no writer would turn an instant EOF into a block until stall_timeout.
// not parallel: withConf mutates the package-level conf
func TestBuildCommandWithoutIsolation(t *testing.T) { //nolint:paralleltest
	disabled := false
	withConf(t, &disabled)

	pkg := &ProtoPackage{March: testMarchV3, Pkgbuild: "/tmp/pkg/PKGBUILD"}
	cmd, release, err := buildCommand(t.Context(), pkg, testBuildID, "makepkg-%s.conf")
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	defer release()

	if cmd.Args[0] != makechrootpkgBin {
		t.Errorf("argv[0] = %q, want %q", cmd.Args[0], makechrootpkgBin)
	}
	if cmd.Stdin != nil {
		t.Error("non-isolated build must leave stdin nil so os/exec opens /dev/null")
	}
}

// not parallel: withConf mutates the package-level conf
func TestNetworkIsolationDefaultsOn(t *testing.T) { //nolint:paralleltest
	withConf(t, nil)
	if !networkIsolationEnabled() {
		t.Error("absent config must mean enabled")
	}
	off := false
	conf.Build.NetworkIsolation = &off
	if networkIsolationEnabled() {
		t.Error("explicit false must disable")
	}
}
