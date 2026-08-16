package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runDetector drives a detector over run, simulating a build that accumulates
// cpuShare cores worth of CPU time and writes every outputEvery (0 meaning never).
// It returns how far into the run the detector fired and the cause it reported.
func runDetector(limits stallLimits, run time.Duration, cpuShare float64, outputEvery time.Duration) (time.Duration, error) {
	start := time.Now()
	detector := newStallDetector(limits, start, 0)

	var (
		cpu        time.Duration
		now        = start
		lastOutput = start
	)

	for range int(run / buildPollInterval) {
		now = now.Add(buildPollInterval)
		cpu += time.Duration(float64(buildPollInterval) * cpuShare)
		if outputEvery > 0 && now.Sub(lastOutput) >= outputEvery {
			lastOutput = now
		}

		if cause := detector.observe(now, cpu, lastOutput); cause != nil {
			return now.Sub(start), cause
		}
	}

	return 0, nil
}

func TestStallDetector(t *testing.T) {
	t.Parallel()

	limits := stallLimits{stall: 30 * time.Minute, silence: 90 * time.Minute}
	const run = 4 * time.Hour

	tests := []struct {
		name string
		// cpuShare is how many cores worth of CPU time the tree accumulates
		cpuShare float64
		// outputEvery is how often the build writes something, 0 meaning never
		outputEvery time.Duration
		wantCause   error
		// wantAfter is the window that must elapse before the kill is allowed
		wantAfter time.Duration
	}{
		{name: "compiling normally", cpuShare: 4, outputEvery: time.Minute},
		{name: "chatty but idle", cpuShare: 0, outputEvery: 10 * time.Minute},
		// output keeps the silence window open even when it is barely a trickle
		{name: "occasional output while busy", cpuShare: 4, outputEvery: 80 * time.Minute},
		// CPU work holds off the stall window but must not hold off silence: this is
		// the spinning-test-runner hang
		{name: "silent but cpu bound", cpuShare: 1, outputEvery: 0, wantCause: ErrBuildSilent, wantAfter: limits.silence},
		{name: "silent single-core link", cpuShare: 0.5, outputEvery: 0, wantCause: ErrBuildSilent, wantAfter: limits.silence},
		{name: "hung with no cpu at all", cpuShare: 0, outputEvery: 0, wantCause: ErrBuildStalled, wantAfter: limits.stall},
		{name: "hung with idle wakeups below floor", cpuShare: 0.001, outputEvery: 0, wantCause: ErrBuildStalled, wantAfter: limits.stall},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			firedAt, cause := runDetector(limits, run, tt.cpuShare, tt.outputEvery)

			if !errors.Is(cause, tt.wantCause) {
				t.Fatalf("cause = %v, want %v (fired after %s)", cause, tt.wantCause, firedAt)
			}
			// a build must never be killed before its window has passed
			if cause != nil && firedAt < tt.wantAfter {
				t.Fatalf("killed after %s, want at least %s", firedAt, tt.wantAfter)
			}
		})
	}
}

// TestStallDetectorWindowsAreIndependent guards that either window works on its
// own, so a deployment that disables one keeps the other.
func TestStallDetectorWindowsAreIndependent(t *testing.T) {
	t.Parallel()

	const run = 4 * time.Hour

	tests := []struct {
		name      string
		limits    stallLimits
		cpuShare  float64
		wantCause error
	}{
		{
			name:      "silence alone still kills a spinning build",
			limits:    stallLimits{silence: 90 * time.Minute},
			cpuShare:  1,
			wantCause: ErrBuildSilent,
		},
		{
			name:      "stall alone still kills an idle build",
			limits:    stallLimits{stall: 30 * time.Minute},
			cpuShare:  0,
			wantCause: ErrBuildStalled,
		},
		{
			name:     "both disabled kills nothing",
			limits:   stallLimits{},
			cpuShare: 0,
		},
		{
			name:     "stall alone leaves a spinning build running",
			limits:   stallLimits{stall: 30 * time.Minute},
			cpuShare: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			firedAt, cause := runDetector(tt.limits, run, tt.cpuShare, 0)
			if !errors.Is(cause, tt.wantCause) {
				t.Fatalf("cause = %v, want %v (fired after %s)", cause, tt.wantCause, firedAt)
			}
		})
	}
}

func TestStallDetectorNonMonotonicCPUDoesNotUnderflow(t *testing.T) {
	t.Parallel()

	// the caller clamps CPU to keep it monotonic, but a regression there must not
	// turn into a build that can never be killed
	start := time.Now()
	detector := newStallDetector(stallLimits{stall: time.Minute, silence: time.Hour}, start, 10*time.Hour)

	now := start
	for range 120 {
		now = now.Add(buildPollInterval)
		if errors.Is(detector.observe(now, 0, start), ErrBuildStalled) {
			return
		}
	}

	t.Fatal("detector never reported a stall for a tree that dropped to zero cpu")
}

// TestKillReasonCoversEveryCause guards the pairing housekeeping depends on: a
// cause we kill for must map to a skip reason, and that skip reason must be in the
// set the requeue path refuses, or the build is rebuilt straight back into the hang.
func TestKillReasonCoversEveryCause(t *testing.T) {
	t.Parallel()

	for _, cause := range []error{ErrBuildStalled, ErrBuildSilent, ErrBuildTimeout} {
		metric, skipReason, ok := killReason(cause)
		if !ok {
			t.Errorf("killReason(%v) reported the build was not killed by us", cause)
			continue
		}
		if metric == "" || skipReason == "" {
			t.Errorf("killReason(%v) = %q, %q, want both non-empty", cause, metric, skipReason)
		}
		if !slices.Contains(killSkipReasons, skipReason) {
			t.Errorf("skip reason %q for %v is missing from killSkipReasons, "+
				"housekeeping would requeue the build into the same hang", skipReason, cause)
		}
	}

	if _, _, ok := killReason(errors.New("some build error")); ok {
		t.Error("killReason reported an unrelated error as one of our kills")
	}
}

// TestStallLimitsReason pins the log text apart from the two windows it names. It
// is the only signal in the journal saying which window fired, and swapping the two
// strings would be invisible to every other test here.
func TestStallLimitsReason(t *testing.T) {
	t.Parallel()

	limits := stallLimits{stall: 2 * time.Hour, silence: 6 * time.Hour}

	tests := []struct {
		cause error
		want  string
	}{
		{cause: ErrBuildStalled, want: "no progress for 2h0m0s"},
		{cause: ErrBuildSilent, want: "no output for 6h0m0s"},
		{cause: ErrBuildTimeout, want: "build timeout"},
		{cause: fmt.Errorf("wrapped: %w", ErrBuildSilent), want: "no output for 6h0m0s"},
		{cause: nil, want: "unknown reason"},
	}

	for _, tt := range tests {
		if got := limits.reason(tt.cause); got != tt.want {
			t.Errorf("reason(%v) = %q, want %q", tt.cause, got, tt.want)
		}
	}
}

func TestProgressWriter(t *testing.T) {
	t.Parallel()

	var sink strings.Builder
	pw := newProgressWriter(&sink)

	before := pw.lastWrite()
	time.Sleep(2 * time.Millisecond)

	if _, err := pw.Write([]byte("compiling")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !pw.lastWrite().After(before) {
		t.Errorf("lastWrite did not advance: %s not after %s", pw.lastWrite(), before)
	}
	if sink.String() != "compiling" {
		t.Errorf("underlying writer got %q, want %q", sink.String(), "compiling")
	}
}

func TestConfDuration(t *testing.T) {
	t.Parallel()

	const def = 2 * time.Hour

	tests := []struct {
		raw  string
		want time.Duration
	}{
		{raw: "", want: def},
		{raw: "45m", want: 45 * time.Minute},
		{raw: "0", want: 0},
		{raw: "not a duration", want: def},
		{raw: "-5m", want: def},
	}

	for _, tt := range tests {
		if got := confDuration(tt.raw, def, "test"); got != tt.want {
			t.Errorf("confDuration(%q) = %s, want %s", tt.raw, got, tt.want)
		}
	}
}

// startTree starts a process in its own group, the shape the monitor samples, and
// kills the whole group on test exit.
func startTree(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = killProcessGroup(cmd)()
		_ = cmd.Wait()
	})

	return cmd
}

// startIdleTree starts a process that burns no CPU.
func startIdleTree(t *testing.T) *exec.Cmd {
	t.Helper()

	return startTree(t, "sleep", "30")
}

// startBusyTree starts a process that burns CPU continuously and never writes.
func startBusyTree(t *testing.T) *exec.Cmd {
	t.Helper()

	return startTree(t, "sh", "-c", "while :; do :; done")
}

func TestBuildMonitorReportsMemoryWithoutStalling(t *testing.T) {
	t.Parallel()

	cmd := startIdleTree(t)
	kills := make(chan error, 1)

	// zero windows disable detection, so an idle tree must survive
	monitor := startBuildMonitor(cmd.Process.Pid, newProgressWriter(io.Discard), stallLimits{}, func(cause error) {
		kills <- cause
	})
	time.Sleep(2 * buildPollInterval)
	peak := monitor.stop()

	if peak <= 0 {
		t.Errorf("peak memory = %d kB, want > 0", peak)
	}
	select {
	case cause := <-kills:
		t.Errorf("onKill fired with %v while detection was disabled", cause)
	default:
	}
}

func TestBuildMonitorKillsIdleTree(t *testing.T) {
	t.Parallel()

	cmd := startIdleTree(t)
	kills := make(chan error, 1)

	monitor := startBuildMonitor(cmd.Process.Pid, newProgressWriter(io.Discard),
		stallLimits{stall: time.Millisecond, silence: time.Hour}, func(cause error) {
			kills <- cause
		})
	defer monitor.stop()

	select {
	case cause := <-kills:
		if !errors.Is(cause, ErrBuildStalled) {
			t.Errorf("cause = %v, want %v", cause, ErrBuildStalled)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("onKill never fired for a process consuming no cpu")
	}
}

// TestBuildMonitorKillsSilentTree covers the window a busy build cannot escape,
// end to end against a real process tree: this is the production hang, a spinning
// test runner that writes nothing.
//
// Both windows are live and the stall window is the shorter of the two, so only the
// tree's own CPU burn keeps it reopened long enough for silence to be what fires.
// Point this at an idle tree instead and it fails with ErrBuildStalled, which is the
// property that makes it worth running.
func TestBuildMonitorKillsSilentTree(t *testing.T) {
	t.Parallel()

	cmd := startBusyTree(t)
	kills := make(chan error, 1)

	monitor := startBuildMonitor(cmd.Process.Pid, newProgressWriter(io.Discard),
		stallLimits{stall: 3 * buildPollInterval, silence: 5 * buildPollInterval}, func(cause error) {
			kills <- cause
		})
	defer monitor.stop()

	select {
	case cause := <-kills:
		if !errors.Is(cause, ErrBuildSilent) {
			t.Errorf("cause = %v, want %v", cause, ErrBuildSilent)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("onKill never fired for a process that produced no output")
	}
}

// startGrandchildTree starts cmd and returns the pid of the grandchild it prints
// on its first line. Shared with the cancel-pipe test in netns_test.go, which
// guards the same property through the other cancellation mechanism.
func startGrandchildTree(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("reading grandchild pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("parsing grandchild pid %q: %v", line, err)
	}

	return pid
}

// requireGone polls rather than asserting immediately: the grandchild is orphaned
// onto init once its parent dies, so it is not reaped the instant the group is
// signaled.
func requireGone(t *testing.T, pid int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("grandchild %d survived", pid)
}

// TestKillProcessGroup guards the property the whole feature rests on: killing a
// build must take its grandchildren with it. Signaling only the direct child (the
// os/exec default) leaves systemd-nspawn running and Wait blocked on the pipe.
func TestKillProcessGroup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// print the grandchild's pid, then block so the shell stays alive
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 300 & echo $!; wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = killProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second

	grandchild := startGrandchildTree(t, cmd)
	cancel()

	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("Wait returned no error for a killed process")
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			t.Fatal("Wait hit WaitDelay, output pipe was still held open")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Wait did not return after cancel")
	}

	requireGone(t, grandchild)
}
