package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStallDetector(t *testing.T) {
	t.Parallel()

	const (
		timeout = 30 * time.Minute
		run     = 90 * time.Minute
	)

	tests := []struct {
		name string
		// cpuShare is how many cores worth of CPU time the tree accumulates
		cpuShare float64
		// outputEvery is how often the build writes something, 0 meaning never
		outputEvery time.Duration
		wantStall   bool
	}{
		{name: "compiling normally", cpuShare: 4, outputEvery: time.Minute, wantStall: false},
		{name: "silent but cpu bound", cpuShare: 1, outputEvery: 0, wantStall: false},
		{name: "silent single-core link", cpuShare: 0.5, outputEvery: 0, wantStall: false},
		{name: "chatty but idle", cpuShare: 0, outputEvery: 10 * time.Minute, wantStall: false},
		{name: "hung with no cpu at all", cpuShare: 0, outputEvery: 0, wantStall: true},
		{name: "hung with idle wakeups below floor", cpuShare: 0.001, outputEvery: 0, wantStall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			start := time.Now()
			detector := newStallDetector(timeout, start, 0)

			var (
				cpu        time.Duration
				now        = start
				lastOutput = start
				stalled    bool
				stalledAt  time.Duration
			)

			for range int(run / buildPollInterval) {
				now = now.Add(buildPollInterval)
				cpu += time.Duration(float64(buildPollInterval) * tt.cpuShare)
				if tt.outputEvery > 0 && now.Sub(lastOutput) >= tt.outputEvery {
					lastOutput = now
				}

				if detector.observe(now, cpu, lastOutput) {
					stalled = true
					stalledAt = now.Sub(start)
					break
				}
			}

			if stalled != tt.wantStall {
				t.Fatalf("stalled = %v, want %v (fired after %s)", stalled, tt.wantStall, stalledAt)
			}

			// a stall must never be called before the configured window has passed
			if stalled && stalledAt < timeout {
				t.Fatalf("stalled after %s, want at least %s", stalledAt, timeout)
			}
		})
	}
}

func TestStallDetectorNonMonotonicCPUDoesNotUnderflow(t *testing.T) {
	t.Parallel()

	// the caller clamps CPU to keep it monotonic, but a regression there must not
	// turn into a build that can never be killed
	start := time.Now()
	detector := newStallDetector(time.Minute, start, 10*time.Hour)

	now := start
	for range 120 {
		now = now.Add(buildPollInterval)
		if detector.observe(now, 0, start) {
			return
		}
	}

	t.Fatal("detector never reported a stall for a tree that dropped to zero cpu")
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

// startIdleTree starts a process that burns no CPU and cleans it up on test exit.
func startIdleTree(t *testing.T) *exec.Cmd {
	t.Helper()

	cmd := exec.Command("sleep", "30")
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

func TestBuildMonitorReportsMemoryWithoutStalling(t *testing.T) {
	t.Parallel()

	cmd := startIdleTree(t)
	stalls := make(chan struct{}, 1)

	// a zero stall timeout disables detection, so an idle tree must survive
	monitor := startBuildMonitor(cmd.Process.Pid, newProgressWriter(io.Discard), 0, func() {
		stalls <- struct{}{}
	})
	time.Sleep(2 * buildPollInterval)
	peak := monitor.stop()

	if peak <= 0 {
		t.Errorf("peak memory = %d kB, want > 0", peak)
	}
	select {
	case <-stalls:
		t.Error("onStall fired while stall detection was disabled")
	default:
	}
}

func TestBuildMonitorKillsIdleTree(t *testing.T) {
	t.Parallel()

	cmd := startIdleTree(t)
	stalls := make(chan struct{}, 1)

	monitor := startBuildMonitor(cmd.Process.Pid, newProgressWriter(io.Discard), time.Millisecond, func() {
		stalls <- struct{}{}
	})
	defer monitor.stop()

	select {
	case <-stalls:
	case <-time.After(30 * time.Second):
		t.Fatal("onStall never fired for a process consuming no cpu")
	}
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
	grandchild, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("parsing grandchild pid %q: %v", line, err)
	}

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

	// the grandchild is orphaned onto init once the shell dies, so poll rather than
	// assume it is reaped the instant the group is signaled
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + strconv.Itoa(grandchild)); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("grandchild %d survived the kill", grandchild)
}
