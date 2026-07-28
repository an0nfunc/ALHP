package main

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	// ErrBuildStalled is the cancel cause used when a build produced neither output
	// nor meaningful CPU work for build.stall_timeout.
	ErrBuildStalled = errors.New("build stalled")
	// ErrBuildTimeout is the cancel cause used when a build exceeded build.timeout.
	ErrBuildTimeout = errors.New("build timeout")
)

const (
	// defaultStallTimeout is how long a build may make no progress before it is killed.
	// Deliberately generous: legitimate builds can be silent for a long time, and a
	// false positive costs a rebuild while a missed hang only costs detection latency.
	defaultStallTimeout = 2 * time.Hour

	// cpuProgressFloor is the share of a single core the build tree must average over
	// the current window to count as making progress. A build with makej > 1 sits
	// orders of magnitude above this; a hung process waking on a timer sits far below.
	cpuProgressFloor = 0.01

	// buildPollInterval is how often the build's process tree is sampled.
	buildPollInterval = 1 * time.Second

	// buildKillGrace bounds how long Wait may block on output pipes after the build
	// was killed, so a leaked grandchild holding the pipe cannot hang the worker.
	buildKillGrace = 30 * time.Second
)

// buildStallTimeout returns the configured no-progress timeout. Zero disables stall detection.
func buildStallTimeout() time.Duration {
	return confDuration(conf.Build.StallTimeout, defaultStallTimeout, "build.stall_timeout")
}

// buildTimeout returns the absolute wall-clock cap per build. Zero (the default) disables it.
func buildTimeout() time.Duration {
	return confDuration(conf.Build.Timeout, 0, "build.timeout")
}

func confDuration(raw string, def time.Duration, name string) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Warningf("invalid %s %q, falling back to %s: %v", name, raw, def, err)
		return def
	}
	if d < 0 {
		log.Warningf("negative %s %q, falling back to %s", name, raw, def)
		return def
	}
	return d
}

// killReason classifies a build's cancel cause, reporting the Prometheus label and
// the skip reason to persist, with ok false when the build was not killed by one of
// our own deadlines. Both values are kept out of the error text so that rewording an
// error cannot silently rename a metric label or a stored skip reason.
func killReason(cause error) (metric, skipReason string, ok bool) {
	switch {
	case errors.Is(cause, ErrBuildStalled):
		return "stalled", SkipReasonStalled, true
	case errors.Is(cause, ErrBuildTimeout):
		return "timeout", SkipReasonTimeout, true
	default:
		return "", "", false
	}
}

// killProcessGroup builds a cmd.Cancel function that SIGKILLs the entire process
// group of cmd. It requires SysProcAttr.Setpgid, which makes the group id equal to
// the child's pid; signaling the pid alone would leave nested containers running.
// Unlike the default Cancel, which goes through os.Process and so is protected
// against pid reuse, this signals a raw pid. Cmd.Wait reaps the child before it
// resolves the cancel handshake, so a cancel landing in that window signals a
// released pid; that needs a full pid wraparound inside a microsecond to bite.
func killProcessGroup(cmd *exec.Cmd) func() error {
	return func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// progressWriter records when output was last written, so a stalled build can be
// told apart from one that is merely slow.
type progressWriter struct {
	// created carries a monotonic reading, and last is stored as an offset from it
	// rather than as a wall-clock timestamp. Add preserves that reading, so the
	// detector compares like with like and a clock step cannot mask a stall.
	created time.Time
	w       io.Writer
	last    atomic.Int64
}

func newProgressWriter(w io.Writer) *progressWriter {
	return &progressWriter{created: time.Now(), w: w}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.last.Store(int64(time.Since(p.created)))
	return p.w.Write(b)
}

func (p *progressWriter) lastWrite() time.Time {
	return p.created.Add(time.Duration(p.last.Load()))
}

// stallDetector tracks a window during which a build produced no output and no
// meaningful CPU work. Progress on either signal reopens the window, so a silent
// but CPU-bound step (a long LTO link) is not mistaken for a hang, and a hung test
// blocked on a socket is not kept alive by its own idle wakeups.
type stallDetector struct {
	timeout     time.Duration
	windowStart time.Time
	windowCPU   time.Duration
}

func newStallDetector(timeout time.Duration, now time.Time, cpu time.Duration) *stallDetector {
	return &stallDetector{timeout: timeout, windowStart: now, windowCPU: cpu}
}

// observe feeds one sample to the detector and reports whether the build is stalled.
// cpu must be monotonic across calls.
func (s *stallDetector) observe(now time.Time, cpu time.Duration, lastOutput time.Time) bool {
	elapsed := now.Sub(s.windowStart)

	wrote := lastOutput.After(s.windowStart)
	computed := cpu-s.windowCPU >= time.Duration(float64(elapsed)*cpuProgressFloor)
	if wrote || computed {
		s.windowStart = now
		s.windowCPU = cpu
		return false
	}

	return elapsed >= s.timeout
}

// buildMonitor samples a running build's process tree in the background, tracking
// peak memory and watching for a lack of progress.
type buildMonitor struct {
	done   chan struct{}
	result chan int64
}

// startBuildMonitor begins sampling the process tree rooted at pid. When stallTimeout
// is non-zero and the build stops making progress, onStall is called once and is
// expected to kill the build. Every monitor must be stopped.
func startBuildMonitor(pid int, out *progressWriter, stallTimeout time.Duration, onStall func()) *buildMonitor {
	m := &buildMonitor{done: make(chan struct{}), result: make(chan int64)}
	go m.poll(pid, out, stallTimeout, onStall)
	return m
}

// stop ends the sampling and returns the tree's peak memory (RSS+swap, in kB).
func (m *buildMonitor) stop() int64 {
	close(m.done)
	return <-m.result
}

func (m *buildMonitor) poll(pid int, out *progressWriter, stallTimeout time.Duration, onStall func()) {
	var (
		peakMemory int64
		maxCPU     time.Duration
		killed     bool
	)
	detector := newStallDetector(stallTimeout, time.Now(), 0)

	for {
		select {
		case <-m.done:
			m.result <- peakMemory
			return
		default:
		}

		memory, cpu := sampleProcessTree(pid)
		if memory > peakMemory {
			peakMemory = memory
		}
		// the walk races with processes exiting, so a sample can come back short.
		// clamp to keep the series monotonic for the detector.
		if cpu > maxCPU {
			maxCPU = cpu
		}

		if stallTimeout > 0 && !killed && detector.observe(time.Now(), maxCPU, out.lastWrite()) {
			killed = true
			onStall()
		}

		time.Sleep(buildPollInterval)
	}
}
