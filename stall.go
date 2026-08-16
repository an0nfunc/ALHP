package main

import (
	"errors"
	"fmt"
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
	// ErrBuildSilent is the cancel cause used when a build produced no output at all
	// for build.silence_timeout, however busy it looked.
	ErrBuildSilent = errors.New("build silent")
	// ErrBuildTimeout is the cancel cause used when a build exceeded build.timeout.
	ErrBuildTimeout = errors.New("build timeout")
)

const (
	// Both windows below are deliberately generous, because the two ways of being
	// wrong are not symmetric. A missed hang costs detection latency. A false positive
	// costs the package: the build is recorded failed, the already published optimized
	// package is purged from the repo, and isPkgFailed then holds the failure until
	// upstream ships a new version, so it does not simply come back on the next pass.

	// defaultStallTimeout is how long a build may make no progress before it is killed.
	// Legitimate builds can be silent for a long time.
	defaultStallTimeout = 2 * time.Hour

	// defaultSilenceTimeout is how long a build may produce no output whatsoever,
	// regardless of how much CPU it burns, before it is killed. It covers the hang
	// stall detection is structurally blind to: a test runner that deadlocks with its
	// worker threads spinning looks like progress to it forever, so without this
	// window only build.timeout would ever end that build, and that one is off by
	// default. Set far above the longest legitimate silent stretch, a large LTO link
	// at roughly an hour.
	defaultSilenceTimeout = 6 * time.Hour

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

// stallLimits are the two no-progress windows applied to a running build. They
// differ only in what reopens them: stall accepts CPU work as progress, silence
// accepts nothing but output. A zero window is disabled.
type stallLimits struct {
	stall   time.Duration
	silence time.Duration
}

// buildStallLimits returns the configured windows. Zero disables that window.
func buildStallLimits() stallLimits {
	return stallLimits{
		stall:   confDuration(conf.Build.StallTimeout, defaultStallTimeout, "build.stall_timeout"),
		silence: confDuration(conf.Build.SilenceTimeout, defaultSilenceTimeout, "build.silence_timeout"),
	}
}

// reason renders a kill for the log, naming the window that tripped and how long
// it was open. Only the detector's own causes carry a window, so anything else is
// reported as-is rather than mislabelled as one of them.
func (l stallLimits) reason(cause error) string {
	switch {
	// unreachable, the monitor only calls this for a cause it just produced, but a
	// panic here would land in the monitor goroutine and take the daemon with it
	case cause == nil:
		return "unknown reason"
	case errors.Is(cause, ErrBuildStalled):
		return fmt.Sprintf("no progress for %s", l.stall)
	case errors.Is(cause, ErrBuildSilent):
		return fmt.Sprintf("no output for %s", l.silence)
	default:
		return cause.Error()
	}
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
//
// Every skip reason returned here must also appear in killSkipReasons.
func killReason(cause error) (metric, skipReason string, ok bool) {
	switch {
	case errors.Is(cause, ErrBuildStalled):
		return "stalled", SkipReasonStalled, true
	case errors.Is(cause, ErrBuildSilent):
		return "silent", SkipReasonSilent, true
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
//
// Only works when ALHP itself runs as root. makechrootpkg elevates via sudo, so
// the whole build tree is root-owned; signaling it from an unprivileged ALHP
// returns EPERM and kills nothing. That is why network-isolated builds route
// cancellation through the alhp-netns helper instead, which does the killing as
// root. This path remains for build.network_isolation: false.
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

// stallDetector tracks two windows over a running build.
//
// The stall window is reopened by output or by CPU work, so a silent but CPU-bound
// step (a long LTO link) is not mistaken for a hang, and a hung test blocked on a
// socket is not kept alive by its own idle wakeups.
//
// The silence window is reopened by output alone. It is the only thing that catches
// a hang which keeps a core busy, such as a deadlocked test runner whose threads
// spin: to the stall window that is indistinguishable from a long link, forever.
// Because it ignores CPU entirely it is the blunter of the two and runs on a much
// longer timeout.
type stallDetector struct {
	limits stallLimits

	// the windows are reopened by different signals, so their starts drift apart and
	// each is measured against its own
	stallStart   time.Time
	stallCPU     time.Duration
	silenceStart time.Time
}

func newStallDetector(limits stallLimits, now time.Time, cpu time.Duration) *stallDetector {
	return &stallDetector{limits: limits, stallStart: now, stallCPU: cpu, silenceStart: now}
}

// observe feeds one sample to the detector and reports the cancel cause the build
// must be killed with, or nil while it is still making progress. cpu must be
// monotonic across calls.
func (s *stallDetector) observe(now time.Time, cpu time.Duration, lastOutput time.Time) error {
	elapsed := now.Sub(s.stallStart)
	computed := cpu-s.stallCPU >= time.Duration(float64(elapsed)*cpuProgressFloor)

	switch {
	case lastOutput.After(s.stallStart) || computed:
		s.stallStart = now
		s.stallCPU = cpu
	case s.limits.stall > 0 && elapsed >= s.limits.stall:
		return ErrBuildStalled
	}

	switch {
	case lastOutput.After(s.silenceStart):
		s.silenceStart = now
	case s.limits.silence > 0 && now.Sub(s.silenceStart) >= s.limits.silence:
		return ErrBuildSilent
	}

	return nil
}

// buildMonitor samples a running build's process tree in the background, tracking
// peak memory and watching for a lack of progress.
type buildMonitor struct {
	done   chan struct{}
	result chan int64
}

// startBuildMonitor begins sampling the process tree rooted at pid. When the build
// trips one of the enabled windows, onKill is called once with the cause and is
// expected to kill the build. Every monitor must be stopped.
func startBuildMonitor(pid int, out *progressWriter, limits stallLimits, onKill func(error)) *buildMonitor {
	m := &buildMonitor{done: make(chan struct{}), result: make(chan int64)}
	go m.poll(pid, out, limits, onKill)
	return m
}

// stop ends the sampling and returns the tree's peak memory (RSS+swap, in kB).
func (m *buildMonitor) stop() int64 {
	close(m.done)
	return <-m.result
}

func (m *buildMonitor) poll(pid int, out *progressWriter, limits stallLimits, onKill func(error)) {
	var (
		peakMemory int64
		maxCPU     time.Duration
		killed     bool
	)
	detector := newStallDetector(limits, time.Now(), 0)

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

		if !killed {
			if cause := detector.observe(time.Now(), maxCPU, out.lastWrite()); cause != nil {
				killed = true
				onKill(cause)
			}
		}

		time.Sleep(buildPollInterval)
	}
}
