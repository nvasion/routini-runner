// Package execx runs exec.start commands (PROTOCOL.md section 2.3): each in a
// new process group under /bin/sh -c, with line-by-line output streaming,
// timeouts, cancellation and a concurrency cap.
package execx

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Error messages sent in exec.exit when a command never ran.
const (
	ErrDisabled      = "exec is disabled on this runner"
	ErrInvalidEnvKey = "invalid env key"
	ErrShuttingDown  = "runner is shutting down"
)

// Timeout limits, in seconds.
const (
	DefaultTimeoutSec = 600
	MaxTimeoutSec     = 86400
)

// DefaultKillGrace is the delay between SIGTERM and SIGKILL.
const DefaultKillGrace = 5 * time.Second

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// StartMsg is the exec.start message.
type StartMsg struct {
	ID         string            `json:"id"`
	Command    string            `json:"command"`
	Env        map[string]string `json:"env"`
	Cwd        *string           `json:"cwd"`
	TimeoutSec *int              `json:"timeoutSec"`
}

// CancelMsg is the exec.cancel message.
type CancelMsg struct {
	ID string `json:"id"`
}

// OutputMsg is the exec.output message.
type OutputMsg struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Stream string `json:"stream"`
	Data   string `json:"data"`
}

// ExitMsg is the exec.exit message.
type ExitMsg struct {
	Type     string  `json:"type"`
	ID       string  `json:"id"`
	ExitCode *int    `json:"exitCode"`
	TimedOut bool    `json:"timedOut"`
	Canceled bool    `json:"canceled"`
	Error    *string `json:"error"`
}

// ErrorExit returns the exec.exit sent for a command that never ran.
func ErrorExit(id, msg string) ExitMsg {
	return ExitMsg{Type: "exec.exit", ID: id, Error: &msg}
}

// SendFunc delivers one message to the server. It must be safe for
// concurrent use and must not block forever when the connection is gone.
type SendFunc func(v any)

// Options configures a Manager.
type Options struct {
	Enabled   bool
	Max       int           // maximum concurrent commands; default 8
	KillGrace time.Duration // SIGTERM to SIGKILL delay; default 5s
	Logger    *log.Logger
}

// Manager tracks the running commands.
type Manager struct {
	opts Options

	mu     sync.Mutex
	jobs   map[string]*job
	closed bool
	wg     sync.WaitGroup
}

// NewManager returns a Manager.
func NewManager(opts Options) *Manager {
	if opts.Max <= 0 {
		opts.Max = 8
	}
	if opts.KillGrace <= 0 {
		opts.KillGrace = DefaultKillGrace
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	return &Manager{opts: opts, jobs: make(map[string]*job)}
}

type stopReason int

const (
	notStopped stopReason = iota
	stopCanceled
	stopTimedOut
)

type job struct {
	id    string
	cmd   *exec.Cmd
	send  SendFunc
	grace time.Duration

	silent atomic.Bool // set when the connection dropped: send nothing more

	mu        sync.Mutex
	pgid      int
	reason    stopReason
	finished  bool
	killTimer *time.Timer
}

func (j *job) sendMsg(v any) {
	if !j.silent.Load() {
		j.send(v)
	}
}

// stop sends SIGTERM to the process group, then SIGKILL after the grace
// period. The first reason wins. It never signals after the process has been
// reaped, so a recycled process-group id is never hit.
func (j *job) stop(r stopReason) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.finished || j.reason != notStopped {
		return
	}
	j.reason = r
	if j.pgid != 0 {
		j.signalLocked()
	}
}

// setPgid records the process group once the command has started, applying
// a stop that was requested while it was starting.
func (j *job) setPgid(pgid int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.pgid = pgid
	if j.reason != notStopped {
		j.signalLocked()
	}
}

func (j *job) signalLocked() {
	_ = syscall.Kill(-j.pgid, syscall.SIGTERM)
	j.killTimer = time.AfterFunc(j.grace, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		if !j.finished {
			_ = syscall.Kill(-j.pgid, syscall.SIGKILL)
		}
	})
}

// Running returns the number of commands currently running.
func (m *Manager) Running() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs)
}

// Start handles exec.start. Every outcome, including refusals, is reported
// through send as exec.output / exec.exit messages.
func (m *Manager) Start(msg StartMsg, send SendFunc) {
	if msg.ID == "" {
		m.opts.Logger.Printf("exec.start without id ignored")
		return
	}
	if !m.opts.Enabled {
		send(ErrorExit(msg.ID, ErrDisabled))
		return
	}
	for k := range msg.Env {
		if !envKeyRe.MatchString(k) {
			send(ErrorExit(msg.ID, ErrInvalidEnvKey))
			return
		}
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		send(ErrorExit(msg.ID, ErrShuttingDown))
		return
	}
	if _, dup := m.jobs[msg.ID]; dup {
		m.mu.Unlock()
		m.opts.Logger.Printf("exec %s: already running; duplicate exec.start ignored", msg.ID)
		return
	}
	if n := len(m.jobs); n >= m.opts.Max {
		m.mu.Unlock()
		send(ErrorExit(msg.ID, fmt.Sprintf("runner busy (%d commands running)", n)))
		return
	}
	j := &job{id: msg.ID, send: send, grace: m.opts.KillGrace}
	m.jobs[msg.ID] = j
	m.wg.Add(1)
	m.mu.Unlock()

	if err := m.spawn(j, msg); err != nil {
		m.mu.Lock()
		delete(m.jobs, msg.ID)
		m.mu.Unlock()
		m.wg.Done()
		m.opts.Logger.Printf("exec %s: %v", msg.ID, err)
		send(ErrorExit(msg.ID, err.Error()))
	}
}

func (m *Manager) spawn(j *job, msg StartMsg) error {
	cmd := exec.Command("/bin/sh", "-c", msg.Command)
	cmd.Env = MergeEnv(os.Environ(), msg.Env)
	cmd.Dir = HomeDir()
	if msg.Cwd != nil && *msg.Cwd != "" {
		cmd.Dir = *msg.Cwd
	}
	cmd.Stdin = nil // os/exec connects a nil Stdin to /dev/null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("spawn failed: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("spawn failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn failed: %v", err)
	}
	j.cmd = cmd
	j.setPgid(cmd.Process.Pid) // Setpgid with Pgid 0: the group id is the child's pid

	m.opts.Logger.Printf("exec %s: started (pid %d)", j.id, cmd.Process.Pid)
	go m.run(j, stdout, stderr, timeoutFor(msg.TimeoutSec))
	return nil
}

func timeoutFor(sec *int) time.Duration {
	s := DefaultTimeoutSec
	if sec != nil && *sec > 0 {
		s = *sec
	}
	if s > MaxTimeoutSec {
		s = MaxTimeoutSec
	}
	return time.Duration(s) * time.Second
}

func (m *Manager) run(j *job, stdout, stderr io.Reader, timeout time.Duration) {
	defer m.wg.Done()
	started := time.Now()
	timer := time.AfterFunc(timeout, func() { j.stop(stopTimedOut) })

	var readers sync.WaitGroup
	readers.Add(2)
	pump := func(r io.Reader, stream string) {
		defer readers.Done()
		splitLines(r, func(line string) {
			j.sendMsg(OutputMsg{Type: "exec.output", ID: j.id, Stream: stream, Data: line})
		})
	}
	go pump(stdout, "stdout")
	go pump(stderr, "stderr")
	// Both pipes must be drained before Wait (which closes them); only then
	// is exec.exit sent, so it always follows the last output line.
	readers.Wait()
	_ = j.cmd.Wait()
	timer.Stop()

	j.mu.Lock()
	j.finished = true
	if j.killTimer != nil {
		j.killTimer.Stop()
	}
	reason := j.reason
	j.mu.Unlock()

	m.mu.Lock()
	delete(m.jobs, j.id)
	m.mu.Unlock()

	exit := ExitMsg{
		Type:     "exec.exit",
		ID:       j.id,
		ExitCode: exitCode(j.cmd.ProcessState),
		TimedOut: reason == stopTimedOut,
		Canceled: reason == stopCanceled,
	}
	code := "signal"
	if exit.ExitCode != nil {
		code = fmt.Sprint(*exit.ExitCode)
	}
	m.opts.Logger.Printf("exec %s: finished exit=%s timedOut=%v canceled=%v in %s",
		j.id, code, exit.TimedOut, exit.Canceled, time.Since(started).Round(time.Millisecond))
	j.sendMsg(exit)
}

func exitCode(ps *os.ProcessState) *int {
	if ps == nil {
		return nil
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return nil
	}
	if !ps.Exited() {
		return nil
	}
	c := ps.ExitCode()
	return &c
}

// Cancel handles exec.cancel. Unknown ids are ignored.
func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	j := m.jobs[id]
	m.mu.Unlock()
	if j != nil {
		m.opts.Logger.Printf("exec %s: cancel requested", id)
		j.stop(stopCanceled)
	}
}

// AbortAll cancels every running command without reporting anything more
// for them. It is used when the control connection drops.
func (m *Manager) AbortAll() {
	for _, j := range m.snapshot() {
		j.silent.Store(true)
		j.stop(stopCanceled)
	}
}

// Shutdown refuses new commands and cancels the running ones; their
// exec.exit (canceled) is still sent while the connection is up.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	for _, j := range m.snapshot() {
		j.stop(stopCanceled)
	}
}

// Wait waits up to d for all commands to finish and reports whether they did.
func (m *Manager) Wait(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (m *Manager) snapshot() []*job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j)
	}
	return out
}

// MergeEnv returns base with extra merged on top (extra wins).
func MergeEnv(base []string, extra map[string]string) []string {
	out := make([]string, 0, len(base)+len(extra))
	idx := make(map[string]int, len(base)+len(extra))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kv := k + "=" + extra[k]
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	return out
}

// HomeDir returns the runner user's home directory, or "/" if it cannot be
// found.
func HomeDir() string {
	if h, err := os.UserHomeDir(); err == nil && isDir(h) {
		return h
	}
	if u, err := user.Current(); err == nil && isDir(u.HomeDir) {
		return u.HomeDir
	}
	return "/"
}

func isDir(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
