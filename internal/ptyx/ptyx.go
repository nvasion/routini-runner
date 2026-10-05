// Package ptyx runs interactive terminals (PROTOCOL.md section 2.4): a login
// shell in a pseudo-terminal, with base64 framing in both directions.
package ptyx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"

	"github.com/nvasion/routini-runner/internal/execx"
)

// Error messages sent in pty.error.
const (
	ErrDisabled     = "terminals are disabled on this runner"
	ErrTooMany      = "too many terminals"
	ErrAlreadyOpen  = "terminal id is already open"
	ErrShuttingDown = "runner is shutting down"
)

// DefaultMax is the maximum number of open terminals.
const DefaultMax = 4

// DefaultHangupGrace is the delay between SIGHUP and SIGKILL on pty.close.
const DefaultHangupGrace = 2 * time.Second

// ChunkSize is the largest pty.data payload (before base64).
const ChunkSize = 32 * 1024

// drainTimeout bounds how long output is drained after the shell exits while
// another process still holds the terminal open.
const drainTimeout = 500 * time.Millisecond

const inputQueue = 256

// OpenMsg is the pty.open message.
type OpenMsg struct {
	ID   string `json:"id"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// InputMsg is the pty.input message.
type InputMsg struct {
	ID  string `json:"id"`
	B64 string `json:"b64"`
}

// ResizeMsg is the pty.resize message.
type ResizeMsg struct {
	ID   string `json:"id"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// CloseMsg is the pty.close message.
type CloseMsg struct {
	ID string `json:"id"`
}

// OpenedMsg is the pty.opened message.
type OpenedMsg struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ErrorMsg is the pty.error message.
type ErrorMsg struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Message string `json:"message"`
}

// DataMsg is the pty.data message.
type DataMsg struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	B64  string `json:"b64"`
}

// ExitMsg is the pty.exit message.
type ExitMsg struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	ExitCode *int   `json:"exitCode"`
}

// ErrorReply returns a pty.error message.
func ErrorReply(id, msg string) ErrorMsg {
	return ErrorMsg{Type: "pty.error", ID: id, Message: msg}
}

// SendFunc delivers one message to the server.
type SendFunc func(v any)

// Options configures a Manager.
type Options struct {
	Enabled     bool
	Max         int           // default 4
	HangupGrace time.Duration // default 2s
	Logger      *log.Logger
}

// Manager tracks open terminals.
type Manager struct {
	opts Options

	mu       sync.Mutex
	sessions map[string]*session
	closed   bool
	wg       sync.WaitGroup
}

// NewManager returns a Manager.
func NewManager(opts Options) *Manager {
	if opts.Max <= 0 {
		opts.Max = DefaultMax
	}
	if opts.HangupGrace <= 0 {
		opts.HangupGrace = DefaultHangupGrace
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	return &Manager{opts: opts, sessions: make(map[string]*session)}
}

type session struct {
	id    string
	cmd   *exec.Cmd
	ptmx  *os.File
	send  SendFunc
	grace time.Duration
	input chan []byte
	done  chan struct{} // closed when the session has ended

	silent atomic.Bool

	mu       sync.Mutex
	finished bool // the shell has been reaped: never signal its group again
	hungUp   bool
	timer    *time.Timer
}

func (s *session) sendMsg(v any) {
	if !s.silent.Load() {
		s.send(v)
	}
}

// hangup sends SIGHUP to the shell's process group, then SIGKILL after the
// grace period if the shell is still running.
func (s *session) hangup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.hungUp {
		return
	}
	s.hungUp = true
	pgid := s.cmd.Process.Pid // Setsid: the shell leads its own session and group
	_ = syscall.Kill(-pgid, syscall.SIGHUP)
	s.timer = time.AfterFunc(s.grace, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.finished {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
	})
}

// Count returns the number of open terminals.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Open handles pty.open, replying with pty.opened or pty.error.
func (m *Manager) Open(msg OpenMsg, send SendFunc) {
	if msg.ID == "" {
		m.opts.Logger.Printf("pty.open without id ignored")
		return
	}
	if !m.opts.Enabled {
		send(ErrorReply(msg.ID, ErrDisabled))
		return
	}
	m.mu.Lock()
	switch {
	case m.closed:
		m.mu.Unlock()
		send(ErrorReply(msg.ID, ErrShuttingDown))
		return
	case m.sessions[msg.ID] != nil:
		m.mu.Unlock()
		send(ErrorReply(msg.ID, ErrAlreadyOpen))
		return
	case len(m.sessions) >= m.opts.Max:
		m.mu.Unlock()
		send(ErrorReply(msg.ID, ErrTooMany))
		return
	}
	s := &session{
		id:    msg.ID,
		send:  send,
		grace: m.opts.HangupGrace,
		input: make(chan []byte, inputQueue),
		done:  make(chan struct{}),
	}
	m.sessions[msg.ID] = s // reserve the slot while starting
	m.mu.Unlock()

	if err := m.start(s, msg); err != nil {
		m.mu.Lock()
		delete(m.sessions, msg.ID)
		m.mu.Unlock()
		m.opts.Logger.Printf("pty %s: %v", msg.ID, err)
		send(ErrorReply(msg.ID, err.Error()))
		return
	}
}

func (m *Manager) start(s *session, msg OpenMsg) error {
	shell := FindShell()
	cmd := exec.Command(shell, "-l")
	cmd.Dir = execx.HomeDir()
	cmd.Env = execx.MergeEnv(os.Environ(), map[string]string{
		"TERM": "xterm-256color",
		"LANG": "C.UTF-8",
	})
	// pty.StartWithSize sets Setsid and Setctty; Setpgid must not be set too.
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: clampSize(msg.Rows, 24), Cols: clampSize(msg.Cols, 80)})
	if err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}
	ptmx, err := pollable(f)
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		return fmt.Errorf("failed to start shell: %v", err)
	}
	m.mu.Lock()
	s.cmd, s.ptmx = cmd, ptmx
	m.mu.Unlock()

	m.wg.Add(1)
	m.opts.Logger.Printf("pty %s: opened (%s, pid %d)", s.id, shell, cmd.Process.Pid)
	s.send(OpenedMsg{Type: "pty.opened", ID: s.id})
	go m.run(s)
	return nil
}

// pollable re-opens the pty master as a non-blocking file managed by Go's
// poller, so that Close reliably interrupts a blocked Read. (creack/pty uses
// File.Fd for its ioctls, which leaves the file in blocking mode.)
func pollable(f *os.File) (*os.File, error) {
	defer f.Close()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/ptmx"), nil
}

func (m *Manager) run(s *session) {
	defer m.wg.Done()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, ChunkSize)
		for {
			n, err := s.ptmx.Read(buf)
			if n > 0 {
				s.sendMsg(DataMsg{Type: "pty.data", ID: s.id, B64: base64.StdEncoding.EncodeToString(buf[:n])})
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case b := <-s.input:
				if _, err := s.ptmx.Write(b); err != nil {
					if !errors.Is(err, os.ErrClosed) {
						m.opts.Logger.Printf("pty %s: write: %v", s.id, err)
					}
				}
			case <-s.done:
				return
			}
		}
	}()

	_ = s.cmd.Wait()
	s.mu.Lock()
	s.finished = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()

	// Drain what the shell wrote before exiting. The read ends with EIO once
	// no process holds the terminal; if a background process still does,
	// stop waiting after drainTimeout.
	select {
	case <-readDone:
	case <-time.After(drainTimeout):
	}
	_ = s.ptmx.Close()
	<-readDone
	close(s.done)

	m.mu.Lock()
	delete(m.sessions, s.id)
	m.mu.Unlock()

	code := exitCode(s.cmd.ProcessState)
	desc := "signal"
	if code != nil {
		desc = fmt.Sprint(*code)
	}
	m.opts.Logger.Printf("pty %s: shell exited (%s)", s.id, desc)
	s.sendMsg(ExitMsg{Type: "pty.exit", ID: s.id, ExitCode: code})
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

func (m *Manager) get(id string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil || s.cmd == nil {
		return nil
	}
	return s
}

// Input handles pty.input. Frames for unknown or ended sessions are ignored.
func (m *Manager) Input(msg InputMsg) {
	s := m.get(msg.ID)
	if s == nil {
		return
	}
	b, err := base64.StdEncoding.DecodeString(msg.B64)
	if err != nil {
		m.opts.Logger.Printf("pty %s: ignoring pty.input with invalid base64", msg.ID)
		return
	}
	if len(b) == 0 {
		return
	}
	select {
	case s.input <- b:
	case <-s.done:
	default:
		m.opts.Logger.Printf("pty %s: input queue full, dropping %d bytes", msg.ID, len(b))
	}
}

// Resize handles pty.resize.
func (m *Manager) Resize(msg ResizeMsg) {
	s := m.get(msg.ID)
	if s == nil {
		return
	}
	ws := pty.Winsize{Rows: clampSize(msg.Rows, 24), Cols: clampSize(msg.Cols, 80)}
	if err := setsize(s.ptmx, &ws); err != nil && !errors.Is(err, os.ErrClosed) {
		m.opts.Logger.Printf("pty %s: resize: %v", msg.ID, err)
	}
}

// setsize is pty.Setsize without File.Fd, which would switch the file back
// to blocking mode.
func setsize(f *os.File, ws *pty.Winsize) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// Close handles pty.close: SIGHUP to the shell's process group, then SIGKILL
// after the grace period. pty.exit follows when the shell has ended.
func (m *Manager) Close(id string) {
	if s := m.get(id); s != nil {
		m.opts.Logger.Printf("pty %s: close requested", id)
		s.hangup()
	}
}

// AbortAll closes every terminal without sending anything more for them.
// It is used when the control connection drops.
func (m *Manager) AbortAll() {
	for _, s := range m.snapshot() {
		s.silent.Store(true)
		s.hangup()
	}
}

// Shutdown refuses new terminals and closes the open ones.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	for _, s := range m.snapshot() {
		s.hangup()
	}
}

// Wait waits up to d for all terminals to end and reports whether they did.
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

func (m *Manager) snapshot() []*session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if s.cmd != nil {
			out = append(out, s)
		}
	}
	return out
}

// FindShell returns $SHELL, /bin/bash or /bin/sh, whichever exists first.
func FindShell() string {
	if sh := os.Getenv("SHELL"); sh != "" && isExecutable(sh) {
		return sh
	}
	for _, sh := range []string{"/bin/bash", "/bin/sh"} {
		if isExecutable(sh) {
			return sh
		}
	}
	return "/bin/sh"
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

func clampSize(v, def int) uint16 {
	if v <= 0 {
		return uint16(def)
	}
	if v > 0xFFFF {
		return 0xFFFF
	}
	return uint16(v)
}
