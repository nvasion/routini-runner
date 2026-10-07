package envx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

// TTYOpenMsg is the env.tty.open message.
type TTYOpenMsg struct {
	ID          string `json:"id"`
	ContainerID string `json:"containerId"`
	Cols        int    `json:"cols"`
	Rows        int    `json:"rows"`
}

// TTYInputMsg is the env.tty.input message.
type TTYInputMsg struct {
	ID  string `json:"id"`
	B64 string `json:"b64"`
}

// TTYResizeMsg is the env.tty.resize message.
type TTYResizeMsg struct {
	ID   string `json:"id"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// TTYOpenedMsg is the env.tty.opened message.
type TTYOpenedMsg struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// TTYErrorMsg is the env.tty.error message.
type TTYErrorMsg struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Message string `json:"message"`
}

// TTYDataMsg is the env.tty.data message.
type TTYDataMsg struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	B64  string `json:"b64"`
}

// TTYExitMsg is the env.tty.exit message.
type TTYExitMsg struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	ExitCode *int   `json:"exitCode"`
}

func ttyErrorReply(id, msg string) TTYErrorMsg {
	return TTYErrorMsg{Type: TypeTTYError, ID: id, Message: msg}
}

// ttySession is one open environment terminal.
type ttySession struct {
	id   string
	tty  dockerx.TTY
	send SendFunc

	silent atomic.Bool
	input  chan []byte
	done   chan struct{}
}

func (s *ttySession) sendMsg(v any) {
	if !s.silent.Load() {
		s.send(v)
	}
}

func (m *Manager) ttySnapshot() []*ttySession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ttySession, 0, len(m.ttys))
	for _, s := range m.ttys {
		if s.tty != nil {
			out = append(out, s)
		}
	}
	return out
}

func (m *Manager) getTTY(id string) *ttySession {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.ttys[id]
	if s == nil || s.tty == nil {
		return nil
	}
	return s
}

// OpenTTY handles env.tty.open, replying with env.tty.opened or
// env.tty.error. It requires a managed, running environment container and
// refuses a fifth terminal.
func (m *Manager) OpenTTY(msg TTYOpenMsg, send SendFunc) {
	if send == nil {
		m.logf("env.tty.open without a send function ignored")
		return
	}
	if msg.ID == "" {
		m.logf("env.tty.open without id ignored")
		return
	}
	if !m.enabled {
		send(ttyErrorReply(msg.ID, ErrDisabled))
		return
	}
	m.mu.Lock()
	switch {
	case m.ttys[msg.ID] != nil:
		m.mu.Unlock()
		send(ttyErrorReply(msg.ID, ErrAlreadyOpen))
		return
	case len(m.ttys) >= MaxTTYs:
		m.mu.Unlock()
		send(ttyErrorReply(msg.ID, ErrTooMany))
		return
	}
	s := &ttySession{id: msg.ID, send: send, input: make(chan []byte, inputQueue), done: make(chan struct{})}
	m.ttys[msg.ID] = s
	m.mu.Unlock()

	if err := m.startTTY(s, msg); err != nil {
		m.mu.Lock()
		delete(m.ttys, msg.ID)
		m.mu.Unlock()
		m.logf("env tty %s: %v", msg.ID, err)
		send(ttyErrorReply(msg.ID, err.Error()))
	}
}

func (m *Manager) startTTY(s *ttySession, msg TTYOpenMsg) error {
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	info, err := m.opts.Docker.InspectEnv(ctx, msg.ContainerID)
	if err != nil {
		return err
	}
	if !info.Managed {
		return errors.New(ErrContainerMissing)
	}

	tty, err := m.opts.Docker.ExecTTY(context.Background(), msg.ContainerID, ttySize(msg.Cols, 80), ttySize(msg.Rows, 24))
	if err != nil {
		return err
	}
	s.tty = tty
	m.wg.Add(1)
	s.send(TTYOpenedMsg{Type: TypeTTYOpened, ID: s.id})
	go m.runTTY(s)
	return nil
}

// ttySize clamps v to a uint16-sized terminal dimension, falling back to def
// when v is not positive.
func ttySize(v, def int) uint {
	if v <= 0 {
		v = def
	}
	if v > 0xFFFF {
		v = 0xFFFF
	}
	return uint(v)
}

func (m *Manager) runTTY(s *ttySession) {
	defer m.wg.Done()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, ttyChunkSize)
		for {
			n, err := s.tty.Read(buf)
			if n > 0 {
				s.sendMsg(TTYDataMsg{Type: TypeTTYData, ID: s.id, B64: base64.StdEncoding.EncodeToString(buf[:n])})
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
				if _, err := s.tty.Write(b); err != nil {
					m.logf("env tty %s: write: %v", s.id, err)
				}
			case <-s.done:
				return
			}
		}
	}()

	code, waitErr := s.tty.Wait()
	// Drain whatever was still buffered when the shell exited; if another
	// process still holds the terminal open, stop waiting after
	// drainTimeout rather than forever, exactly like ptyx does.
	select {
	case <-readDone:
	case <-time.After(drainTimeout):
	}
	_ = s.tty.Close()
	<-readDone
	close(s.done)

	m.mu.Lock()
	delete(m.ttys, s.id)
	m.mu.Unlock()

	if waitErr != nil {
		m.logf("env tty %s: wait: %v", s.id, waitErr)
	}
	m.logf("env tty %s: shell exited (%s)", s.id, codeDesc(code))
	s.sendMsg(TTYExitMsg{Type: TypeTTYExit, ID: s.id, ExitCode: code})
}

func codeDesc(code *int) string {
	if code == nil {
		return "unknown"
	}
	return fmt.Sprint(*code)
}

// TTYInput handles env.tty.input. Frames for unknown or ended terminals are
// ignored.
func (m *Manager) TTYInput(msg TTYInputMsg) {
	s := m.getTTY(msg.ID)
	if s == nil {
		return
	}
	b, err := base64.StdEncoding.DecodeString(msg.B64)
	if err != nil {
		m.logf("env tty %s: ignoring env.tty.input with invalid base64", msg.ID)
		return
	}
	if len(b) == 0 {
		return
	}
	select {
	case s.input <- b:
	case <-s.done:
	default:
		m.logf("env tty %s: input queue full, dropping %d bytes", msg.ID, len(b))
	}
}

// TTYResize handles env.tty.resize.
func (m *Manager) TTYResize(msg TTYResizeMsg) {
	s := m.getTTY(msg.ID)
	if s == nil {
		return
	}
	if err := s.tty.Resize(ttySize(msg.Cols, 80), ttySize(msg.Rows, 24)); err != nil {
		m.logf("env tty %s: resize: %v", msg.ID, err)
	}
}

// TTYClose handles env.tty.close by closing the session; env.tty.exit
// follows once the shell has ended.
func (m *Manager) TTYClose(id string) {
	s := m.getTTY(id)
	if s == nil {
		return
	}
	m.logf("env tty %s: close requested", id)
	_ = s.tty.Close()
}
