// Package testserver is a fake Routini server for tests. It implements
// POST /api/runner/enroll and GET /api/runner/connect and records every frame
// it receives.
package testserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Default identifiers handed out by the fake server.
const (
	Credential = "rrc_test_credential"
	Token      = "rre_test_token"
	RunnerID   = "11111111-2222-3333-4444-555555555555"
	RunnerName = "test-runner"
)

// Frame is one JSON frame received from the runner.
type Frame map[string]any

// Type returns the frame's type field.
func (f Frame) Type() string { return f.Str("type") }

// ID returns the frame's id field.
func (f Frame) ID() string { return f.Str("id") }

// Str returns a string field, or "".
func (f Frame) Str(k string) string {
	s, _ := f[k].(string)
	return s
}

// Server is the fake Routini server.
type Server struct {
	*httptest.Server
	t        testing.TB
	upgrader websocket.Upgrader

	mu             sync.Mutex
	enrollStatus   int
	enrollBody     any
	enrollRequests []map[string]any
	connectStatus  int
	autoWelcome    bool
	conns          []*Conn
	connCh         chan *Conn
}

// New starts a fake server; it is closed when the test ends.
func New(t testing.TB) *Server {
	s := &Server{
		t:            t,
		enrollStatus: http.StatusCreated,
		enrollBody: map[string]any{
			"runnerId": RunnerID, "credential": Credential, "hostId": "host-1",
			"name": RunnerName, "org": "acme",
		},
		autoWelcome: true,
		connCh:      make(chan *Conn, 64),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/runner/enroll", s.handleEnroll)
	mux.HandleFunc("/api/runner/connect", s.handleConnect)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// Close shuts the server down and drops every connection.
func (s *Server) Close() {
	s.mu.Lock()
	conns := append([]*Conn(nil), s.conns...)
	s.mu.Unlock()
	for _, c := range conns {
		c.Drop()
	}
	s.Server.Close()
}

// SetEnrollResponse sets the status and JSON body of enrollment responses.
func (s *Server) SetEnrollResponse(status int, body any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollStatus, s.enrollBody = status, body
}

// EnrollRequests returns the enrollment request bodies received so far.
func (s *Server) EnrollRequests() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.enrollRequests...)
}

// SetConnectStatus makes /api/runner/connect answer status instead of
// upgrading (0 restores upgrading).
func (s *Server) SetConnectStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectStatus = status
}

// SetAutoWelcome controls whether the server answers hello with welcome.
func (s *Server) SetAutoWelcome(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoWelcome = v
}

// ConnCount returns how many WebSocket connections have been accepted.
func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// NextConn waits for the next accepted connection.
func (s *Server) NextConn(timeout time.Duration) *Conn {
	s.t.Helper()
	select {
	case c := <-s.connCh:
		return c
	case <-time.After(timeout):
		s.t.Fatalf("no runner connection within %s", timeout)
		return nil
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid body"}`))
		return
	}
	s.mu.Lock()
	s.enrollRequests = append(s.enrollRequests, body)
	status, resp := s.enrollStatus, s.enrollBody
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	status, auto := s.connectStatus, s.autoWelcome
	s.mu.Unlock()
	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":"status %d"}`, status)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Credential {
		http.Error(w, `{"error":"unknown credential"}`, http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Routini-Runner-Protocol") != "1" {
		http.Error(w, `{"error":"unsupported protocol"}`, http.StatusUpgradeRequired)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &Conn{
		ws:     ws,
		Header: r.Header.Clone(),
		frames: make(chan Frame, 4096),
		pongs:  make(chan string, 16),
		done:   make(chan struct{}),
	}
	ws.SetPongHandler(func(data string) error {
		select {
		case c.pongs <- data:
		default:
		}
		return nil
	})
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
	go c.readLoop(auto)
	s.connCh <- c
}

// Conn is one runner connection as seen by the server.
type Conn struct {
	ws     *websocket.Conn
	Header http.Header

	wmu    sync.Mutex
	frames chan Frame
	pongs  chan string
	done   chan struct{}

	mu       sync.Mutex
	recorded []Frame
	raw      [][]byte
	closeErr error
}

func (c *Conn) readLoop(autoWelcome bool) {
	defer close(c.done)
	defer close(c.frames)
	for {
		mt, data, err := c.ws.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.closeErr = err
			c.mu.Unlock()
			return
		}
		if mt != websocket.TextMessage {
			continue
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			f = Frame{"type": "__invalid__", "raw": string(data)}
		}
		c.mu.Lock()
		c.recorded = append(c.recorded, f)
		c.raw = append(c.raw, data)
		c.mu.Unlock()
		if autoWelcome && f.Type() == "hello" {
			_ = c.Send(map[string]any{"type": "welcome", "runnerId": RunnerID, "name": RunnerName})
		}
		c.frames <- f
	}
}

// Recorded returns every frame received on this connection so far.
func (c *Conn) Recorded() []Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Frame(nil), c.recorded...)
}

// RawFrames returns the raw bytes of every received frame.
func (c *Conn) RawFrames() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.raw...)
}

// Done is closed when the connection's read side has ended.
func (c *Conn) Done() <-chan struct{} { return c.done }

// CloseErr returns the error that ended the read side (after Done).
func (c *Conn) CloseErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// Send writes v as a JSON text frame.
func (c *Conn) Send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.SendRaw(string(b))
}

// SendRaw writes s as a text frame, verbatim.
func (c *Conn) SendRaw(s string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.ws.WriteMessage(websocket.TextMessage, []byte(s))
}

// Ping sends a WebSocket ping.
func (c *Conn) Ping(data string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.WriteControl(websocket.PingMessage, []byte(data), time.Now().Add(5*time.Second))
}

// WaitPong waits for a pong and returns its payload.
func (c *Conn) WaitPong(timeout time.Duration) (string, bool) {
	select {
	case p := <-c.pongs:
		return p, true
	case <-time.After(timeout):
		return "", false
	}
}

// CloseWith sends a close frame with code, then drops the connection.
func (c *Conn) CloseWith(code int, text string) {
	c.wmu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(time.Second))
	c.wmu.Unlock()
	select {
	case <-c.done:
	case <-time.After(time.Second):
	}
	_ = c.ws.Close()
}

// Drop closes the TCP connection without a close frame.
func (c *Conn) Drop() { _ = c.ws.Close() }

// Next returns the next frame, failing the test after timeout.
func (c *Conn) Next(t testing.TB, timeout time.Duration) Frame {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if !ok {
			t.Fatalf("connection closed while waiting for a frame")
		}
		return f
	case <-time.After(timeout):
		t.Fatalf("no frame within %s", timeout)
		return nil
	}
}

// Expect returns the first frame for which match is true, discarding the
// others. It fails the test after timeout.
func (c *Conn) Expect(t testing.TB, timeout time.Duration, desc string, match func(Frame) bool) Frame {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				t.Fatalf("connection closed while waiting for %s", desc)
			}
			if match(f) {
				return f
			}
		case <-deadline:
			t.Fatalf("no %s within %s", desc, timeout)
			return nil
		}
	}
}

// ExpectType waits for a frame of the given type (and id, if non-empty).
func (c *Conn) ExpectType(t testing.TB, timeout time.Duration, typ, id string) Frame {
	t.Helper()
	return c.Expect(t, timeout, fmt.Sprintf("%s frame (id %q)", typ, id), func(f Frame) bool {
		return f.Type() == typ && (id == "" || f.ID() == id)
	})
}

// Collect gathers frames until done(f) returns true for one of them (that
// frame included), failing the test after timeout.
func (c *Conn) Collect(t testing.TB, timeout time.Duration, done func(Frame) bool) []Frame {
	t.Helper()
	var out []Frame
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				t.Fatalf("connection closed after %d frames: %s", len(out), summarize(out))
			}
			out = append(out, f)
			if done(f) {
				return out
			}
		case <-deadline:
			t.Fatalf("timed out after %s; got %d frames: %s", timeout, len(out), summarize(out))
			return nil
		}
	}
}

// NoFrame asserts that no frame matching match arrives within d.
func (c *Conn) NoFrame(t testing.TB, d time.Duration, match func(Frame) bool) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				return
			}
			if match(f) {
				t.Fatalf("unexpected frame: %v", f)
			}
		case <-deadline:
			return
		}
	}
}

func summarize(fs []Frame) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		b, _ := json.Marshal(f)
		s := string(b)
		if len(s) > 160 {
			s = s[:160] + "..."
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "\n")
}
