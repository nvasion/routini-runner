package conn_test

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/testserver"
)

const wait = 10 * time.Second

// logWriter forwards runner logs to the test log until the test ends.
type logWriter struct {
	mu      sync.Mutex
	t       testing.TB
	stopped bool
	buf     strings.Builder
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if !w.stopped {
		w.t.Logf("runner: %s", strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}

func (w *logWriter) stop() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
}

func (w *logWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type harness struct {
	srv    *testserver.Server
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	logs   *logWriter
}

// startRunner runs a Runner against srv with test-friendly timings.
func startRunner(t *testing.T, srv *testserver.Server, mutate func(*config.Config, *conn.Options)) *harness {
	t.Helper()
	cfg := config.New()
	cfg.URL = srv.URL
	cfg.RunnerID = testserver.RunnerID
	cfg.Credential = testserver.Credential
	lw := &logWriter{t: t}
	opts := conn.Options{
		Config:        cfg,
		Logger:        log.New(lw, "", log.Lmicroseconds),
		Backoff:       conn.Backoff{Initial: 20 * time.Millisecond, Max: 100 * time.Millisecond, Jitter: 0.2, ResetAfter: time.Minute},
		KillGrace:     time.Second,
		HangupGrace:   500 * time.Millisecond,
		FactsInterval: time.Hour,
		Hostname:      "test-host",
	}
	if mutate != nil {
		mutate(cfg, &opts)
	}
	r, err := conn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{srv: srv, cancel: cancel, done: make(chan struct{}), logs: lw}
	go func() {
		h.err = r.Run(ctx)
		close(h.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(15 * time.Second):
			t.Error("runner did not stop within 15s")
		}
		lw.stop()
	})
	return h
}

// wait waits for Run to return and gives its error.
func (h *harness) wait(t *testing.T, d time.Duration) error {
	t.Helper()
	select {
	case <-h.done:
		return h.err
	case <-time.After(d):
		t.Fatalf("Run did not return within %s", d)
		return nil
	}
}

// connect waits for the runner's connection and its hello.
func connect(t *testing.T, srv *testserver.Server) (*testserver.Conn, testserver.Frame) {
	t.Helper()
	c := srv.NextConn(wait)
	hello := c.ExpectType(t, wait, "hello", "")
	return c, hello
}

func execStart(id, command string, extra map[string]any) map[string]any {
	m := map[string]any{"type": "exec.start", "id": id, "command": command}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// execResult gathers the output lines and the exit frame of one exec.
type execResult struct {
	stdout, stderr []string
	exit           testserver.Frame
	afterExit      int // frames for this id after exec.exit (must be 0)
}

func collectExec(t *testing.T, c *testserver.Conn, id string, timeout time.Duration) execResult {
	t.Helper()
	var r execResult
	frames := c.Collect(t, timeout, func(f testserver.Frame) bool {
		return f.Type() == "exec.exit" && f.ID() == id
	})
	for _, f := range frames {
		if f.ID() != id {
			continue
		}
		switch f.Type() {
		case "exec.output":
			if f.Str("stream") == "stdout" {
				r.stdout = append(r.stdout, f.Str("data"))
			} else {
				r.stderr = append(r.stderr, f.Str("data"))
			}
		case "exec.exit":
			r.exit = f
		}
	}
	return r
}

func exitCode(f testserver.Frame) (int, bool) {
	v, ok := f["exitCode"].(float64)
	return int(v), ok
}

// procAlive reports whether pid exists and is not a zombie.
func procAlive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	return state != 'Z' && state != 'X'
}

func waitDead(t *testing.T, pid int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !procAlive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d is still alive after %s", pid, d)
}

func ptyInput(id, s string) map[string]any {
	return map[string]any{"type": "pty.input", "id": id, "b64": base64.StdEncoding.EncodeToString([]byte(s))}
}

var pidRe = regexp.MustCompile(`PID=(\d+)\r?\n`)

// ptyPid asks the shell in session id for its pid. The typed command is
// echoed as "PID=$((0+$$))", so only the output matches PID=<digits>.
func ptyPid(t *testing.T, c *testserver.Conn, id string) int {
	t.Helper()
	_ = c.Send(ptyInput(id, "echo PID=$((0+$$))\n"))
	out := ptyOutput(t, c, id, wait, func(s string) bool { return pidRe.MatchString(s) })
	pid, err := strconv.Atoi(pidRe.FindStringSubmatch(out)[1])
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// ptyOutput accumulates pty.data for id until done(output) is true.
func ptyOutput(t *testing.T, c *testserver.Conn, id string, timeout time.Duration, done func(string) bool) string {
	t.Helper()
	var out strings.Builder
	c.Collect(t, timeout, func(f testserver.Frame) bool {
		if f.ID() != id {
			return false
		}
		if f.Type() == "pty.exit" {
			t.Fatalf("pty.exit before expected output; got %q", out.String())
		}
		if f.Type() == "pty.data" {
			b, err := base64.StdEncoding.DecodeString(f.Str("b64"))
			if err != nil {
				t.Fatalf("bad base64: %v", err)
			}
			out.Write(b)
		}
		return done(out.String())
	})
	return out.String()
}
