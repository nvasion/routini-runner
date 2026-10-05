package conn_test

import (
	"errors"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/testserver"
	"github.com/nvasion/routini-runner/internal/version"
)

func TestHelloHandshake(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, hello := connect(t, srv)

	if got := c.Header.Get("Authorization"); got != "Bearer "+testserver.Credential {
		t.Errorf("Authorization = %q", got)
	}
	if got := c.Header.Get("Routini-Runner-Protocol"); got != "1" {
		t.Errorf("Routini-Runner-Protocol = %q", got)
	}
	if p, _ := hello["protocol"].(float64); p != 1 {
		t.Errorf("protocol = %v", hello["protocol"])
	}
	if hello.Str("version") != version.Version {
		t.Errorf("version = %q", hello.Str("version"))
	}
	if hello.Str("hostname") != "test-host" || hello.Str("os") != "linux" || hello.Str("arch") != runtime.GOARCH {
		t.Errorf("hostname/os/arch = %q/%q/%q", hello.Str("hostname"), hello.Str("os"), hello.Str("arch"))
	}
	if caps, _ := hello["capabilities"].([]any); !reflect.DeepEqual(caps, []any{"exec", "pty"}) {
		t.Errorf("capabilities = %v", hello["capabilities"])
	}
	f, ok := hello["facts"].(map[string]any)
	if !ok {
		t.Fatalf("facts missing: %v", hello)
	}
	if _, ok := f["cpus"]; !ok {
		t.Errorf("facts.cpus missing: %v", f)
	}
	// hello is the first frame on the connection.
	if rec := c.Recorded(); rec[0].Type() != "hello" {
		t.Errorf("first frame is %q", rec[0].Type())
	}
}

func TestWaitsForWelcome(t *testing.T) {
	srv := testserver.New(t)
	srv.SetAutoWelcome(false)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	if err := c.Send(execStart("early", "echo early", nil)); err != nil {
		t.Fatal(err)
	}
	_ = c.Send(map[string]any{"type": "pty.open", "id": "early-pty", "cols": 80, "rows": 24})
	c.NoFrame(t, 400*time.Millisecond, func(f testserver.Frame) bool { return true })

	_ = c.Send(map[string]any{"type": "welcome", "runnerId": testserver.RunnerID, "name": testserver.RunnerName})
	_ = c.Send(execStart("after", "echo after", nil))
	r := collectExec(t, c, "after", wait)
	if !reflect.DeepEqual(r.stdout, []string{"after"}) {
		t.Fatalf("stdout = %q", r.stdout)
	}
	for _, f := range c.Recorded() {
		if f.ID() == "early" || f.ID() == "early-pty" {
			t.Fatalf("runner acted on a frame sent before welcome: %v", f)
		}
	}
}

func TestExecOutputAndExit(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	cmd := `printf 'a\nb\n'; echo e1 >&2; echo c; echo e2 >&2; printf 'd\r\n'; printf tail; exit 3`
	_ = c.Send(execStart("t1", cmd, nil))
	r := collectExec(t, c, "t1", wait)
	if !reflect.DeepEqual(r.stdout, []string{"a", "b", "c", "d", "tail"}) {
		t.Errorf("stdout = %q", r.stdout)
	}
	if !reflect.DeepEqual(r.stderr, []string{"e1", "e2"}) {
		t.Errorf("stderr = %q", r.stderr)
	}
	if code, ok := exitCode(r.exit); !ok || code != 3 {
		t.Errorf("exitCode = %v", r.exit["exitCode"])
	}
	if r.exit["timedOut"] != false || r.exit["canceled"] != false || r.exit["error"] != nil {
		t.Errorf("exit = %v", r.exit)
	}
	for _, k := range []string{"exitCode", "timedOut", "canceled", "error"} {
		if _, ok := r.exit[k]; !ok {
			t.Errorf("exec.exit lacks field %q", k)
		}
	}
	// Nothing for t1 after its exit.
	c.NoFrame(t, 200*time.Millisecond, func(f testserver.Frame) bool { return f.ID() == "t1" })
}

func TestExecStreamsLinesAsTheyArrive(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	_ = c.Send(execStart("s1", "echo first; sleep 2; echo second", nil))
	start := time.Now()
	f := c.ExpectType(t, wait, "exec.output", "s1")
	if f.Str("data") != "first" {
		t.Fatalf("data = %q", f.Str("data"))
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("first line was not streamed before the command ended")
	}
	collectExec(t, c, "s1", wait)
}

func TestExecEnvAndCwd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ROUTINI_TEST_BASE", "base")
	t.Setenv("ROUTINI_TEST_OVER", "old")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(execStart("e1", `echo "$FOO|$ROUTINI_TEST_BASE|$ROUTINI_TEST_OVER"; pwd`, map[string]any{
		"env": map[string]string{"FOO": "bar", "ROUTINI_TEST_OVER": "new"},
	}))
	r := collectExec(t, c, "e1", wait)
	if !reflect.DeepEqual(r.stdout, []string{"bar|base|new", home}) {
		t.Errorf("stdout = %q (want env merge and cwd %s)", r.stdout, home)
	}

	dir := t.TempDir()
	_ = c.Send(execStart("e2", "pwd", map[string]any{"cwd": dir, "timeoutSec": 0}))
	r = collectExec(t, c, "e2", wait)
	if !reflect.DeepEqual(r.stdout, []string{dir}) {
		t.Errorf("stdout = %q, want %s", r.stdout, dir)
	}

	// stdin is /dev/null: cat ends immediately.
	_ = c.Send(execStart("e3", "cat; echo done", nil))
	r = collectExec(t, c, "e3", wait)
	if !reflect.DeepEqual(r.stdout, []string{"done"}) {
		t.Errorf("stdout = %q", r.stdout)
	}

	// A spawn failure is reported as an error with a null exit code.
	_ = c.Send(execStart("e4", "true", map[string]any{"cwd": "/does/not/exist"}))
	r = collectExec(t, c, "e4", wait)
	if r.exit["exitCode"] != nil || r.exit.Str("error") == "" {
		t.Errorf("exit = %v", r.exit)
	}
}

func TestExecInvalidEnvKey(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	_ = c.Send(execStart("bad", "echo should-not-run", map[string]any{"env": map[string]string{"OK": "1", "BAD-KEY": "x"}}))
	r := collectExec(t, c, "bad", wait)
	if r.exit.Str("error") != "invalid env key" || r.exit["exitCode"] != nil || len(r.stdout) != 0 {
		t.Fatalf("exit = %v, stdout = %q", r.exit, r.stdout)
	}
}

func TestExecTimeoutKillsProcessGroup(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(execStart("to", `sleep 30 & echo $!; echo $$; sleep 31`, map[string]any{"timeoutSec": 1}))
	start := time.Now()
	r := collectExec(t, c, "to", wait)
	if r.exit["timedOut"] != true || r.exit["canceled"] != false || r.exit["exitCode"] != nil {
		t.Fatalf("exit = %v", r.exit)
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 5*time.Second {
		t.Errorf("timeout took %s", el)
	}
	if len(r.stdout) != 2 {
		t.Fatalf("stdout = %q", r.stdout)
	}
	for _, s := range r.stdout {
		pid, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		waitDead(t, pid, 3*time.Second)
	}
}

func TestExecCancel(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(execStart("c1", "echo started; sleep 30", nil))
	f := c.ExpectType(t, wait, "exec.output", "c1")
	if f.Str("data") != "started" {
		t.Fatalf("data = %q", f.Str("data"))
	}
	_ = c.Send(map[string]any{"type": "exec.cancel", "id": "c1"})
	_ = c.Send(map[string]any{"type": "exec.cancel", "id": "unknown"}) // ignored
	r := collectExec(t, c, "c1", wait)
	if r.exit["canceled"] != true || r.exit["timedOut"] != false || r.exit["exitCode"] != nil {
		t.Fatalf("exit = %v", r.exit)
	}
}

func TestExecCancelEscalatesToSIGKILL(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil) // KillGrace is 1s in tests
	c, _ := connect(t, srv)

	_ = c.Send(execStart("k1", `trap '' TERM; echo ready; while :; do sleep 0.1; done`, nil))
	c.ExpectType(t, wait, "exec.output", "k1")
	start := time.Now()
	_ = c.Send(map[string]any{"type": "exec.cancel", "id": "k1"})
	r := collectExec(t, c, "k1", wait)
	if r.exit["canceled"] != true {
		t.Fatalf("exit = %v", r.exit)
	}
	if el := time.Since(start); el < 800*time.Millisecond {
		t.Errorf("SIGKILL came after %s, before the grace period", el)
	}
}

func TestExecBusy(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, func(c *config.Config, _ *conn.Options) { c.MaxConcurrentExec = 2 })
	c, _ := connect(t, srv)

	_ = c.Send(execStart("b1", "echo up; sleep 30", nil))
	_ = c.Send(execStart("b2", "echo up; sleep 30", nil))
	_ = c.Send(execStart("b3", "echo never", nil))
	r := collectExec(t, c, "b3", wait)
	if r.exit.Str("error") != "runner busy (2 commands running)" || r.exit["exitCode"] != nil {
		t.Fatalf("exit = %v", r.exit)
	}
	_ = c.Send(map[string]any{"type": "exec.cancel", "id": "b1"})
	collectExec(t, c, "b1", wait)
	// A slot is free again.
	_ = c.Send(execStart("b4", "echo ok", nil))
	r = collectExec(t, c, "b4", wait)
	if !reflect.DeepEqual(r.stdout, []string{"ok"}) {
		t.Fatalf("stdout = %q, exit = %v", r.stdout, r.exit)
	}
}

func TestExecDisabled(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, func(c *config.Config, _ *conn.Options) { c.Capabilities.Exec = false })
	c, hello := connect(t, srv)
	if caps, _ := hello["capabilities"].([]any); !reflect.DeepEqual(caps, []any{"pty"}) {
		t.Errorf("capabilities = %v", hello["capabilities"])
	}
	_ = c.Send(execStart("d1", "echo nope", nil))
	r := collectExec(t, c, "d1", wait)
	if r.exit.Str("error") != "exec is disabled on this runner" || r.exit["exitCode"] != nil || len(r.stdout) != 0 {
		t.Fatalf("exit = %v", r.exit)
	}
}

func TestConnectionDropKillsExec(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(execStart("drop", "sleep 30 & echo $!; echo $$; sleep 31", nil))
	f1 := c.ExpectType(t, wait, "exec.output", "drop")
	f2 := c.ExpectType(t, wait, "exec.output", "drop")
	c.Drop()

	for _, s := range []string{f1.Str("data"), f2.Str("data")} {
		pid, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		waitDead(t, pid, 3*time.Second)
	}
	// The runner reconnects and never reports the killed command.
	c2, _ := connect(t, srv)
	c2.NoFrame(t, 1500*time.Millisecond, func(f testserver.Frame) bool { return f.ID() == "drop" })
}

func TestPtyEchoAndExit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "pty.open", "id": "p1", "cols": 120, "rows": 32})
	c.ExpectType(t, wait, "pty.opened", "p1")
	// The shell echoes the typed input ("echo h''i"), so only the command's
	// output contains "hi".
	_ = c.Send(ptyInput("p1", "echo h''i; echo \"$TERM $LANG\"\n"))
	out := ptyOutput(t, c, "p1", wait, func(s string) bool { return strings.Contains(s, "xterm-256color C.UTF-8") })
	if !strings.Contains(out, "hi\r\n") {
		t.Errorf("output lacks hi: %q", out)
	}
	_ = c.Send(ptyInput("p1", "exit 7\n"))
	f := c.ExpectType(t, wait, "pty.exit", "p1")
	if code, ok := exitCode(f); !ok || code != 7 {
		t.Errorf("pty.exit = %v", f)
	}
	// Frames for an ended session are ignored, and nothing follows pty.exit.
	_ = c.Send(ptyInput("p1", "echo again\n"))
	_ = c.Send(map[string]any{"type": "pty.resize", "id": "p1", "cols": 10, "rows": 10})
	_ = c.Send(map[string]any{"type": "pty.close", "id": "p1"})
	c.NoFrame(t, 300*time.Millisecond, func(f testserver.Frame) bool { return f.ID() == "p1" })
}

func TestPtyResize(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "pty.open", "id": "r1", "cols": 80, "rows": 24})
	c.ExpectType(t, wait, "pty.opened", "r1")
	_ = c.Send(ptyInput("r1", "stty size\n"))
	ptyOutput(t, c, "r1", wait, func(s string) bool { return strings.Contains(s, "24 80") })
	_ = c.Send(map[string]any{"type": "pty.resize", "id": "r1", "cols": 100, "rows": 30})
	_ = c.Send(ptyInput("r1", "stty size\n"))
	ptyOutput(t, c, "r1", wait, func(s string) bool { return strings.Contains(s, "30 100") })
}

func TestPtyClose(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "pty.open", "id": "x1", "cols": 80, "rows": 24})
	c.ExpectType(t, wait, "pty.opened", "x1")
	pid := ptyPid(t, c, "x1")
	_ = c.Send(map[string]any{"type": "pty.close", "id": "x1"})
	c.ExpectType(t, wait, "pty.exit", "x1")
	waitDead(t, pid, 3*time.Second)
}

func TestPtyMaxAndDisabled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	for i := 1; i <= 4; i++ {
		id := "m" + strconv.Itoa(i)
		_ = c.Send(map[string]any{"type": "pty.open", "id": id, "cols": 80, "rows": 24})
		c.ExpectType(t, wait, "pty.opened", id)
	}
	_ = c.Send(map[string]any{"type": "pty.open", "id": "m5", "cols": 80, "rows": 24})
	f := c.ExpectType(t, wait, "pty.error", "m5")
	if f.Str("message") != "too many terminals" {
		t.Fatalf("pty.error = %v", f)
	}
	// Closing one frees a slot.
	_ = c.Send(map[string]any{"type": "pty.close", "id": "m1"})
	c.ExpectType(t, wait, "pty.exit", "m1")
	_ = c.Send(map[string]any{"type": "pty.open", "id": "m6", "cols": 80, "rows": 24})
	c.ExpectType(t, wait, "pty.opened", "m6")

	srv2 := testserver.New(t)
	startRunner(t, srv2, func(c *config.Config, _ *conn.Options) { c.Capabilities.Pty = false })
	c2, hello := connect(t, srv2)
	if caps, _ := hello["capabilities"].([]any); !reflect.DeepEqual(caps, []any{"exec"}) {
		t.Errorf("capabilities = %v", hello["capabilities"])
	}
	_ = c2.Send(map[string]any{"type": "pty.open", "id": "d1", "cols": 80, "rows": 24})
	f = c2.ExpectType(t, wait, "pty.error", "d1")
	if f.Str("message") != "terminals are disabled on this runner" {
		t.Fatalf("pty.error = %v", f)
	}
}

func TestConnectionDropClosesPty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	_ = c.Send(map[string]any{"type": "pty.open", "id": "q1", "cols": 80, "rows": 24})
	c.ExpectType(t, wait, "pty.opened", "q1")
	pid := ptyPid(t, c, "q1")
	c.Drop()
	waitDead(t, pid, 4*time.Second)
	c2, _ := connect(t, srv)
	c2.NoFrame(t, 500*time.Millisecond, func(f testserver.Frame) bool { return f.ID() == "q1" })
}

func TestConnect401And426AreFatal(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{{http.StatusUnauthorized, conn.ErrUnauthorized}, {http.StatusUpgradeRequired, conn.ErrUnsupportedProtocol}} {
		srv := testserver.New(t)
		srv.SetConnectStatus(tc.status)
		h := startRunner(t, srv, nil)
		err := h.wait(t, wait)
		if !conn.IsFatal(err) || !errors.Is(err, tc.want) {
			t.Errorf("status %d: Run returned %v", tc.status, err)
		}
	}
}

func TestOtherConnectErrorsRetry(t *testing.T) {
	srv := testserver.New(t)
	srv.SetConnectStatus(http.StatusServiceUnavailable)
	h := startRunner(t, srv, nil)
	time.Sleep(300 * time.Millisecond)
	select {
	case <-h.done:
		t.Fatalf("Run returned on 503: %v", h.err)
	default:
	}
	srv.SetConnectStatus(0)
	connect(t, srv)
	if !strings.Contains(h.logs.String(), "503") {
		t.Errorf("logs do not mention the 503")
	}
}

func TestRevokedIsFatal(t *testing.T) {
	srv := testserver.New(t)
	h := startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	_ = c.Send(map[string]any{"type": "revoked"})
	err := h.wait(t, wait)
	if !conn.IsFatal(err) || !errors.Is(err, conn.ErrRevoked) {
		t.Fatalf("Run returned %v", err)
	}
	if err.Error() != "runner was removed from Routini" {
		t.Errorf("message = %q", err.Error())
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	c.Drop()
	c2, hello := connect(t, srv)
	if hello.Type() != "hello" || c2 == c {
		t.Fatal("expected a fresh connection with hello")
	}
	// The new connection works.
	_ = c2.Send(execStart("after-reconnect", "echo ok", nil))
	r := collectExec(t, c2, "after-reconnect", wait)
	if !reflect.DeepEqual(r.stdout, []string{"ok"}) {
		t.Fatalf("stdout = %q", r.stdout)
	}
}

func TestReplacedWaitsBackoff(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, func(_ *config.Config, o *conn.Options) {
		o.Backoff = conn.Backoff{Initial: 400 * time.Millisecond, Max: time.Second, ResetAfter: time.Minute}
	})
	c, _ := connect(t, srv)
	start := time.Now()
	c.CloseWith(4000, "replaced")
	connect(t, srv)
	if el := time.Since(start); el < 350*time.Millisecond {
		t.Fatalf("reconnected after %s, before a full backoff interval", el)
	}
}

func TestMalformedFramesIgnored(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	for _, raw := range []string{
		`not json`,
		`[1,2,3]`,
		`{"no":"type"}`,
		`{"type":42}`,
		`{"type":"something.new","id":"x"}`,
		`{"type":"exec.cancel"}`,
		`{"type":"pty.input","id":"nope","b64":"!!!"}`,
	} {
		if err := c.SendRaw(raw); err != nil {
			t.Fatal(err)
		}
	}
	// A typed-wrong exec.start with an id is answered with an error exit.
	_ = c.SendRaw(`{"type":"exec.start","id":"typed","command":"echo x","env":{"A":5}}`)
	r := collectExec(t, c, "typed", wait)
	if r.exit.Str("error") == "" || r.exit["exitCode"] != nil {
		t.Errorf("exit = %v", r.exit)
	}
	// The connection is still up and working.
	_ = c.Send(execStart("ok", "echo fine", nil))
	r = collectExec(t, c, "ok", wait)
	if !reflect.DeepEqual(r.stdout, []string{"fine"}) {
		t.Fatalf("stdout = %q", r.stdout)
	}
	if n := srv.ConnCount(); n != 1 {
		t.Errorf("connections = %d, want 1", n)
	}
}

func TestPingPongAndReadTimeout(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, func(_ *config.Config, o *conn.Options) { o.ReadTimeout = 600 * time.Millisecond })
	c, _ := connect(t, srv)

	// Pings are answered and keep the connection alive past ReadTimeout.
	for i := 0; i < 8; i++ {
		if err := c.Ping("p" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
		if p, ok := c.WaitPong(2 * time.Second); !ok || p != "p"+strconv.Itoa(i) {
			t.Fatalf("pong %d = %q, %v", i, p, ok)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n := srv.ConnCount(); n != 1 {
		t.Fatalf("connections = %d during pings, want 1", n)
	}
	// Silence for longer than ReadTimeout: the runner gives up and redials.
	connect(t, srv)
	<-c.Done()
}

func TestPeriodicFacts(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, func(_ *config.Config, o *conn.Options) { o.FactsInterval = 100 * time.Millisecond })
	c, _ := connect(t, srv)
	f := c.ExpectType(t, wait, "facts", "")
	if _, ok := f["facts"].(map[string]any); !ok {
		t.Fatalf("facts frame = %v", f)
	}
}

func TestGracefulShutdown(t *testing.T) {
	srv := testserver.New(t)
	h := startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	_ = c.Send(execStart("g1", "echo $$; sleep 30", nil))
	f := c.ExpectType(t, wait, "exec.output", "g1")
	pid, _ := strconv.Atoi(f.Str("data"))

	h.cancel()
	r := collectExec(t, c, "g1", wait)
	if r.exit["canceled"] != true {
		t.Errorf("exit = %v", r.exit)
	}
	if err := h.wait(t, wait); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	<-c.Done()
	var ce *websocket.CloseError
	if !errors.As(c.CloseErr(), &ce) || ce.Code != websocket.CloseNormalClosure {
		t.Errorf("close = %v, want 1000", c.CloseErr())
	}
	waitDead(t, pid, 3*time.Second)
}

func TestPlainHTTPToPublicAddressIsFatal(t *testing.T) {
	srv := testserver.New(t)
	h := startRunner(t, srv, func(c *config.Config, _ *conn.Options) { c.URL = "http://8.8.8.8:3001" })
	err := h.wait(t, wait)
	if !conn.IsFatal(err) || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Run returned %v", err)
	}
}

func TestCredentialNeverLogged(t *testing.T) {
	srv := testserver.New(t)
	h := startRunner(t, srv, nil)
	c, _ := connect(t, srv)
	c.Drop()
	connect(t, srv)
	if strings.Contains(h.logs.String(), testserver.Credential) {
		t.Fatal("the credential appears in the logs")
	}
}
