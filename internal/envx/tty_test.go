package envx

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

// ttyFixture extends fixture with a sink that also exposes TTY frames.
func openTTY(t *testing.T, f *fixture, id string, tty *fakeTTY) {
	t.Helper()
	f.dock.inspectEnv = managedRunning()
	f.dock.execTTY = func(_ context.Context, cid string, cols, rows uint) (dockerx.TTY, error) {
		return tty, nil
	}
	f.mgr.OpenTTY(TTYOpenMsg{ID: id, ContainerID: "c1", Cols: 120, Rows: 32}, f.out.send)
	waitForOpened(t, f, id)
	// Every opened session must end before the fixture's cleanup waits for
	// the Manager's goroutines, or a test that does not itself close the
	// terminal would hang forever on a fake shell that never exits.
	t.Cleanup(func() { _ = tty.Close() })
}

func waitForOpened(t *testing.T, f *fixture, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, fr := range f.out.all() {
			if o, ok := fr.(TTYOpenedMsg); ok && o.ID == id {
				return
			}
			if e, ok := fr.(TTYErrorMsg); ok && e.ID == id {
				t.Fatalf("env.tty.error: %s", e.Message)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no env.tty.opened for %s within 5s", id)
}

func TestOpenTTYSuccess(t *testing.T) {
	f := newFixture(t, nil)
	tty := newFakeTTY()
	openTTY(t, f, "term-1", tty)

	frames := f.out.all()
	if len(frames) != 1 {
		t.Fatalf("frames = %+v, want exactly env.tty.opened", frames)
	}
	if _, ok := frames[0].(TTYOpenedMsg); !ok {
		t.Errorf("frame = %+v, want TTYOpenedMsg", frames[0])
	}
}

func TestOpenTTYDisabled(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Enabled = false })
	f.mgr.OpenTTY(TTYOpenMsg{ID: "term-1", ContainerID: "c1"}, f.out.send)
	frames := f.out.all()
	if len(frames) != 1 {
		t.Fatalf("frames = %+v", frames)
	}
	e, ok := frames[0].(TTYErrorMsg)
	if !ok || e.Message != ErrDisabled {
		t.Errorf("frame = %+v, want ErrDisabled", frames[0])
	}
}

func TestOpenTTYContainerNotManaged(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = func(string) (dockerx.EnvInfo, error) { return dockerx.EnvInfo{}, nil }
	f.mgr.OpenTTY(TTYOpenMsg{ID: "term-1", ContainerID: "c1"}, f.out.send)
	frames := f.out.all()
	if len(frames) != 1 {
		t.Fatalf("frames = %+v", frames)
	}
	e, ok := frames[0].(TTYErrorMsg)
	if !ok || e.Message != ErrContainerMissing {
		t.Errorf("frame = %+v, want %q", frames[0], ErrContainerMissing)
	}
}

func TestOpenTTYTooMany(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	f.dock.execTTY = func(context.Context, string, uint, uint) (dockerx.TTY, error) { return newFakeTTY(), nil }
	for i := 0; i < MaxTTYs; i++ {
		openTTY(t, f, "term-"+string(rune('a'+i)), newFakeTTY())
	}
	f.mgr.OpenTTY(TTYOpenMsg{ID: "term-overflow", ContainerID: "c1"}, f.out.send)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, fr := range f.out.all() {
			if e, ok := fr.(TTYErrorMsg); ok && e.ID == "term-overflow" {
				if e.Message != ErrTooMany {
					t.Fatalf("message = %q, want %q", e.Message, ErrTooMany)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no env.tty.error for the fifth terminal")
}

func TestTTYDataFlowsBothWays(t *testing.T) {
	f := newFixture(t, nil)
	tty := newFakeTTY()
	openTTY(t, f, "term-1", tty)

	tty.send([]byte("hello"))
	deadline := time.Now().Add(2 * time.Second)
	var gotB64 string
	for time.Now().Before(deadline) {
		for _, fr := range f.out.all() {
			if d, ok := fr.(TTYDataMsg); ok && d.ID == "term-1" {
				gotB64 = d.B64
			}
		}
		if gotB64 != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, err := base64.StdEncoding.DecodeString(gotB64)
	if err != nil || string(b) != "hello" {
		t.Fatalf("decoded output = %q, err = %v", b, err)
	}

	f.mgr.TTYInput(TTYInputMsg{ID: "term-1", B64: base64.StdEncoding.EncodeToString([]byte("ls\n"))})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tty.writtenData()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	writes := tty.writtenData()
	if len(writes) != 1 || string(writes[0]) != "ls\n" {
		t.Fatalf("writes = %v, want [ls\\n]", writes)
	}
}

func TestTTYResize(t *testing.T) {
	f := newFixture(t, nil)
	tty := newFakeTTY()
	openTTY(t, f, "term-1", tty)

	f.mgr.TTYResize(TTYResizeMsg{ID: "term-1", Cols: 100, Rows: 40})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tty.resizeCalls()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls := tty.resizeCalls()
	if len(calls) != 1 || calls[0].cols != 100 || calls[0].rows != 40 {
		t.Fatalf("resize calls = %v", calls)
	}
}

func TestTTYCloseSendsExit(t *testing.T) {
	f := newFixture(t, nil)
	tty := newFakeTTY()
	tty.code = ptr(0)
	openTTY(t, f, "term-1", tty)

	f.mgr.TTYClose("term-1")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, fr := range f.out.all() {
			if e, ok := fr.(TTYExitMsg); ok && e.ID == "term-1" {
				if e.ExitCode == nil || *e.ExitCode != 0 {
					t.Fatalf("exitCode = %v, want 0", e.ExitCode)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no env.tty.exit within 5s")
}

func TestDisconnectClosesTerminalsSilently(t *testing.T) {
	f := newFixture(t, nil)
	tty := newFakeTTY()
	openTTY(t, f, "term-1", tty)

	f.mgr.Disconnect()
	if !f.mgr.Wait(5 * time.Second) {
		t.Fatal("Disconnect did not finish the terminal")
	}
	for _, fr := range f.out.all() {
		if _, ok := fr.(TTYExitMsg); ok {
			t.Error("env.tty.exit was sent after Disconnect silenced the session")
		}
	}
}

func TestTTYInputAndResizeOnUnknownIDAreIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.mgr.TTYInput(TTYInputMsg{ID: "nobody", B64: "aGk="})
	f.mgr.TTYResize(TTYResizeMsg{ID: "nobody", Cols: 10, Rows: 10})
	f.mgr.TTYClose("nobody")
	// No panics, no frames.
	if frames := f.out.all(); len(frames) != 0 {
		t.Errorf("frames = %+v, want none", frames)
	}
}
