package conn_test

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/envx"
	"github.com/nvasion/routini-runner/internal/testserver"
)

// envOp builds an env.op frame.
func envOp(id, op string, args map[string]any) map[string]any {
	return map[string]any{"type": "env.op", "id": id, "op": op, "args": args}
}

func TestEnvOpIsRouted(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer}
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.Send(envOp("env-1", "volume.ensure", map[string]any{"name": "routini-env-a"}))
	done := c.ExpectType(t, wait, "env.done", "env-1")
	if ok, _ := done["ok"].(bool); !ok {
		t.Errorf("done = %v, want ok", done)
	}
	if !d.called("EnsureVolume") {
		t.Error("env.op never reached the environment manager")
	}
}

func TestEnvOpRefusedWhenAgentsAreUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config, *conn.Options)
	}{
		{name: "disabled in the config"},
		{
			name:   "docker did not answer at startup",
			mutate: withAgents(&fakeDocker{pingErr: errNoEgress}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t)
			startRunner(t, srv, tc.mutate)
			c, _ := connect(t, srv)

			_ = c.Send(envOp("env-2", "volume.ensure", map[string]any{"name": "routini-env-a"}))
			done := c.ExpectType(t, wait, "env.done", "env-2")
			if ok, _ := done["ok"].(bool); ok {
				t.Errorf("done = %v, want a refusal", done)
			}
			if got := done.Str("error"); got != envx.ErrDisabled {
				t.Errorf("error = %q, want %q", got, envx.ErrDisabled)
			}
		})
	}
}

func TestEnvTTYOpenRefusedWhenAgentsAreUnavailable(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, nil)
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "env.tty.open", "id": "term-1", "containerId": "c1", "cols": 80, "rows": 24})
	errFrame := c.ExpectType(t, wait, "env.tty.error", "term-1")
	if got := errFrame.Str("message"); got != envx.ErrDisabled {
		t.Errorf("message = %q, want %q", got, envx.ErrDisabled)
	}
}

func TestMalformedEnvOpIsAnsweredOnce(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer}
	srv := testserver.New(t)
	h := startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	// "op" has the wrong type, so OpMsg decoding fails even though the
	// generic envelope (type/id only) decodes fine.
	_ = c.SendRaw(`{"type":"env.op","id":"env-3","op":12345,"args":{"session":"top-secret-value"}}`)
	done := c.ExpectType(t, wait, "env.done", "env-3")
	if got := done.Str("error"); got != "invalid env.op message" {
		t.Errorf("error = %q", got)
	}
	if strings.Contains(h.logs.String(), "top-secret-value") {
		t.Errorf("the args reached the log: %s", h.logs.String())
	}
}

func TestEnvironmentsRunningInFacts(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer, countEnv: func() (int, error) { return 2, nil }}
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	_, hello := connect(t, srv)

	f, _ := hello["facts"].(map[string]any)
	dk, _ := f["docker"].(map[string]any)
	if n, _ := dk["environmentsRunning"].(float64); n != 2 {
		t.Errorf("facts.docker.environmentsRunning = %v, want 2", dk["environmentsRunning"])
	}
}

// fakeTTY is a minimal dockerx.TTY for the connection-drop test.
type fakeTTY struct {
	closed chan struct{}
	once   sync.Once
}

func newFakeTTY() *fakeTTY { return &fakeTTY{closed: make(chan struct{})} }

func (f *fakeTTY) Read(p []byte) (int, error) {
	<-f.closed
	return 0, io.EOF
}
func (f *fakeTTY) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTTY) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}
func (f *fakeTTY) Resize(uint, uint) error { return nil }
func (f *fakeTTY) Wait() (*int, error) {
	<-f.closed
	return nil, nil
}

func (f *fakeTTY) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

func TestConnectionDropDisconnectsEnvs(t *testing.T) {
	tty := newFakeTTY()
	d := &fakeDocker{
		pingVersion: dockerVer,
		inspectEnv: func() (dockerx.EnvInfo, error) {
			return dockerx.EnvInfo{Exists: true, Running: true, Managed: true}, nil
		},
		execTTYHook: func(context.Context) (dockerx.TTY, error) { return tty, nil },
	}
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "env.tty.open", "id": "term-1", "containerId": "c1", "cols": 80, "rows": 24})
	c.ExpectType(t, wait, "env.tty.opened", "term-1")

	c.Drop()
	waitUntil(t, tty.isClosed)
}
