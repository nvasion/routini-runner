package conn_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/agentx"
	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/testserver"
)

const (
	agentImage  = "ghcr.io/nvasion/routini-agent-claude:0.3.0"
	egressImage = "ghcr.io/nvasion/routini-egress:0.3.0"
	dockerVer   = "27.3.1"
)

// errNoEgress is what the fake daemon answers when a test only needs to see
// that agent.start reached the agent manager.
var errNoEgress = errors.New("no egress image in this test")

// fakeDocker is a dockerx.Docker for the connection tests. It answers the
// startup ping and records what the agent manager asks of it; EnsureEgress
// optionally blocks, which keeps a task running for cancel tests.
type fakeDocker struct {
	pingVersion string
	pingErr     error
	imageErr    error
	hold        chan struct{} // non-nil: EnsureEgress waits for it

	// Overrides used by the environment tests; nil keeps the stub default.
	inspectEnv  func() (dockerx.EnvInfo, error)
	execStream  func(ctx context.Context, onLine func(string, string)) (*int, error)
	execTTYHook func(ctx context.Context) (dockerx.TTY, error)
	countEnv    func() (int, error)

	mu    sync.Mutex
	calls []string
}

func (f *fakeDocker) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeDocker) called(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

func (f *fakeDocker) Ping(context.Context) (string, error) {
	f.record("Ping")
	if f.pingErr != nil {
		return "", f.pingErr
	}
	return f.pingVersion, nil
}

func (f *fakeDocker) EnsureImage(_ context.Context, ref, _ string) error {
	f.record("EnsureImage " + ref)
	return f.imageErr
}

func (f *fakeDocker) EnsureEgress(ctx context.Context, _, _ string) (string, error) {
	f.record("EnsureEgress")
	if f.hold != nil {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return "", errors.New("no egress container in this test")
}

func (f *fakeDocker) EnsureNetwork(context.Context, string, map[string]string) error {
	f.record("EnsureNetwork")
	return nil
}

func (f *fakeDocker) ConnectNetwork(context.Context, string, string, string) error {
	f.record("ConnectNetwork")
	return nil
}

func (f *fakeDocker) RunStreaming(context.Context, dockerx.RunSpec, func(string, string)) (*int, error) {
	f.record("RunStreaming")
	return nil, errors.New("no container in this test")
}

func (f *fakeDocker) Stop(_ context.Context, name string, _ time.Duration) error {
	f.record("Stop " + name)
	return nil
}

func (f *fakeDocker) KillByLabels(context.Context, map[string]string) error {
	f.record("KillByLabels")
	return nil
}

func (f *fakeDocker) EnsureVolume(context.Context, string, map[string]string) error {
	f.record("EnsureVolume")
	return nil
}

func (f *fakeDocker) RemoveVolume(context.Context, string) error {
	f.record("RemoveVolume")
	return nil
}

func (f *fakeDocker) InspectVolume(context.Context, string) (dockerx.VolumeInfo, error) {
	f.record("InspectVolume")
	return dockerx.VolumeInfo{}, nil
}

func (f *fakeDocker) StartEnvContainer(context.Context, dockerx.EnvSpec) (string, error) {
	f.record("StartEnvContainer")
	return "", errors.New("no environment container in this test")
}

func (f *fakeDocker) InspectEnv(context.Context, string) (dockerx.EnvInfo, error) {
	f.record("InspectEnv")
	if f.inspectEnv != nil {
		return f.inspectEnv()
	}
	return dockerx.EnvInfo{}, nil
}

func (f *fakeDocker) RemoveEnvContainer(context.Context, string) error {
	f.record("RemoveEnvContainer")
	return nil
}

func (f *fakeDocker) CountEnvContainers(context.Context) (int, error) {
	f.record("CountEnvContainers")
	if f.countEnv != nil {
		return f.countEnv()
	}
	return 0, nil
}

func (f *fakeDocker) ExecStreaming(ctx context.Context, _ string, _ dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
	f.record("ExecStreaming")
	if f.execStream != nil {
		return f.execStream(ctx, onLine)
	}
	return nil, errors.New("no exec in this test")
}

func (f *fakeDocker) ExecTTY(ctx context.Context, _ string, _, _ uint) (dockerx.TTY, error) {
	f.record("ExecTTY")
	if f.execTTYHook != nil {
		return f.execTTYHook(ctx)
	}
	return nil, errors.New("no tty in this test")
}

// withAgents enables agents and injects the fake daemon.
func withAgents(d *fakeDocker) func(*config.Config, *conn.Options) {
	return func(cfg *config.Config, opts *conn.Options) {
		cfg.Capabilities.Agents = true
		opts.Docker = d
	}
}

// agentStart builds an agent.start frame.
func agentStart(id string, extra map[string]any) map[string]any {
	m := map[string]any{
		"type":       "agent.start",
		"id":         id,
		"image":      agentImage,
		"pull":       "missing",
		"timeoutSec": 60,
		"labels":     map[string]any{"routini.managed": "true", "routini.run": "run-1"},
		"egress": map[string]any{
			"image":   egressImage,
			"network": "routini-sb-org1",
			"session": map[string]any{"token": "tok_1", "orgId": "org-1", "bindings": []any{}},
		},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestHelloAdvertisesAgentsOnlyWhenDockerAnswers(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*config.Config, *conn.Options)
		wantCaps   []any
		wantDocker bool
	}{
		{
			name:     "agents off in the config",
			mutate:   nil,
			wantCaps: []any{"exec", "pty"},
		},
		{
			name:       "agents on and docker answers",
			mutate:     withAgents(&fakeDocker{pingVersion: dockerVer}),
			wantCaps:   []any{"exec", "pty", "agents", "environments"},
			wantDocker: true,
		},
		{
			name:     "agents on but docker is unreachable",
			mutate:   withAgents(&fakeDocker{pingErr: errors.New("dial unix /var/run/docker.sock: no such file")}),
			wantCaps: []any{"exec", "pty"},
		},
		{
			name: "agents on but the docker client cannot be built",
			mutate: func(cfg *config.Config, opts *conn.Options) {
				cfg.Capabilities.Agents = true
				cfg.DockerHost = "not-a-docker-host"
			},
			wantCaps: []any{"exec", "pty"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The probe must depend on the config alone, not on a
			// DOCKER_HOST the test machine happens to export.
			t.Setenv(dockerx.EnvDockerHost, "")
			srv := testserver.New(t)
			h := startRunner(t, srv, tc.mutate)
			c, hello := connect(t, srv)

			if caps, _ := hello["capabilities"].([]any); !reflect.DeepEqual(caps, tc.wantCaps) {
				t.Errorf("capabilities = %v, want %v", hello["capabilities"], tc.wantCaps)
			}
			f, _ := hello["facts"].(map[string]any)
			docker, ok := f["docker"].(map[string]any)
			if ok != tc.wantDocker {
				t.Fatalf("facts.docker present = %v, want %v (%v)", ok, tc.wantDocker, f["docker"])
			}
			if tc.wantDocker {
				want := map[string]any{
					"available": true, "version": dockerVer,
					"agentsRunning": float64(0), "maxAgents": float64(config.DefaultMaxConcurrentAgents),
					"environmentsRunning": float64(0), "maxEnvironments": float64(config.DefaultMaxEnvironments),
				}
				if !reflect.DeepEqual(docker, want) {
					t.Errorf("facts.docker = %v, want %v", docker, want)
				}
			}
			// Whatever Docker did, exec keeps working.
			_ = c.Send(execStart("still-works", "echo ok", nil))
			r := collectExec(t, c, "still-works", wait)
			if !reflect.DeepEqual(r.stdout, []string{"ok"}) {
				t.Errorf("stdout = %q", r.stdout)
			}
			if !tc.wantDocker && tc.mutate != nil {
				if n := strings.Count(h.logs.String(), "Docker is unavailable"); n != 1 {
					t.Errorf("warnings about Docker = %d, want exactly 1", n)
				}
			}
		})
	}
}

func TestAgentStartIsRouted(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer, imageErr: errNoEgress}
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.Send(agentStart("agent-1", nil))
	exit := c.ExpectType(t, wait, "agent.exit", "agent-1")

	if exit["exitCode"] != nil {
		t.Errorf("exitCode = %v, want null", exit["exitCode"])
	}
	if msg := exit.Str("error"); !strings.Contains(msg, errNoEgress.Error()) {
		t.Errorf("error = %q, want the daemon's failure", msg)
	}
	if !d.called("EnsureImage " + egressImage) {
		t.Error("agent.start never reached the agent manager")
	}
	c.NoFrame(t, 300*time.Millisecond, func(f testserver.Frame) bool {
		return f.Type() == "agent.exit" && f.ID() == "agent-1"
	})
}

func TestAgentCancelIsRouted(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer, hold: make(chan struct{})}
	t.Cleanup(func() { close(d.hold) })
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.Send(agentStart("agent-2", nil))
	waitUntil(t, func() bool { return d.called("EnsureEgress") })
	_ = c.Send(map[string]any{"type": "agent.cancel", "id": "agent-2"})

	exit := c.ExpectType(t, wait, "agent.exit", "agent-2")
	if canceled, _ := exit["canceled"].(bool); !canceled {
		t.Errorf("exit = %v, want canceled", exit)
	}
	if !d.called("Stop " + agentx.ContainerPrefix + "agent-2") {
		t.Error("agent.cancel did not stop the container")
	}
}

func TestAgentStartRefusedWhenAgentsAreUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config, *conn.Options)
	}{
		{name: "disabled in the config"},
		{
			name:   "docker did not answer at startup",
			mutate: withAgents(&fakeDocker{pingErr: errors.New("connection refused")}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t)
			startRunner(t, srv, tc.mutate)
			c, _ := connect(t, srv)

			_ = c.Send(agentStart("agent-3", nil))
			exit := c.ExpectType(t, wait, "agent.exit", "agent-3")
			if got := exit.Str("error"); got != agentx.ErrDisabled {
				t.Errorf("error = %q, want %q", got, agentx.ErrDisabled)
			}
			if exit["exitCode"] != nil || exit["egress"] != nil {
				t.Errorf("exit = %v, want a bare refusal", exit)
			}
		})
	}
}

func TestMalformedAgentStartIsAnsweredOnce(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer}
	srv := testserver.New(t)
	h := startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.SendRaw(`{"type":"agent.start","id":"agent-4","egress":{"session":{"token":42}}}`)
	exit := c.ExpectType(t, wait, "agent.exit", "agent-4")
	if got := exit.Str("error"); got != "invalid agent.start message" {
		t.Errorf("error = %q", got)
	}
	// The frame holds the egress session, so nothing but the id is logged.
	if strings.Contains(h.logs.String(), "token") {
		t.Errorf("the session reached the log: %s", h.logs.String())
	}
}

func TestConnectionDropCancelsAgents(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer, hold: make(chan struct{})}
	t.Cleanup(func() { close(d.hold) })
	srv := testserver.New(t)
	startRunner(t, srv, withAgents(d))
	c, _ := connect(t, srv)

	_ = c.Send(agentStart("agent-5", nil))
	waitUntil(t, func() bool { return d.called("EnsureEgress") })
	c.Drop()

	waitUntil(t, func() bool {
		return d.called("Stop "+agentx.ContainerPrefix+"agent-5") && d.called("KillByLabels")
	})
}

func TestAgentsRunningInPeriodicFacts(t *testing.T) {
	d := &fakeDocker{pingVersion: dockerVer, hold: make(chan struct{})}
	t.Cleanup(func() { close(d.hold) })
	srv := testserver.New(t)
	startRunner(t, srv, func(cfg *config.Config, opts *conn.Options) {
		withAgents(d)(cfg, opts)
		opts.FactsInterval = 50 * time.Millisecond
	})
	c, _ := connect(t, srv)

	_ = c.Send(agentStart("agent-6", nil))
	waitUntil(t, func() bool { return d.called("EnsureEgress") })

	f := c.Expect(t, wait, "facts with one agent running", func(fr testserver.Frame) bool {
		if fr.Type() != "facts" {
			return false
		}
		fx, _ := fr["facts"].(map[string]any)
		dk, _ := fx["docker"].(map[string]any)
		n, _ := dk["agentsRunning"].(float64)
		return n == 1
	})
	if f == nil {
		t.Fatal("no facts frame reported a running agent")
	}
}

// waitUntil polls cond until it holds or the test times out.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition did not hold within %s", wait)
}
