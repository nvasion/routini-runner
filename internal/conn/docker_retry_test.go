package conn_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/agentx"
	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/testserver"
)

// lateDocker is a daemon that does not answer until up is set, like Docker
// starting after the runner (at boot, or started by hand later).
type lateDocker struct {
	*fakeDocker
	up atomic.Bool
}

func (l *lateDocker) Ping(context.Context) (string, error) {
	if !l.up.Load() {
		return "", errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
	}
	return dockerVer, nil
}

func capsOf(f testserver.Frame) []string {
	raw, _ := f["capabilities"].([]any)
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		s, _ := c.(string)
		out = append(out, s)
	}
	return out
}

func TestAgentsTurnOnWhenDockerAnswersLater(t *testing.T) {
	d := &lateDocker{fakeDocker: &fakeDocker{imageErr: errNoEgress}}
	srv := testserver.New(t)
	h := startRunner(t, srv, func(cfg *config.Config, opts *conn.Options) {
		cfg.Capabilities.Agents = true
		opts.Docker = d
		opts.DockerRetry = 20 * time.Millisecond
	})
	c, hello := connect(t, srv)

	// Docker is down at startup: no agents, and the facts say why.
	if caps := capsOf(hello); slices.Contains(caps, "agents") || slices.Contains(caps, "environments") {
		t.Fatalf("hello capabilities = %v, want no agents yet", caps)
	}
	f, _ := hello["facts"].(map[string]any)
	agents, _ := f["agents"].(map[string]any)
	if msg, _ := agents["error"].(string); !strings.Contains(msg, "Is the docker daemon running") {
		t.Errorf("facts.agents = %v, want the startup error", f["agents"])
	}
	_ = c.Send(agentStart("before", nil))
	if got := c.ExpectType(t, wait, "agent.exit", "before").Str("error"); got != agentx.ErrDisabled {
		t.Fatalf("agent.start before Docker answered: error %q, want %q", got, agentx.ErrDisabled)
	}

	// Docker comes up: the runner tells the server without reconnecting.
	d.up.Store(true)
	caps := capsOf(c.ExpectType(t, wait, "capabilities", ""))
	if !slices.Contains(caps, "agents") || !slices.Contains(caps, "environments") || !slices.Contains(caps, "exec") {
		t.Fatalf("capabilities = %v, want exec, agents and environments", caps)
	}
	facts := c.Expect(t, wait, "facts with docker", func(fr testserver.Frame) bool {
		fx, _ := fr["facts"].(map[string]any)
		dk, _ := fx["docker"].(map[string]any)
		return fr.Type() == "facts" && dk["version"] == dockerVer
	})
	if fx, _ := facts["facts"].(map[string]any); fx["agents"].(map[string]any)["error"] != nil {
		t.Errorf("facts.agents still carries an error: %v", fx["agents"])
	}

	// And agent.start now reaches the agent manager instead of the refusal.
	_ = c.Send(agentStart("after", nil))
	if got := c.ExpectType(t, wait, "agent.exit", "after").Str("error"); !strings.Contains(got, errNoEgress.Error()) {
		t.Fatalf("agent.start after Docker answered: error %q, want the daemon's", got)
	}
	if n := strings.Count(h.logs.String(), "Docker answered: agents enabled"); n != 1 {
		t.Errorf("log lines about Docker answering = %d, want 1:\n%s", n, h.logs.String())
	}
}

func TestNoDockerRetryWhenAgentsAreOff(t *testing.T) {
	d := &lateDocker{fakeDocker: &fakeDocker{}}
	d.up.Store(true)
	srv := testserver.New(t)
	startRunner(t, srv, func(_ *config.Config, opts *conn.Options) {
		opts.Docker = d
		opts.DockerRetry = 10 * time.Millisecond
	})
	c, _ := connect(t, srv)
	c.NoFrame(t, 200*time.Millisecond, func(f testserver.Frame) bool { return f.Type() == "capabilities" })
	if d.called("Ping") {
		t.Error("Docker was pinged although agents are off in the config")
	}
}
