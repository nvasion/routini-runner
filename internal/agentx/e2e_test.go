package agentx

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/egressctl"
)

// EnvE2E opts a test run into the end-to-end test below. It needs a reachable
// Docker daemon and pulls a public image, so it is off by default:
//
//	ROUTINI_RUNNER_DOCKER_E2E=1 go test ./internal/agentx/ -run E2E -v
const EnvE2E = "ROUTINI_RUNNER_DOCKER_E2E"

// The e2e images. alpine stands in for the agent image, which only has to
// start, and for the egress image, whose EnsureEgress step the test replaces
// with its own control server (the real egress image is not public).
const (
	e2eImage   = "alpine:3.20"
	e2ePrefix  = "alpine:"
	e2eNetwork = "routini-e2e-sb"
)

// e2eDocker is the real Docker client with the egress container swapped for
// the test's control server, and with the RunSpec recorded so the injected
// environment of step 4 can be asserted on what the daemon really received.
type e2eDocker struct {
	dockerx.Docker
	controlURL string

	mu    sync.Mutex
	specs []dockerx.RunSpec
}

// EnsureEgress hands back the test's control server instead of starting the
// egress container.
func (d *e2eDocker) EnsureEgress(context.Context, string, string) (string, error) {
	return d.controlURL, nil
}

// ConnectNetwork is a no-op: there is no routini-egress container to attach
// to the network in this test.
func (d *e2eDocker) ConnectNetwork(context.Context, string, string, string) error {
	return nil
}

func (d *e2eDocker) RunStreaming(ctx context.Context, spec dockerx.RunSpec, onLine func(stream, line string)) (*int, error) {
	d.mu.Lock()
	d.specs = append(d.specs, spec)
	d.mu.Unlock()
	return d.Docker.RunStreaming(ctx, spec, onLine)
}

func (d *e2eDocker) spec(t *testing.T) dockerx.RunSpec {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.specs) != 1 {
		t.Fatalf("RunStreaming calls = %d, want 1", len(d.specs))
	}
	return d.specs[0]
}

// TestE2EAgainstRealDocker drives a Manager through every step of
// PROTOCOL.md 2.6 against the local Docker daemon: it pulls the image,
// creates the internal network, opens and closes an egress session on the
// control server, and runs a real container to completion.
func TestE2EAgainstRealDocker(t *testing.T) {
	if os.Getenv(EnvE2E) != "1" {
		t.Skipf("set %s=1 to run the Docker end-to-end test", EnvE2E)
	}
	client, err := dockerx.New("")
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	version, err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("docker ping: %v", err)
	}
	t.Logf("docker %s", version)

	rec := &recorder{}
	ctrl := newControlServer(t, rec)
	docker := &e2eDocker{Docker: client, controlURL: ctrl.URL}
	mgr, err := New(Options{
		Docker:        docker,
		Enabled:       true,
		ImagePrefixes: []string{e2ePrefix},
		MaxConcurrent: 1,
		Logger:        testLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := newSink()

	frame := map[string]any{
		"type":       "agent.start",
		"id":         "e2e-1",
		"image":      e2eImage,
		"pull":       "missing",
		"user":       "1000:1000",
		"cpus":       1,
		"memoryMb":   256,
		"pidsLimit":  64,
		"timeoutSec": 120,
		"env":        map[string]any{"ROUTINI_PROMPT": "hello", "ANTHROPIC_API_KEY": "routini-brokered-credential"},
		"labels":     map[string]any{"routini.managed": "true", "routini.run": "e2e"},
		"egress": map[string]any{
			"image":   e2eImage,
			"network": e2eNetwork,
			"session": json.RawMessage(testSession),
		},
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	var msg StartMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}

	mgr.Start(msg, out.send)
	exit := out.onlyExit(t)
	if !mgr.Wait(time.Minute) {
		t.Error("the task did not finish")
	}

	// The image's own entrypoint is what runs, so a clean exit is the
	// container having started under the runner's hardening defaults.
	if exit.ExitCode == nil || *exit.ExitCode != 0 {
		t.Errorf("exitCode = %v, error = %v, want 0", exit.ExitCode, errString(exit.Error))
	}
	if exit.Error != nil || exit.TimedOut || exit.Canceled {
		t.Errorf("exit = %+v, want a clean run", exit)
	}
	want := &EgressStats{Requests: 41, Intercepted: 12, Blocked: []string{"evil.example"}}
	if !reflect.DeepEqual(exit.Egress, want) {
		t.Errorf("egress = %+v, want %+v", exit.Egress, want)
	}
	if got := rec.list(); !reflect.DeepEqual(got, []string{
		"PUT " + egressctl.SessionsPath + testToken,
		"GET " + egressctl.CAPath,
		"DELETE " + egressctl.SessionsPath + testToken,
	}) {
		t.Errorf("control calls = %v", got)
	}

	// The environment the daemon received carries the proxy settings and the
	// CA, and none of the session's real credentials.
	spec := docker.spec(t)
	proxy := "http://routini:" + testToken + "@routini-egress:3128"
	for k, v := range map[string]string{
		"HTTPS_PROXY":               proxy,
		"http_proxy":                proxy,
		"NO_PROXY":                  "",
		"GIT_HTTP_PROXY_AUTHMETHOD": "basic",
		"ROUTINI_CA_PEM":            testPEM,
		"ANTHROPIC_API_KEY":         "routini-brokered-credential",
	} {
		if spec.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, spec.Env[k], v)
		}
	}
	for k, v := range spec.Env {
		if strings.Contains(v, bindingSecret) {
			t.Errorf("env %s carries a binding secret", k)
		}
	}
	if spec.Network != e2eNetwork || spec.Name != ContainerPrefix+"e2e-1" {
		t.Errorf("spec = %+v", spec)
	}
}

// testLogger sends the Manager's log lines to the test log.
func testLogger(t *testing.T) *log.Logger {
	return log.New(testWriter{t}, "agentx: ", 0)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func errString(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
