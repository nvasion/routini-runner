package agentx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

// Fixtures shared by the tests. The session body holds a binding secret on
// purpose: several tests assert it never leaves the control API.
const (
	testID          = "task-1"
	testAgentImage  = "ghcr.io/nvasion/routini-agent-claude:0.3.0"
	testEgressImage = "ghcr.io/nvasion/routini-egress:0.3.0"
	testNetwork     = "routini-sb-org1"
	testToken       = "tok_abc123"
	testPEM         = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
	testPrefix      = "ghcr.io/nvasion/"
	bindingSecret   = "sk-real-binding-secret"
	testSession     = `{"token":"` + testToken + `","orgId":"org-1","label":"run 12 step 1",` +
		`"allowedHosts":["api.anthropic.com"],` +
		`"bindings":[{"host":"api.anthropic.com","header":"x-api-key","format":"raw","secret":"` + bindingSecret + `"}],` +
		`"expiresAt":"2026-01-01T00:00:00Z"}`
)

// recorder collects the calls a task makes, Docker and control API alike, in
// one ordered list so the order of PROTOCOL.md 2.6 can be asserted.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *recorder) has(line string) bool {
	for _, l := range r.list() {
		if l == line {
			return true
		}
	}
	return false
}

// fakeDocker is a dockerx.Docker that records its calls. Each hook may be
// replaced to make one step fail or block.
type fakeDocker struct {
	rec *recorder

	ensureImage   func(ref, pull string) error
	ensureEgress  func(ref, secret string) (string, error)
	ensureNetwork func(name string, labels map[string]string) error
	connect       func(network, container, alias string) error
	run           func(ctx context.Context, spec dockerx.RunSpec, onLine func(stream, line string)) (*int, error)
	stop          func(name string, grace time.Duration) error
	kill          func(labels map[string]string) error

	mu       sync.Mutex
	secrets  []string
	networks []map[string]string
	specs    []dockerx.RunSpec
	stopped  []string
	killed   []map[string]string
}

func (f *fakeDocker) Ping(context.Context) (string, error) {
	f.rec.add("Ping")
	return "27.3.1", nil
}

func (f *fakeDocker) EnsureImage(_ context.Context, ref, pull string) error {
	f.rec.add("EnsureImage %s %s", ref, pull)
	if f.ensureImage != nil {
		return f.ensureImage(ref, pull)
	}
	return nil
}

func (f *fakeDocker) EnsureEgress(_ context.Context, ref, secret string) (string, error) {
	// The secret is kept out of the recorded line and asserted separately.
	f.rec.add("EnsureEgress %s", ref)
	f.mu.Lock()
	f.secrets = append(f.secrets, secret)
	f.mu.Unlock()
	if f.ensureEgress != nil {
		return f.ensureEgress(ref, secret)
	}
	return "", nil
}

func (f *fakeDocker) EnsureNetwork(_ context.Context, name string, labels map[string]string) error {
	f.rec.add("EnsureNetwork %s", name)
	f.mu.Lock()
	f.networks = append(f.networks, labels)
	f.mu.Unlock()
	if f.ensureNetwork != nil {
		return f.ensureNetwork(name, labels)
	}
	return nil
}

func (f *fakeDocker) ConnectNetwork(_ context.Context, network, container, alias string) error {
	f.rec.add("ConnectNetwork %s %s %s", network, container, alias)
	if f.connect != nil {
		return f.connect(network, container, alias)
	}
	return nil
}

func (f *fakeDocker) RunStreaming(ctx context.Context, spec dockerx.RunSpec, onLine func(stream, line string)) (*int, error) {
	f.rec.add("RunStreaming %s", spec.Name)
	f.mu.Lock()
	f.specs = append(f.specs, spec)
	f.mu.Unlock()
	if f.run != nil {
		return f.run(ctx, spec, onLine)
	}
	return ptr(0), nil
}

func (f *fakeDocker) Stop(_ context.Context, name string, grace time.Duration) error {
	f.rec.add("Stop %s %s", name, grace)
	f.mu.Lock()
	f.stopped = append(f.stopped, name)
	f.mu.Unlock()
	if f.stop != nil {
		return f.stop(name, grace)
	}
	return nil
}

func (f *fakeDocker) KillByLabels(_ context.Context, labels map[string]string) error {
	f.rec.add("KillByLabels %s", sortedLabels(labels))
	f.mu.Lock()
	f.killed = append(f.killed, labels)
	f.mu.Unlock()
	if f.kill != nil {
		return f.kill(labels)
	}
	return nil
}

func (f *fakeDocker) EnsureVolume(context.Context, string, map[string]string) error {
	f.rec.add("EnsureVolume")
	return nil
}

func (f *fakeDocker) RemoveVolume(context.Context, string) error {
	f.rec.add("RemoveVolume")
	return nil
}

func (f *fakeDocker) StartEnvContainer(context.Context, dockerx.EnvSpec) (string, error) {
	f.rec.add("StartEnvContainer")
	return "", errors.New("no environment container in this test")
}

func (f *fakeDocker) InspectEnv(context.Context, string) (dockerx.EnvInfo, error) {
	f.rec.add("InspectEnv")
	return dockerx.EnvInfo{}, nil
}

func (f *fakeDocker) RemoveEnvContainer(context.Context, string) error {
	f.rec.add("RemoveEnvContainer")
	return nil
}

func (f *fakeDocker) CountEnvContainers(context.Context) (int, error) {
	f.rec.add("CountEnvContainers")
	return 0, nil
}

func (f *fakeDocker) ExecStreaming(context.Context, string, dockerx.ExecSpec, func(string, string)) (*int, error) {
	f.rec.add("ExecStreaming")
	return nil, errors.New("no exec in this test")
}

func (f *fakeDocker) ExecTTY(context.Context, string, uint, uint) (dockerx.TTY, error) {
	f.rec.add("ExecTTY")
	return nil, errors.New("no tty in this test")
}

func (f *fakeDocker) lastSpec(t *testing.T) dockerx.RunSpec {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		t.Fatal("RunStreaming was never called")
	}
	return f.specs[len(f.specs)-1]
}

func (f *fakeDocker) egressSecret(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.secrets) == 0 {
		t.Fatal("EnsureEgress was never called")
	}
	return f.secrets[0]
}

// runs returns how many containers RunStreaming has been entered for.
func (f *fakeDocker) runs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.specs)
}

func (f *fakeDocker) stops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.stopped...)
}

func (f *fakeDocker) kills() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.killed...)
}

func sortedLabels(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	// One or two labels only; a plain sort keeps the output stable.
	for i := 1; i < len(parts); i++ {
		for j := i; j > 0 && parts[j] < parts[j-1]; j-- {
			parts[j], parts[j-1] = parts[j-1], parts[j]
		}
	}
	return strings.Join(parts, ",")
}

// controlServer is a stand-in for the egress container's control API.
type controlServer struct {
	*httptest.Server
	rec *recorder

	mu      sync.Mutex
	auths   []string
	putBody []byte
	stats   EgressStats
	pem     string

	putStatus    int
	caStatus     int
	deleteStatus int
	beforeCA     func()
}

func newControlServer(t *testing.T, rec *recorder) *controlServer {
	t.Helper()
	c := &controlServer{
		rec:          rec,
		pem:          testPEM,
		stats:        EgressStats{Requests: 41, Intercepted: 12, Blocked: []string{"evil.example"}},
		putStatus:    http.StatusOK,
		caStatus:     http.StatusOK,
		deleteStatus: http.StatusOK,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", c.handleCA)
	mux.HandleFunc(sessionsPath, c.handleSession)
	c.Server = httptest.NewServer(mux)
	t.Cleanup(c.Close)
	return c
}

func (c *controlServer) handleCA(w http.ResponseWriter, r *http.Request) {
	c.record(r)
	c.mu.Lock()
	status, pem, hook := c.caStatus, c.pem, c.beforeCA
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if status != http.StatusOK {
		http.Error(w, "boom", status)
		return
	}
	writeJSON(w, map[string]string{"pem": pem})
}

func (c *controlServer) handleSession(w http.ResponseWriter, r *http.Request) {
	c.record(r)
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.putBody = body
		status := c.putStatus
		c.mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, "boom", status)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		c.mu.Lock()
		status, stats := c.deleteStatus, c.stats
		c.mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, "boom", status)
			return
		}
		writeJSON(w, stats)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *controlServer) record(r *http.Request) {
	c.rec.add("%s %s", r.Method, r.URL.Path)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auths = append(c.auths, r.Header.Get("Authorization"))
}

func (c *controlServer) body() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.putBody...)
}

func (c *controlServer) authHeaders() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.auths...)
}

func (c *controlServer) set(f func(*controlServer)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// sink collects the frames a Manager sends.
type sink struct {
	mu     sync.Mutex
	frames []any
	exitCh chan ExitMsg
}

func newSink() *sink {
	return &sink{exitCh: make(chan ExitMsg, 16)}
}

func (s *sink) send(v any) {
	s.mu.Lock()
	s.frames = append(s.frames, v)
	s.mu.Unlock()
	if e, ok := v.(ExitMsg); ok {
		s.exitCh <- e
	}
}

func (s *sink) all() []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]any(nil), s.frames...)
}

func (s *sink) outputs() []OutputMsg {
	var out []OutputMsg
	for _, f := range s.all() {
		if o, ok := f.(OutputMsg); ok {
			out = append(out, o)
		}
	}
	return out
}

func (s *sink) exits() []ExitMsg {
	var out []ExitMsg
	for _, f := range s.all() {
		if e, ok := f.(ExitMsg); ok {
			out = append(out, e)
		}
	}
	return out
}

// waitExit waits for the next agent.exit and fails the test if none arrives.
func (s *sink) waitExit(t *testing.T) ExitMsg {
	t.Helper()
	select {
	case e := <-s.exitCh:
		return e
	case <-time.After(10 * time.Second):
		t.Fatalf("no agent.exit within 10s; frames: %v", s.all())
		return ExitMsg{}
	}
}

// onlyExit waits for the single agent.exit of a task and asserts no second
// one follows.
func (s *sink) onlyExit(t *testing.T) ExitMsg {
	t.Helper()
	e := s.waitExit(t)
	select {
	case extra := <-s.exitCh:
		t.Fatalf("a second agent.exit was sent: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}
	return e
}

// json dump of every frame, used to assert that no secret was ever sent.
func (s *sink) json(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(s.all())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fixture wires a Manager to a fake daemon and a control server.
type fixture struct {
	t    *testing.T
	rec  *recorder
	ctrl *controlServer
	dock *fakeDocker
	mgr  *Manager
	out  *sink
	logs *strings.Builder
}

func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()
	rec := &recorder{}
	ctrl := newControlServer(t, rec)
	dock := &fakeDocker{rec: rec}
	dock.ensureEgress = func(string, string) (string, error) { return ctrl.URL, nil }
	logs := &strings.Builder{}
	opts := Options{
		Docker:        dock,
		Enabled:       true,
		ImagePrefixes: []string{testPrefix},
		MaxConcurrent: 2,
		Runtime:       "runsc",
		Logger:        log.New(logs, "", 0),
	}
	if mutate != nil {
		mutate(&opts)
	}
	mgr, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, rec: rec, ctrl: ctrl, dock: dock, mgr: mgr, out: newSink(), logs: logs}
	t.Cleanup(func() {
		if !mgr.Wait(15 * time.Second) {
			t.Error("agent tasks did not finish within 15s")
		}
	})
	return f
}

// start decodes an agent.start frame the way conn does and runs it.
func (f *fixture) start(frame map[string]any) {
	f.t.Helper()
	f.mgr.Start(f.decode(frame), f.out.send)
}

func (f *fixture) decode(frame map[string]any) StartMsg {
	f.t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		f.t.Fatal(err)
	}
	var msg StartMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		f.t.Fatalf("decode agent.start: %v", err)
	}
	return msg
}

// startFrame is the agent.start frame of PROTOCOL.md 2.6, with overrides
// merged on top.
func startFrame(overrides map[string]any) map[string]any {
	frame := map[string]any{
		"type":       "agent.start",
		"id":         testID,
		"image":      testAgentImage,
		"pull":       "always",
		"user":       "1000:1000",
		"cpus":       2,
		"memoryMb":   4096,
		"pidsLimit":  512,
		"timeoutSec": 1800,
		"env":        map[string]any{"ROUTINI_PROMPT": "do the thing", "ANTHROPIC_API_KEY": "routini-brokered-credential"},
		"labels":     map[string]any{"routini.managed": "true", "routini.run": "run-12", "routini.step": "0"},
		"egress": map[string]any{
			"image":   testEgressImage,
			"network": testNetwork,
			"session": json.RawMessage(testSession),
		},
	}
	for k, v := range overrides {
		frame[k] = v
	}
	return frame
}

// egressOverride returns an egress object with fields replaced.
func egressOverride(overrides map[string]any) map[string]any {
	eg := map[string]any{
		"image":   testEgressImage,
		"network": testNetwork,
		"session": json.RawMessage(testSession),
	}
	for k, v := range overrides {
		eg[k] = v
	}
	return eg
}
