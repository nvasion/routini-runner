package envx

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
	"github.com/nvasion/routini-runner/internal/egressctl"
)

func ptr[T any](v T) *T { return &v }

// recorder collects the Docker calls a test makes, in order.
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

// fakeDocker is a dockerx.Docker that records its calls, with a success
// default for every method and an optional hook to override it.
type fakeDocker struct {
	rec *recorder

	ensureImage        func(ref, pull string) error
	ensureEgress       func(ref, secret string) (string, error)
	ensureNetwork      func(name string, labels map[string]string) error
	connectNetwork     func(network, container, alias string) error
	ensureVolume       func(name string, labels map[string]string) error
	removeVolume       func(name string) error
	inspectVolume      func(name string) (dockerx.VolumeInfo, error)
	startEnvContainer  func(spec dockerx.EnvSpec) (string, error)
	inspectEnv         func(id string) (dockerx.EnvInfo, error)
	removeEnvContainer func(id string) error
	countEnvContainers func() (int, error)
	execStreaming      func(ctx context.Context, id string, spec dockerx.ExecSpec, onLine func(string, string)) (*int, error)
	execTTY            func(ctx context.Context, id string, cols, rows uint) (dockerx.TTY, error)

	mu       sync.Mutex
	envSpecs []dockerx.EnvSpec
}

func (f *fakeDocker) Ping(context.Context) (string, error) { return "27.3.1", nil }

func (f *fakeDocker) EnsureImage(_ context.Context, ref, pull string) error {
	f.rec.add("EnsureImage %s %s", ref, pull)
	if f.ensureImage != nil {
		return f.ensureImage(ref, pull)
	}
	return nil
}

func (f *fakeDocker) EnsureNetwork(_ context.Context, name string, labels map[string]string) error {
	f.rec.add("EnsureNetwork %s", name)
	if f.ensureNetwork != nil {
		return f.ensureNetwork(name, labels)
	}
	return nil
}

func (f *fakeDocker) EnsureEgress(_ context.Context, ref, secret string) (string, error) {
	f.rec.add("EnsureEgress %s", ref)
	if f.ensureEgress != nil {
		return f.ensureEgress(ref, secret)
	}
	return "", nil
}

func (f *fakeDocker) ConnectNetwork(_ context.Context, network, container, alias string) error {
	f.rec.add("ConnectNetwork %s %s %s", network, container, alias)
	if f.connectNetwork != nil {
		return f.connectNetwork(network, container, alias)
	}
	return nil
}

func (f *fakeDocker) RunStreaming(context.Context, dockerx.RunSpec, func(string, string)) (*int, error) {
	f.rec.add("RunStreaming")
	return nil, errors.New("no agent container in this test")
}

func (f *fakeDocker) Stop(context.Context, string, time.Duration) error {
	f.rec.add("Stop")
	return nil
}

func (f *fakeDocker) KillByLabels(context.Context, map[string]string) error {
	f.rec.add("KillByLabels")
	return nil
}

func (f *fakeDocker) EnsureVolume(_ context.Context, name string, labels map[string]string) error {
	f.rec.add("EnsureVolume %s", name)
	if f.ensureVolume != nil {
		return f.ensureVolume(name, labels)
	}
	return nil
}

func (f *fakeDocker) RemoveVolume(_ context.Context, name string) error {
	f.rec.add("RemoveVolume %s", name)
	if f.removeVolume != nil {
		return f.removeVolume(name)
	}
	return nil
}

func (f *fakeDocker) InspectVolume(_ context.Context, name string) (dockerx.VolumeInfo, error) {
	f.rec.add("InspectVolume %s", name)
	if f.inspectVolume != nil {
		return f.inspectVolume(name)
	}
	return dockerx.VolumeInfo{}, nil
}

func (f *fakeDocker) StartEnvContainer(_ context.Context, spec dockerx.EnvSpec) (string, error) {
	f.rec.add("StartEnvContainer %s", spec.Name)
	f.mu.Lock()
	f.envSpecs = append(f.envSpecs, spec)
	f.mu.Unlock()
	if f.startEnvContainer != nil {
		return f.startEnvContainer(spec)
	}
	return "container-id", nil
}

func (f *fakeDocker) InspectEnv(_ context.Context, id string) (dockerx.EnvInfo, error) {
	f.rec.add("InspectEnv %s", id)
	if f.inspectEnv != nil {
		return f.inspectEnv(id)
	}
	return dockerx.EnvInfo{}, nil
}

func (f *fakeDocker) RemoveEnvContainer(_ context.Context, id string) error {
	f.rec.add("RemoveEnvContainer %s", id)
	if f.removeEnvContainer != nil {
		return f.removeEnvContainer(id)
	}
	return nil
}

func (f *fakeDocker) CountEnvContainers(context.Context) (int, error) {
	f.rec.add("CountEnvContainers")
	if f.countEnvContainers != nil {
		return f.countEnvContainers()
	}
	return 0, nil
}

func (f *fakeDocker) ExecStreaming(ctx context.Context, id string, spec dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
	f.rec.add("ExecStreaming %s", id)
	if f.execStreaming != nil {
		return f.execStreaming(ctx, id, spec, onLine)
	}
	return ptr(0), nil
}

func (f *fakeDocker) ExecTTY(ctx context.Context, id string, cols, rows uint) (dockerx.TTY, error) {
	f.rec.add("ExecTTY %s", id)
	if f.execTTY != nil {
		return f.execTTY(ctx, id, cols, rows)
	}
	return nil, errors.New("no tty in this test")
}

func (f *fakeDocker) lastEnvSpec(t *testing.T) dockerx.EnvSpec {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.envSpecs) == 0 {
		t.Fatal("StartEnvContainer was never called")
	}
	return f.envSpecs[len(f.envSpecs)-1]
}

// fakeTTY is a dockerx.TTY backed by channels, standing in for a real
// hijacked exec connection.
type fakeTTY struct {
	out    chan []byte
	closed chan struct{}
	once   sync.Once
	code   *int

	mu      sync.Mutex
	writes  [][]byte
	resizes []resizeCall
}

type resizeCall struct{ cols, rows uint }

func newFakeTTY() *fakeTTY {
	return &fakeTTY{out: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakeTTY) Read(p []byte) (int, error) {
	select {
	case b, ok := <-f.out:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, b)
		return n, nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeTTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	f.mu.Unlock()
	return len(p), nil
}

func (f *fakeTTY) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeTTY) Resize(cols, rows uint) error {
	f.mu.Lock()
	f.resizes = append(f.resizes, resizeCall{cols, rows})
	f.mu.Unlock()
	return nil
}

func (f *fakeTTY) Wait() (*int, error) {
	<-f.closed
	return f.code, nil
}

// send pushes output as if the shell had written it, unless the session has
// already been closed.
func (f *fakeTTY) send(b []byte) {
	select {
	case f.out <- b:
	case <-f.closed:
	}
}

func (f *fakeTTY) writtenData() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.writes...)
}

func (f *fakeTTY) resizeCalls() []resizeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]resizeCall(nil), f.resizes...)
}

// controlServer is a stand-in for the egress container's control API,
// reached through internal/egressctl exactly as the real routini-egress
// container would be.
type controlServer struct {
	*httptest.Server
	rec *recorder

	mu      sync.Mutex
	auths   []string
	putBody []byte
	stats   egressctl.Stats
	pem     string

	putStatus    int
	caStatus     int
	deleteStatus int
}

func newControlServer(t *testing.T, rec *recorder) *controlServer {
	t.Helper()
	c := &controlServer{
		rec:          rec,
		pem:          testPEM,
		stats:        egressctl.Stats{Requests: 7, Intercepted: 2, Blocked: []string{"evil.example"}},
		putStatus:    http.StatusOK,
		caStatus:     http.StatusOK,
		deleteStatus: http.StatusOK,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", c.handleCA)
	mux.HandleFunc(egressctl.SessionsPath, c.handleSession)
	c.Server = httptest.NewServer(mux)
	t.Cleanup(c.Close)
	return c
}

func (c *controlServer) handleCA(w http.ResponseWriter, r *http.Request) {
	c.record(r)
	c.mu.Lock()
	status, pem := c.caStatus, c.pem
	c.mu.Unlock()
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
	if c.rec != nil {
		c.rec.add("%s %s", r.Method, r.URL.Path)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auths = append(c.auths, r.Header.Get("Authorization"))
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
	doneCh chan DoneMsg
}

func newSink() *sink {
	return &sink{doneCh: make(chan DoneMsg, 64)}
}

func (s *sink) send(v any) {
	s.mu.Lock()
	s.frames = append(s.frames, v)
	s.mu.Unlock()
	if d, ok := v.(DoneMsg); ok {
		s.doneCh <- d
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

func (s *sink) dones() []DoneMsg {
	var out []DoneMsg
	for _, f := range s.all() {
		if d, ok := f.(DoneMsg); ok {
			out = append(out, d)
		}
	}
	return out
}

func (s *sink) waitDone(t *testing.T) DoneMsg {
	t.Helper()
	select {
	case d := <-s.doneCh:
		return d
	case <-time.After(10 * time.Second):
		t.Fatalf("no env.done within 10s; frames: %v", s.all())
		return DoneMsg{}
	}
}

// onlyDone waits for the single env.done of an op and asserts no second one
// follows.
func (s *sink) onlyDone(t *testing.T) DoneMsg {
	t.Helper()
	d := s.waitDone(t)
	select {
	case extra := <-s.doneCh:
		t.Fatalf("a second env.done was sent: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}
	return d
}

func (s *sink) json(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(s.all())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	testToken     = "tok_abc123"
	testPEM       = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
	testPrefix    = "ghcr.io/nvasion/"
	testEgressImg = "ghcr.io/nvasion/routini-egress:0.3.0"
	testNetwork   = "routini-sb-org1"
	testSession   = `{"token":"` + testToken + `","orgId":"org-1"}`
)

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
		Docker:          dock,
		Enabled:         true,
		ImagePrefixes:   []string{testPrefix},
		MaxEnvironments: 2,
		Runtime:         "runsc",
		EgressSecret:    "test-secret",
		Logger:          log.New(logs, "", 0),
	}
	if mutate != nil {
		mutate(&opts)
	}
	mgr := New(opts)
	f := &fixture{t: t, rec: rec, ctrl: ctrl, dock: dock, mgr: mgr, out: newSink(), logs: logs}
	t.Cleanup(func() {
		if !mgr.Wait(15 * time.Second) {
			t.Error("env ops did not finish within 15s")
		}
	})
	return f
}

// op decodes an env.op frame the way conn does and runs it.
func (f *fixture) op(frame map[string]any) {
	f.t.Helper()
	f.mgr.Op(f.decode(frame), f.out.send)
}

func (f *fixture) decode(frame map[string]any) OpMsg {
	f.t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		f.t.Fatal(err)
	}
	var msg OpMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		f.t.Fatalf("decode env.op: %v", err)
	}
	return msg
}

// opFrame builds an env.op frame with args merged on top of defaults.
func opFrame(id, op string, args map[string]any) map[string]any {
	raw, _ := json.Marshal(args)
	return map[string]any{
		"type": "env.op",
		"id":   id,
		"op":   op,
		"args": json.RawMessage(raw),
	}
}

// ensureNetworkFirst runs a successful network.ensure so a fixture's
// controlURL is set up for session.open/close tests.
func (f *fixture) ensureNetworkFirst() {
	f.t.Helper()
	f.op(opFrame("net-1", "network.ensure", map[string]any{"network": testNetwork, "egressImage": testEgressImg}))
	d := f.out.onlyDone(f.t)
	if !d.OK {
		f.t.Fatalf("network.ensure failed: %v", errString(d.Error))
	}
}

func errString(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
