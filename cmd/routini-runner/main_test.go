package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/testserver"
	"github.com/nvasion/routini-runner/internal/version"
)

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func runCLI(t *testing.T, getenv map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb syncBuffer
	code := realMain(args, &out, &errb, env(getenv))
	return code, out.String(), errb.String()
}

func assertNoSecrets(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, testserver.Token) || strings.Contains(s, testserver.Credential) {
		t.Errorf("output leaks a secret:\n%s", s)
	}
}

func writeConfig(t *testing.T, url string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	c := config.New()
	c.URL, c.RunnerID, c.Credential = url, testserver.RunnerID, testserver.Credential
	if err := config.Save(path, c); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnrollWritesConfig(t *testing.T) {
	srv := testserver.New(t)
	path := filepath.Join(t.TempDir(), "etc", "routini-runner", "config.json")
	code, _, stderr := runCLI(t, nil, "enroll", "--url", srv.URL+"/", "--token", testserver.Token, "--name", "web-01", "--config", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	assertNoSecrets(t, stderr)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("config mode %o, want 600", st.Mode().Perm())
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o, want 700", dst.Mode().Perm())
	}
	var c map[string]any
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c["credential"] != testserver.Credential || c["runnerId"] != testserver.RunnerID || c["url"] != srv.URL {
		t.Errorf("config = %s", raw)
	}
	if c["caFile"] != nil || c["maxConcurrentExec"] != float64(8) {
		t.Errorf("config = %s", raw)
	}
	req := srv.EnrollRequests()[0]
	if req["name"] != "web-01" || req["token"] != testserver.Token || req["os"] != "linux" {
		t.Errorf("request = %v", req)
	}

	// A second enroll refuses to overwrite the existing config.
	code, _, stderr = runCLI(t, nil, "enroll", "--url", srv.URL, "--token", testserver.Token, "--config", path)
	if code == 0 || !strings.Contains(stderr, "already") {
		t.Errorf("re-enroll: exit %d: %s", code, stderr)
	}
}

func TestEnroll401(t *testing.T) {
	srv := testserver.New(t)
	srv.SetEnrollResponse(http.StatusUnauthorized, map[string]any{"error": "token expired"})
	path := filepath.Join(t.TempDir(), "config.json")
	code, _, stderr := runCLI(t, nil, "enroll", "--url", srv.URL, "--token", testserver.Token, "--config", path)
	if code != 78 {
		t.Errorf("exit %d, want 78", code)
	}
	if !strings.Contains(stderr, "enrollment token rejected") || !strings.Contains(stderr, "token expired") {
		t.Errorf("stderr = %s", stderr)
	}
	assertNoSecrets(t, stderr)
	if _, err := os.Stat(path); err == nil {
		t.Error("config written despite 401")
	}
}

func TestEnrollUsage(t *testing.T) {
	if code, _, _ := runCLI(t, nil, "enroll", "--url", "https://x.example"); code != 2 {
		t.Errorf("missing token: exit %d, want 2", code)
	}
	path := filepath.Join(t.TempDir(), "c.json")
	code, _, stderr := runCLI(t, nil, "enroll", "--url", "http://8.8.8.8", "--token", "rre_x", "--config", path)
	if code != 78 || !strings.Contains(stderr, "https") {
		t.Errorf("public http: exit %d: %s", code, stderr)
	}
}

func TestRunExitCodes(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusUpgradeRequired} {
		srv := testserver.New(t)
		srv.SetConnectStatus(status)
		path := writeConfig(t, srv.URL)
		code, _, stderr := runCLI(t, nil, "run", "--config", path)
		if code != 78 {
			t.Errorf("status %d: exit %d, want 78: %s", status, code, stderr)
		}
		assertNoSecrets(t, stderr)
	}
}

func TestRunRevoked(t *testing.T) {
	srv := testserver.New(t)
	path := writeConfig(t, srv.URL)
	done := make(chan struct{})
	var code int
	var stderr string
	go func() {
		code, _, stderr = runCLI(t, nil, "run", "--config", path)
		close(done)
	}()
	c := srv.NextConn(10 * time.Second)
	c.ExpectType(t, 10*time.Second, "hello", "")
	_ = c.Send(map[string]any{"type": "revoked"})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not exit after revoked")
	}
	if code != 78 || !strings.Contains(stderr, "runner was removed from Routini") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestRunMissingConfig(t *testing.T) {
	code, _, stderr := runCLI(t, nil, "run", "--config", filepath.Join(t.TempDir(), "nope.json"))
	if code != 78 || !strings.Contains(stderr, "enroll") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestUpWithoutEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	code, _, stderr := runCLI(t, nil, "up", "--config", path)
	if code != 78 || !strings.Contains(stderr, "set ROUTINI_RUNNER_URL and ROUTINI_RUNNER_TOKEN") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestUpEnrollsThenRuns(t *testing.T) {
	srv := testserver.New(t)
	path := filepath.Join(t.TempDir(), "home", ".config", "routini-runner", "config.json")
	vars := map[string]string{
		"ROUTINI_RUNNER_URL":    srv.URL,
		"ROUTINI_RUNNER_TOKEN":  testserver.Token,
		"ROUTINI_RUNNER_NAME":   "container-1",
		"ROUTINI_RUNNER_CONFIG": path, // not read: getenv is injected, --config is used
	}
	done := make(chan struct{})
	var code int
	var stderr string
	go func() {
		code, _, stderr = runCLI(t, vars, "up", "--config", path)
		close(done)
	}()
	c := srv.NextConn(10 * time.Second)
	c.ExpectType(t, 10*time.Second, "hello", "")
	if req := srv.EnrollRequests(); len(req) != 1 || req[0]["name"] != "container-1" {
		t.Errorf("enroll requests = %v", req)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config not written: %v", err)
	}
	_ = c.Send(map[string]any{"type": "revoked"})
	<-done
	if code != 78 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	assertNoSecrets(t, stderr)

	// With the config present, up does not enroll again.
	done2 := make(chan int)
	go func() {
		c, _, _ := runCLI(t, vars, "up", "--config", path)
		done2 <- c
	}()
	c = srv.NextConn(10 * time.Second)
	c.ExpectType(t, 10*time.Second, "hello", "")
	if n := len(srv.EnrollRequests()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
	_ = c.Send(map[string]any{"type": "revoked"})
	if code := <-done2; code != 78 {
		t.Errorf("second up: exit %d", code)
	}
}

func TestVersionAndFacts(t *testing.T) {
	code, out, _ := runCLI(t, nil, "version")
	if code != 0 || out != "routini-runner "+version.Version+"\n" {
		t.Errorf("version: %d %q", code, out)
	}
	code, out, _ = runCLI(t, nil, "facts")
	var f map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &f) != nil || f["cpus"] == nil {
		t.Errorf("facts: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, nil, "bogus"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
}
