package egressctl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	testToken = "tok_abc123"
	testPEM   = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
	testBody  = `{"orgId":"org-1"}`
)

// controlServer is a stand-in for the egress container's control API.
type controlServer struct {
	*httptest.Server

	mu      sync.Mutex
	auths   []string
	paths   []string
	putBody []byte
	stats   Stats
	pem     string

	putStatus    int
	caStatus     int
	deleteStatus int
}

func newControlServer(t *testing.T) *controlServer {
	t.Helper()
	c := &controlServer{
		pem:          testPEM,
		stats:        Stats{Requests: 41, Intercepted: 12, Blocked: []string{"evil.example"}},
		putStatus:    http.StatusOK,
		caStatus:     http.StatusOK,
		deleteStatus: http.StatusOK,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", c.handleCA)
	mux.HandleFunc(SessionsPath, c.handleSession)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auths = append(c.auths, r.Header.Get("Authorization"))
	c.paths = append(c.paths, r.URL.Path)
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

func TestNewRejectsBadURLs(t *testing.T) {
	tests := []struct {
		name, url, secret, want string
	}{
		{name: "not loopback", url: "http://10.0.0.1:3129", secret: "s", want: "loopback"},
		{name: "a name, not an address", url: "http://localhost:3129", secret: "s", want: "loopback"},
		{name: "wrong scheme", url: "file:///etc/passwd", secret: "s", want: "scheme"},
		{name: "not a URL", url: "http://[::1", secret: "s", want: "not a URL"},
		{name: "no secret", url: "http://127.0.0.1:3129", want: "secret is missing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.url, tc.secret, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
	c, err := New("http://127.0.0.1:3129/", "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.base != "http://127.0.0.1:3129" {
		t.Errorf("base = %q, want the trailing slash removed", c.base)
	}
}

func TestOpenSessionPutsTheBodyWithBearerAuth(t *testing.T) {
	srv := newControlServer(t)
	c, err := New(srv.URL, "my-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.OpenSession(context.Background(), testToken, json.RawMessage(testBody)); err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(srv.putBody, &got); err != nil {
		t.Fatalf("PUT body is not JSON: %v", err)
	}
	_ = json.Unmarshal([]byte(testBody), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PUT body = %v, want %v", got, want)
	}
	auths := srv.authHeaders()
	if len(auths) != 1 || auths[0] != "Bearer my-secret" {
		t.Errorf("Authorization = %v, want a single bearer token", auths)
	}
}

func TestOpenSessionFailureStatus(t *testing.T) {
	srv := newControlServer(t)
	srv.set(func(c *controlServer) { c.putStatus = http.StatusForbidden })
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.OpenSession(context.Background(), testToken, json.RawMessage(testBody))
	if err == nil || !strings.Contains(err.Error(), "open egress session") {
		t.Fatalf("err = %v, want an open egress session error", err)
	}
}

func TestCAReturnsThePem(t *testing.T) {
	srv := newControlServer(t)
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.CA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pem != testPEM {
		t.Errorf("pem = %q, want %q", pem, testPEM)
	}
}

func TestCAFailureStatus(t *testing.T) {
	srv := newControlServer(t)
	srv.set(func(c *controlServer) { c.caStatus = http.StatusInternalServerError })
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CA(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read egress CA") {
		t.Fatalf("err = %v, want a read egress CA error", err)
	}
}

func TestCAEmptyPemIsAnError(t *testing.T) {
	srv := newControlServer(t)
	srv.set(func(c *controlServer) { c.pem = "" })
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CA(context.Background())
	if err == nil || !strings.Contains(err.Error(), "returned no pem") {
		t.Fatalf("err = %v, want a no-pem error", err)
	}
}

func TestCloseSessionReturnsStats(t *testing.T) {
	srv := newControlServer(t)
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := c.CloseSession(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	want := &Stats{Requests: 41, Intercepted: 12, Blocked: []string{"evil.example"}}
	if !reflect.DeepEqual(stats, want) {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if len(srv.paths) == 0 || srv.paths[0] != SessionsPath+testToken {
		t.Errorf("paths = %v, want a call to %s", srv.paths, SessionsPath+testToken)
	}
}

func TestCloseSessionFailureStatus(t *testing.T) {
	srv := newControlServer(t)
	srv.set(func(c *controlServer) { c.deleteStatus = http.StatusInternalServerError })
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CloseSession(context.Background(), testToken)
	if err == nil || !strings.Contains(err.Error(), "close egress session") {
		t.Fatalf("err = %v, want a close egress session error", err)
	}
}

func TestRedactURLDropsTheToken(t *testing.T) {
	srv := newControlServer(t)
	c, err := New(srv.URL, "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // the next call fails with a *url.Error carrying the request URL
	err = c.OpenSession(context.Background(), testToken, json.RawMessage(testBody))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the session token: %q", err)
	}
}
