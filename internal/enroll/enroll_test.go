package enroll_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/enroll"
	"github.com/nvasion/routini-runner/internal/testserver"
	"github.com/nvasion/routini-runner/internal/urlcheck"
)

func doEnroll(t *testing.T, srv *testserver.Server, token string) (*enroll.Response, error) {
	t.Helper()
	base, err := urlcheck.Check(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, _ := config.TLSConfig("")
	client := enroll.NewHTTPClient(base, tlsCfg, nil)
	return enroll.Enroll(context.Background(), client, base, enroll.Request{
		Token: token, Name: "web-01", Hostname: "web-01.prod", OS: "linux", Arch: "amd64", Version: "0.1.0",
	})
}

func TestEnrollSuccess(t *testing.T) {
	srv := testserver.New(t)
	resp, err := doEnroll(t, srv, testserver.Token)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Credential != testserver.Credential || resp.RunnerID != testserver.RunnerID {
		t.Fatalf("unexpected response %+v", resp)
	}
	reqs := srv.EnrollRequests()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests", len(reqs))
	}
	want := map[string]any{"token": testserver.Token, "name": "web-01", "hostname": "web-01.prod", "os": "linux", "arch": "amd64", "version": "0.1.0"}
	for k, v := range want {
		if reqs[0][k] != v {
			t.Errorf("request %s = %v, want %v", k, reqs[0][k], v)
		}
	}
}

func TestEnroll401(t *testing.T) {
	srv := testserver.New(t)
	srv.SetEnrollResponse(http.StatusUnauthorized, map[string]any{"error": "token expired"})
	_, err := doEnroll(t, srv, testserver.Token)
	if !errors.Is(err, enroll.ErrTokenRejected) {
		t.Fatalf("expected ErrTokenRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "token expired") {
		t.Errorf("error should include the server message: %v", err)
	}
	if strings.Contains(err.Error(), testserver.Token) {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestEnroll400AndBadToken(t *testing.T) {
	srv := testserver.New(t)
	srv.SetEnrollResponse(http.StatusBadRequest, map[string]any{"error": "name too long"})
	if _, err := doEnroll(t, srv, testserver.Token); err == nil || !strings.Contains(err.Error(), "name too long") {
		t.Fatalf("expected a 400 error, got %v", err)
	}
	if _, err := doEnroll(t, srv, "abc"); err == nil {
		t.Fatal("expected an error for a token without the rre_ prefix")
	}
}
