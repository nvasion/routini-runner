package conn_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/testserver"
	"github.com/nvasion/routini-runner/internal/updatex"
	"github.com/nvasion/routini-runner/internal/version"
)

// fakeSudo stands in for `sudo -n routini-runner-update ...`.
type fakeSudo struct {
	checkOK bool
	failRun error

	mu    sync.Mutex
	calls []string
}

func (f *fakeSudo) exec(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.mu.Unlock()
	switch last := args[len(args)-1]; {
	case last == "--check" && f.checkOK:
		return []byte("ok\n"), nil
	case last == "--check":
		return []byte("sudo: a password is required"), errors.New("exit status 1")
	case f.failRun != nil:
		return []byte("error: checksum mismatch"), f.failRun
	default:
		return []byte("checksum verified\nrestart of routini-runner scheduled"), nil
	}
}

// withUpdater installs a fake helper file and sudo.
func withUpdater(t *testing.T, s *fakeSudo) func(*config.Config, *conn.Options) {
	helper := filepath.Join(t.TempDir(), "routini-runner-update")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return func(_ *config.Config, opts *conn.Options) {
		opts.UpdateHelper = helper
		opts.UpdateExec = s.exec
	}
}

func TestHelloAdvertisesUpdateOnlyWhenTheHelperAnswers(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testing.T) func(*config.Config, *conn.Options)
		wantCaps []any
	}{
		{"no helper installed", func(*testing.T) func(*config.Config, *conn.Options) { return nil }, []any{"exec", "pty"}},
		{"helper and sudo rule", func(t *testing.T) func(*config.Config, *conn.Options) {
			return withUpdater(t, &fakeSudo{checkOK: true})
		}, []any{"exec", "pty", "update"}},
		{"sudo wants a password", func(t *testing.T) func(*config.Config, *conn.Options) {
			return withUpdater(t, &fakeSudo{checkOK: false})
		}, []any{"exec", "pty"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t)
			startRunner(t, srv, tc.mutate(t))
			_, hello := connect(t, srv)
			if caps, _ := hello["capabilities"].([]any); !reflect.DeepEqual(caps, tc.wantCaps) {
				t.Errorf("capabilities = %v, want %v", hello["capabilities"], tc.wantCaps)
			}
		})
	}
}

func TestRunnerUpdateIsRouted(t *testing.T) {
	s := &fakeSudo{checkOK: true}
	srv := testserver.New(t)
	startRunner(t, srv, withUpdater(t, s))
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "runner.update", "id": "up-1", "version": "v9.9.9"})
	res := c.ExpectType(t, wait, "runner.update.result", "up-1")

	if ok, _ := res["ok"].(bool); !ok || res["error"] != nil {
		t.Fatalf("result = %v, want ok", res)
	}
	if res.Str("version") != "v9.9.9" || !strings.Contains(res.Str("output"), "restart") {
		t.Errorf("result = %v", res)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.calls[len(s.calls)-1]; !strings.HasSuffix(got, "routini-runner-update v9.9.9") || !strings.HasPrefix(got, "-n ") {
		t.Errorf("last sudo call = %q", got)
	}
}

func TestRunnerUpdateRefusals(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*testing.T) func(*config.Config, *conn.Options)
		version string
		want    string
	}{
		{"no update helper", func(*testing.T) func(*config.Config, *conn.Options) { return nil }, "v9.9.9", updatex.ErrDisabled},
		{"not a release tag", func(t *testing.T) func(*config.Config, *conn.Options) {
			return withUpdater(t, &fakeSudo{checkOK: true})
		}, "main", updatex.ErrVersion},
		{"already on it", func(t *testing.T) func(*config.Config, *conn.Options) {
			return withUpdater(t, &fakeSudo{checkOK: true})
		}, "v" + version.Version, "already running v" + version.Version},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t)
			startRunner(t, srv, tc.mutate(t))
			c, _ := connect(t, srv)

			_ = c.Send(map[string]any{"type": "runner.update", "id": "up-2", "version": tc.version})
			res := c.ExpectType(t, wait, "runner.update.result", "up-2")
			if ok, _ := res["ok"].(bool); ok || res.Str("error") != tc.want {
				t.Errorf("result = %v, want error %q", res, tc.want)
			}
		})
	}
}

func TestRunnerUpdateFailureIsReported(t *testing.T) {
	srv := testserver.New(t)
	startRunner(t, srv, withUpdater(t, &fakeSudo{checkOK: true, failRun: errors.New("exit status 1")}))
	c, _ := connect(t, srv)

	_ = c.Send(map[string]any{"type": "runner.update", "id": "up-3", "version": "v9.9.9"})
	res := c.ExpectType(t, wait, "runner.update.result", "up-3")
	if ok, _ := res["ok"].(bool); ok || !strings.Contains(res.Str("error"), "failed") || !strings.Contains(res.Str("output"), "checksum mismatch") {
		t.Errorf("result = %v", res)
	}
}

func TestFactsReportWhyAgentsAreUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config, *conn.Options)
		want   map[string]any
	}{
		{"not configured", nil, map[string]any{"configured": false}},
		{"configured, docker answers", withAgents(&fakeDocker{pingVersion: dockerVer}), map[string]any{"configured": true}},
		{"configured, docker refuses", withAgents(&fakeDocker{pingErr: errors.New("permission denied while trying to connect to the Docker daemon socket")}),
			map[string]any{"configured": true, "error": "permission denied while trying to connect to the Docker daemon socket"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t)
			startRunner(t, srv, tc.mutate)
			_, hello := connect(t, srv)
			f, _ := hello["facts"].(map[string]any)
			if got, _ := f["agents"].(map[string]any); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("facts.agents = %v, want %v", f["agents"], tc.want)
			}
		})
	}
}
