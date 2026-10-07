package dockerx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/pkg/stdcopy"
)

func TestEgressCrashed(t *testing.T) {
	tests := []struct {
		name  string
		state *types.ContainerState
		want  bool
	}{
		{"running", &types.ContainerState{Running: true}, false},
		{"stopped cleanly", &types.ContainerState{ExitCode: 0}, false},
		{"exited with an error", &types.ContainerState{ExitCode: 1}, true},
		{"restart loop", &types.ContainerState{Restarting: true, ExitCode: 1}, true},
		{"no state", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := egressContainer(testEgressImage, testEgressSecret, false, loopbackIP, "5001")
			c.State = tc.state
			if got := egressCrashed(c); got != tc.want {
				t.Errorf("egressCrashed = %v, want %v", got, tc.want)
			}
		})
	}
}

// A crashed egress container (the image could not write its CA) is replaced
// from a fresh pull, not started again.
func TestEnsureEgressRecreatesCrashedContainer(t *testing.T) {
	f := newEgressFake(t)
	crashed := egressContainer(testEgressImage, testEgressSecret, false, loopbackIP, "5001")
	crashed.State = &types.ContainerState{ExitCode: 1}
	f.inspect = func(id string) (types.ContainerJSON, error) {
		if id == "created-id" {
			return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "5002"), nil
		}
		if f.removed > 0 {
			return types.ContainerJSON{}, notFound()
		}
		return crashed, nil
	}
	pulled := 0
	f.api.imagePull = func(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
		pulled++
		return io.NopCloser(strings.NewReader(`{"status":"Downloaded newer image"}` + "\n")), nil
	}
	d := &dockerClient{api: f.api, refreshEgress: true}

	url, err := d.EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if url != "http://127.0.0.1:5002" {
		t.Errorf("url = %q", url)
	}
	if f.removed != 1 || f.created != 1 || pulled != 1 {
		t.Errorf("removed %d, created %d, pulled %d; want 1, 1, 1", f.removed, f.created, pulled)
	}
	if f.removedVolumes {
		t.Error("the CA volume must survive the recreation")
	}
}

// After `docker pull` of a fixed :latest, the old container is replaced.
func TestEnsureEgressRecreatesOnNewerImage(t *testing.T) {
	f := newEgressFake(t)
	old := egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "5001")
	old.Image = "sha256:old"
	f.inspect = func(id string) (types.ContainerJSON, error) {
		if id == "created-id" {
			return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "5002"), nil
		}
		if f.removed > 0 {
			return types.ContainerJSON{}, notFound()
		}
		return old, nil
	}
	f.api.imageInspect = func(context.Context, string) (types.ImageInspect, []byte, error) {
		return types.ImageInspect{ID: "sha256:new"}, nil, nil
	}
	if _, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret); err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if f.removed != 1 || f.created != 1 {
		t.Errorf("removed %d, created %d; want the stale container replaced", f.removed, f.created)
	}
}

// When the proxy never answers, the error carries its own last log lines,
// not just "connection reset".
func TestEnsureEgressReportsTheProxyLogWhenItDoesNotStart(t *testing.T) {
	f := newEgressFake(t)
	f.inspect = func(id string) (types.ContainerJSON, error) {
		if id == "created-id" {
			return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "5002"), nil
		}
		return types.ContainerJSON{}, notFound()
	}
	f.api.containerLogs = func(_ context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error) {
		if id != "created-id" || opts.Tail != "40" {
			t.Errorf("logs of %s tail %s", id, opts.Tail)
		}
		var buf bytes.Buffer
		w := stdcopy.NewStdWriter(&buf, stdcopy.Stderr)
		_, _ = w.Write([]byte("Error: EACCES: permission denied, open '/var/lib/routini-egress/ca-key.pem'\n"))
		return io.NopCloser(&buf), nil
	}
	d := &dockerClient{api: f.api, egressReady: func(context.Context, string, string) error {
		return errors.New("control API not answering")
	}}
	_, err := d.EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err == nil || !strings.Contains(err.Error(), "EACCES") || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("err = %v, want the proxy's EACCES line", err)
	}
	if strings.Contains(err.Error(), testEgressSecret) {
		t.Error("the error leaks the egress secret")
	}
}

func TestWaitEgressReady(t *testing.T) {
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca" || r.Header.Get("Authorization") != "Bearer "+testEgressSecret {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		if !ready {
			ready = true // answers on the second try, like a proxy still starting
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"pem":"x"}`))
	}))
	defer srv.Close()
	if err := waitEgressReady(context.Background(), srv.URL, testEgressSecret); err != nil {
		t.Fatalf("waitEgressReady: %v", err)
	}

	old := EgressReadyTimeout
	EgressReadyTimeout = 600 * time.Millisecond
	defer func() { EgressReadyTimeout = old }()
	srv.Close()
	start := time.Now()
	if err := waitEgressReady(context.Background(), srv.URL, testEgressSecret); err == nil {
		t.Fatal("want an error from a closed control API")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("waitEgressReady overran its timeout")
	}
}
