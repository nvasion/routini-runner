package dockerx

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestE2EEnsureEgressAgainstRealDocker runs the real routini-egress image the
// way agents and environments do. Opt in with
//
//	ROUTINI_RUNNER_DOCKER_E2E=1 ROUTINI_E2E_EGRESS_IMAGE=ghcr.io/nvasion/routini-egress:latest \
//	  go test ./internal/dockerx/ -run E2EEnsureEgress -v
//
// ROUTINI_E2E_EGRESS_EXPECT_FAIL=<text> instead asserts that a broken image
// fails with <text> in the error (the proxy's own log line).
func TestE2EEnsureEgressAgainstRealDocker(t *testing.T) {
	ref := os.Getenv("ROUTINI_E2E_EGRESS_IMAGE")
	if os.Getenv("ROUTINI_RUNNER_DOCKER_E2E") != "1" || ref == "" {
		t.Skip("set ROUTINI_RUNNER_DOCKER_E2E=1 and ROUTINI_E2E_EGRESS_IMAGE to run")
	}
	d, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	dc := d.(*dockerClient)
	if !strings.Contains(ref, "/") {
		dc.refreshEgress = false // a local build cannot be pulled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cleanup := func() {
		_ = dc.removeEgressContainer(context.Background())
		_ = dc.api.VolumeRemove(context.Background(), EgressCAVolume, true)
	}
	cleanup()
	t.Cleanup(cleanup)

	url, err := dc.EnsureEgress(ctx, ref, "e2e-secret-0123456789abcdef")
	if want := os.Getenv("ROUTINI_E2E_EGRESS_EXPECT_FAIL"); want != "" {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want it to mention %q", err, want)
		}
		t.Logf("broken image reported: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	t.Logf("egress ready at %s", url)
	// Reuse: a second call keeps the healthy container.
	if url2, err := dc.EnsureEgress(ctx, ref, "e2e-secret-0123456789abcdef"); err != nil || url2 != url {
		t.Fatalf("second EnsureEgress = %q, %v; want the same %q", url2, err, url)
	}
}
