package envx

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

// EnvE2E opts a test run into the end-to-end test below. It needs a
// reachable Docker daemon and pulls a public image, so it is off by
// default:
//
//	ROUTINI_RUNNER_DOCKER_E2E=1 go test ./internal/envx/ -run E2E -v
const EnvE2E = "ROUTINI_RUNNER_DOCKER_E2E"

// The e2e environment: a real container and volume, with no egress network
// connected. e2ePrefix is what a runner's agentImagePrefixes would allow;
// this test calls dockerx directly, so the prefix only documents the rule
// envx.Op would otherwise enforce.
const (
	e2eID      = "e2e-env-1"
	e2eImage   = "bash:5.2"
	e2ePrefix  = "bash:"
	e2eName    = "routini-env-" + e2eID
	e2eVolume  = e2eName
	e2eNetwork = "routini-sb-e2e"
)

// TestE2EAgainstRealDocker drives the dockerx environment primitives
// (PROTOCOL.md 2.8) against the local Docker daemon, the same primitives
// envx.Manager's ops wrap: ensure a volume and a (egress-free) network,
// start a container on them, run a quick exec to completion, run a slow one
// that a timeout has to kill, check its state, then tear everything down.
func TestE2EAgainstRealDocker(t *testing.T) {
	if os.Getenv(EnvE2E) != "1" {
		t.Skipf("set %s=1 to run the Docker end-to-end test", EnvE2E)
	}
	if !strings.HasPrefix(e2eImage, e2ePrefix) {
		t.Fatalf("test setup: %q does not start with %q", e2eImage, e2ePrefix)
	}
	client, err := dockerx.New("")
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	version, err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("docker ping: %v", err)
	}
	t.Logf("docker %s", version)

	labels := map[string]string{dockerx.LabelManaged: "true", dockerx.LabelEnvironment: e2eID}

	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = client.RemoveEnvContainer(cctx, e2eName)
		_ = client.RemoveVolume(cctx, e2eVolume)
	})

	if err := client.EnsureNetwork(ctx, e2eNetwork, labels); err != nil {
		t.Fatalf("EnsureNetwork: %v", err)
	}
	if err := client.EnsureVolume(ctx, e2eVolume, labels); err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	if err := client.EnsureImage(ctx, e2eImage, dockerx.PullMissing); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}

	spec := dockerx.EnvSpec{
		Name:      e2eName,
		Image:     e2eImage,
		Volume:    e2eVolume,
		Network:   e2eNetwork,
		Labels:    labels,
		Cpus:      1,
		MemoryMb:  256,
		PidsLimit: 64,
	}
	id, err := client.StartEnvContainer(ctx, spec)
	if err != nil {
		t.Fatalf("StartEnvContainer: %v", err)
	}

	// exec "echo hi": a quick command that exits 0.
	var stdout []string
	code, err := client.ExecStreaming(ctx, id, dockerx.ExecSpec{Cmd: []string{"echo", "hi"}}, func(stream, line string) {
		if stream == "stdout" {
			stdout = append(stdout, line)
		}
	})
	if err != nil {
		t.Fatalf("ExecStreaming(echo hi): %v", err)
	}
	if code == nil || *code != 0 {
		t.Errorf("exit code = %v, want 0", code)
	}
	if len(stdout) != 1 || stdout[0] != "hi" {
		t.Errorf("stdout = %v, want [hi]", stdout)
	}

	// exec "sleep 60" with a 2s timeout: killed, nil exit code.
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer timeoutCancel()
	started := time.Now()
	code, err = client.ExecStreaming(timeoutCtx, id, dockerx.ExecSpec{Cmd: []string{"sleep", "60"}}, func(string, string) {})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("ExecStreaming(sleep 60): want an error reporting the cancellation")
	}
	if code != nil {
		t.Errorf("exit code = %v, want null for a killed process", *code)
	}
	if elapsed > 30*time.Second {
		t.Errorf("ExecStreaming took %s to return after a 2s timeout", elapsed)
	}

	// state: running.
	info, err := client.InspectEnv(context.Background(), id)
	if err != nil {
		t.Fatalf("InspectEnv: %v", err)
	}
	if !info.Exists || !info.Running || !info.Managed {
		t.Errorf("info = %+v, want an existing, running, managed container", info)
	}

	// remove, then state: missing.
	if err := client.RemoveEnvContainer(context.Background(), id); err != nil {
		t.Fatalf("RemoveEnvContainer: %v", err)
	}
	info, err = client.InspectEnv(context.Background(), id)
	if err != nil {
		t.Fatalf("InspectEnv after remove: %v", err)
	}
	if info.Exists {
		t.Errorf("info = %+v, want missing after RemoveEnvContainer", info)
	}

	// volume remove.
	if err := client.RemoveVolume(context.Background(), e2eVolume); err != nil {
		t.Fatalf("RemoveVolume: %v", err)
	}
}
