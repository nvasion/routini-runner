package envx

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

func TestOpDisabledRunner(t *testing.T) {
	tests := []struct {
		name    string
		options func(*Options)
	}{
		{name: "not enabled", options: func(o *Options) { o.Enabled = false }},
		{name: "no docker daemon", options: func(o *Options) { o.Docker = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.options)
			f.op(opFrame("op-1", "volume.ensure", map[string]any{"name": "routini-env-a"}))
			d := f.out.onlyDone(t)
			if d.OK {
				t.Fatalf("done = %+v, want a refusal", d)
			}
			if d.Error == nil || *d.Error != ErrDisabled {
				t.Errorf("error = %v, want %q", d.Error, ErrDisabled)
			}
			if len(f.rec.list()) != 0 {
				t.Errorf("a disabled Manager called Docker: %v", f.rec.list())
			}
		})
	}
}

func TestOpWithoutIDIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("", "volume.ensure", map[string]any{"name": "routini-env-a"}))
	time.Sleep(100 * time.Millisecond)
	if frames := f.out.all(); len(frames) != 0 {
		t.Errorf("frames = %+v, want none", frames)
	}
}

func TestUnknownOp(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "widget.spin", map[string]any{}))
	d := f.out.onlyDone(t)
	if d.OK {
		t.Fatalf("done = %+v, want a refusal", d)
	}
}

func TestVolumeEnsureAndRemove(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "volume.ensure", map[string]any{"name": "routini-env-a", "labels": map[string]any{"routini.managed": "true"}}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil || d.Result != nil {
		t.Errorf("done = %+v, want a bare success", d)
	}
	if !f.rec.has("EnsureVolume routini-env-a") {
		t.Errorf("calls = %v", f.rec.list())
	}

	f.op(opFrame("op-2", "volume.remove", map[string]any{"name": "routini-env-a"}))
	d = f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Errorf("done = %+v, want a bare success", d)
	}
	if !f.rec.has("RemoveVolume routini-env-a") {
		t.Errorf("calls = %v", f.rec.list())
	}
}

func TestVolumeOpDockerFailure(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.ensureVolume = func(string, map[string]string) error { return errors.New("no space left on device") }
	f.op(opFrame("op-1", "volume.ensure", map[string]any{"name": "routini-env-a"}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || !strings.Contains(*d.Error, "no space left") {
		t.Errorf("done = %+v, want the docker error", d)
	}
}

func TestMalformedArgsNeverEchoTheBody(t *testing.T) {
	f := newFixture(t, nil)
	// args is a JSON array, not an object: json.Unmarshal into the target
	// struct fails.
	frame := map[string]any{"type": "env.op", "id": "op-1", "op": "volume.ensure", "args": json.RawMessage(`["env-secret-value"]`)}
	f.op(frame)
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil {
		t.Fatal("want a refusal")
	}
	if strings.Contains(*d.Error, "env-secret-value") {
		t.Errorf("error echoes the args: %q", *d.Error)
	}
	if *d.Error != "invalid volume.ensure args" {
		t.Errorf("error = %q", *d.Error)
	}
}

func TestNetworkEnsure(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "network.ensure", map[string]any{"network": testNetwork, "egressImage": testEgressImg}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Fatalf("done = %+v, want success", d)
	}
	result, ok := d.Result.(networkResult)
	if !ok {
		// Result decodes through 'any' as the concrete type set by doneOK.
		t.Fatalf("result = %+v (%T), want networkResult", d.Result, d.Result)
	}
	if result.Network != testNetwork {
		t.Errorf("network = %q, want %q", result.Network, testNetwork)
	}
	wantOrder := []string{
		"EnsureImage " + testEgressImg + " missing",
		"EnsureEgress " + testEgressImg,
		"EnsureNetwork " + testNetwork,
		"ConnectNetwork " + testNetwork + " routini-egress routini-egress",
	}
	if got := f.rec.list(); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("call order:\n got %v\nwant %v", got, wantOrder)
	}
}

func TestNetworkEnsureImageNotAllowed(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "network.ensure", map[string]any{"network": testNetwork, "egressImage": "docker.io/library/evil:1"}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ImageNotAllowedError("docker.io/library/evil:1") {
		t.Errorf("done = %+v", d)
	}
	if len(f.rec.list()) != 0 {
		t.Errorf("a refused op reached Docker: %v", f.rec.list())
	}
}

func TestSessionOpenAndClose(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()

	f.op(opFrame("op-open", "session.open", map[string]any{"session": json.RawMessage(testSession)}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Fatalf("done = %+v, want success", d)
	}
	if got := d.Result.(sessionOpenResult); got.CaPem != testPEM {
		t.Errorf("caPem = %q, want %q", got.CaPem, testPEM)
	}
	if !f.ctrl.rec.has("PUT " + sessionsPath()) {
		t.Errorf("calls = %v", f.rec.list())
	}

	f.op(opFrame("op-close", "session.close", map[string]any{"token": testToken}))
	d = f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Fatalf("done = %+v, want success", d)
	}
	closeResult := d.Result.(sessionCloseResult)
	if closeResult.Egress == nil || closeResult.Egress.Requests != 7 {
		t.Errorf("egress = %+v, want the server's stats", closeResult.Egress)
	}
}

func sessionsPath() string { return "/sessions/" + testToken }

func TestSessionOpenWithoutNetworkEnsureIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "session.open", map[string]any{"session": json.RawMessage(testSession)}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ErrEgressNotReady {
		t.Errorf("done = %+v, want %q", d, ErrEgressNotReady)
	}
}

func TestSessionOpenInvalidToken(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()
	f.op(opFrame("op-1", "session.open", map[string]any{"session": json.RawMessage(`{"token":"../ca"}`)}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != "invalid session token" {
		t.Errorf("done = %+v", d)
	}
}

func TestSessionOpenCAFailureClosesTheSession(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()
	f.ctrl.set(func(c *controlServer) { c.caStatus = 500 })

	f.op(opFrame("op-1", "session.open", map[string]any{"session": json.RawMessage(testSession)}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil {
		t.Fatal("want a refusal")
	}
	if !f.ctrl.rec.has("DELETE " + sessionsPath()) {
		t.Error("the session was not closed after the CA read failed")
	}
	if n := len(f.mgr.tokenSnapshot()); n != 0 {
		t.Errorf("tokens remembered = %d, want 0", n)
	}
}

func TestSessionCloseWithoutNetworkEnsureIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "session.close", map[string]any{"token": testToken}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ErrEgressNotReady {
		t.Errorf("done = %+v, want %q", d, ErrEgressNotReady)
	}
}

func TestSessionCloseDeleteFailureStillSucceeds(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()
	f.ctrl.set(func(c *controlServer) { c.deleteStatus = 500 })

	f.op(opFrame("op-1", "session.close", map[string]any{"token": testToken}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Fatalf("done = %+v, want ok with a null egress", d)
	}
	result := d.Result.(sessionCloseResult)
	if result.Egress != nil {
		t.Errorf("egress = %+v, want null", result.Egress)
	}
}

func validContainerStartArgs() map[string]any {
	return map[string]any{
		"name":    "routini-env-task1",
		"image":   testEgressImg,
		"volume":  "routini-env-task1",
		"labels":  map[string]any{"routini.managed": "true", "routini.environment": "env-1"},
		"network": testNetwork,
	}
}

func TestContainerStart(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectVolume = func(string) (dockerx.VolumeInfo, error) {
		return dockerx.VolumeInfo{Exists: true, Labels: map[string]string{dockerx.LabelManaged: "true", dockerx.LabelEnvironment: "env-1"}}, nil
	}
	f.op(opFrame("op-1", "container.start", validContainerStartArgs()))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil {
		t.Fatalf("done = %+v, want success", d)
	}
	result := d.Result.(containerStartResult)
	if result.ContainerID != "container-id" {
		t.Errorf("containerId = %q", result.ContainerID)
	}
	spec := f.dock.lastEnvSpec(t)
	if spec.Runtime != "runsc" {
		t.Errorf("runtime = %q, want runsc (from Options.Runtime)", spec.Runtime)
	}
	if spec.Labels[dockerx.LabelManaged] != "true" {
		t.Errorf("labels = %v, want the managed label forced on", spec.Labels)
	}
}

func TestContainerStartImageNotAllowed(t *testing.T) {
	f := newFixture(t, nil)
	args := validContainerStartArgs()
	args["image"] = "docker.io/library/evil:1"
	f.op(opFrame("op-1", "container.start", args))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ImageNotAllowedError("docker.io/library/evil:1") {
		t.Errorf("done = %+v", d)
	}
	if len(f.rec.list()) != 0 {
		t.Errorf("a refused start reached Docker: %v", f.rec.list())
	}
}

func TestContainerStartBusy(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxEnvironments = 2 })
	f.dock.countEnvContainers = func() (int, error) { return 2, nil }
	f.op(opFrame("op-1", "container.start", validContainerStartArgs()))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != BusyError(2) {
		t.Errorf("done = %+v, want %q", d, BusyError(2))
	}
	if f.rec.has("EnsureImage " + testEgressImg + " missing") {
		t.Error("a busy refusal still pulled the image")
	}
}

func TestContainerStartVolumeMissing(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectVolume = func(string) (dockerx.VolumeInfo, error) { return dockerx.VolumeInfo{}, nil }
	f.op(opFrame("op-1", "container.start", validContainerStartArgs()))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || !strings.Contains(*d.Error, "does not exist") {
		t.Errorf("done = %+v, want a volume-missing refusal", d)
	}
	if len(f.dock.envSpecs) != 0 {
		t.Error("StartEnvContainer must not be called when the volume is missing")
	}
}

func TestContainerStartVolumeLabelMismatch(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectVolume = func(string) (dockerx.VolumeInfo, error) {
		return dockerx.VolumeInfo{Exists: true, Labels: map[string]string{dockerx.LabelManaged: "true", dockerx.LabelEnvironment: "some-other-env"}}, nil
	}
	f.op(opFrame("op-1", "container.start", validContainerStartArgs()))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || !strings.Contains(*d.Error, "does not carry") {
		t.Errorf("done = %+v, want a label-mismatch refusal", d)
	}
	if len(f.dock.envSpecs) != 0 {
		t.Error("StartEnvContainer must not be called when the labels mismatch")
	}
}

func TestContainerStartDockerFailure(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectVolume = func(string) (dockerx.VolumeInfo, error) {
		return dockerx.VolumeInfo{Exists: true, Labels: map[string]string{dockerx.LabelManaged: "true", dockerx.LabelEnvironment: "env-1"}}, nil
	}
	f.dock.startEnvContainer = func(dockerx.EnvSpec) (string, error) { return "", errors.New("no such runtime") }
	f.op(opFrame("op-1", "container.start", validContainerStartArgs()))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || !strings.Contains(*d.Error, "no such runtime") {
		t.Errorf("done = %+v", d)
	}
}

func TestContainerRemove(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "container.remove", map[string]any{"containerId": "c1"}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil || d.Result != nil {
		t.Errorf("done = %+v, want a bare success", d)
	}
	if !f.rec.has("RemoveEnvContainer c1") {
		t.Errorf("calls = %v", f.rec.list())
	}
}

func TestContainerRemoveFailure(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.removeEnvContainer = func(string) error { return errors.New("not a Routini environment container") }
	f.op(opFrame("op-1", "container.remove", map[string]any{"containerId": "c1"}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil {
		t.Fatal("want a refusal")
	}
}

func TestContainerState(t *testing.T) {
	tests := []struct {
		name string
		info dockerx.EnvInfo
		want string
	}{
		{"missing", dockerx.EnvInfo{}, "missing"},
		{"not managed", dockerx.EnvInfo{Exists: true, Running: true}, "missing"},
		{"running", dockerx.EnvInfo{Exists: true, Running: true, Managed: true}, "running"},
		{"stopped", dockerx.EnvInfo{Exists: true, Running: false, Managed: true}, "stopped"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.dock.inspectEnv = func(string) (dockerx.EnvInfo, error) { return tc.info, nil }
			f.op(opFrame("op-1", "container.state", map[string]any{"containerId": "c1"}))
			d := f.out.onlyDone(t)
			if !d.OK || d.Error != nil {
				t.Fatalf("done = %+v, want success", d)
			}
			result := d.Result.(containerStateResult)
			if result.State != tc.want {
				t.Errorf("state = %q, want %q", result.State, tc.want)
			}
		})
	}
}

func TestPull(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "pull", map[string]any{"image": testEgressImg}))
	d := f.out.onlyDone(t)
	if !d.OK || d.Error != nil || d.Result != nil {
		t.Errorf("done = %+v, want a bare success", d)
	}
	if !f.rec.has("EnsureImage " + testEgressImg + " always") {
		t.Errorf("calls = %v", f.rec.list())
	}
}

func TestPullImageNotAllowed(t *testing.T) {
	f := newFixture(t, nil)
	f.op(opFrame("op-1", "pull", map[string]any{"image": "docker.io/library/evil:1"}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ImageNotAllowedError("docker.io/library/evil:1") {
		t.Errorf("done = %+v", d)
	}
	if len(f.rec.list()) != 0 {
		t.Errorf("a refused pull reached Docker: %v", f.rec.list())
	}
}

func TestRunningCountsEnvironmentContainers(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.countEnvContainers = func() (int, error) { return 3, nil }
	if n := f.mgr.Running(); n != 3 {
		t.Errorf("Running() = %d, want 3", n)
	}
}

func TestRunningErrorsCountAsZero(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.countEnvContainers = func() (int, error) { return 0, errors.New("daemon unreachable") }
	if n := f.mgr.Running(); n != 0 {
		t.Errorf("Running() = %d, want 0", n)
	}
}

func TestRunningOnADisabledManagerIsZero(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Enabled = false })
	if n := f.mgr.Running(); n != 0 {
		t.Errorf("Running() = %d, want 0", n)
	}
}

func TestConcurrentOpsEachGetExactlyOneDone(t *testing.T) {
	f := newFixture(t, nil)
	ids := []string{"o1", "o2", "o3", "o4"}
	for _, id := range ids {
		f.op(opFrame(id, "volume.ensure", map[string]any{"name": "routini-env-" + id}))
	}
	seen := map[string]int{}
	for range ids {
		seen[f.out.waitDone(t).ID]++
	}
	for _, id := range ids {
		if seen[id] != 1 {
			t.Errorf("op %s got %d env.done frames, want 1", id, seen[id])
		}
	}
	select {
	case extra := <-f.out.doneCh:
		t.Fatalf("an extra env.done was sent: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestSecretsNeverReachTheServer(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()
	f.op(opFrame("op-1", "session.open", map[string]any{"session": json.RawMessage(testSession)}))
	f.out.onlyDone(t)
	if strings.Contains(f.out.json(t), f.mgr.secret) {
		t.Error("the egress secret was sent to the server")
	}
	if strings.Contains(f.logs.String(), f.mgr.secret) {
		t.Error("the egress secret was logged")
	}
}

func TestDisconnectClosesSessionsWithoutRemovingContainers(t *testing.T) {
	f := newFixture(t, nil)
	f.ensureNetworkFirst()
	f.op(opFrame("op-open", "session.open", map[string]any{"session": json.RawMessage(testSession)}))
	f.out.onlyDone(t)

	f.mgr.Disconnect()

	if !f.ctrl.rec.has("DELETE " + sessionsPath()) {
		t.Error("Disconnect did not close the egress session")
	}
	if n := len(f.mgr.tokenSnapshot()); n != 0 {
		t.Errorf("tokens remembered after Disconnect = %d, want 0", n)
	}
	for _, line := range f.rec.list() {
		if strings.HasPrefix(line, "RemoveEnvContainer") || strings.HasPrefix(line, "RemoveVolume") {
			t.Errorf("Disconnect touched containers or volumes: %q", line)
		}
	}
}

func TestDisconnectCancelsRunningExecs(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = func(string) (dockerx.EnvInfo, error) {
		return dockerx.EnvInfo{Exists: true, Running: true, Managed: true}, nil
	}
	started := make(chan struct{})
	f.dock.execStreaming = func(ctx context.Context, _ string, _ dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"sleep", "60"}}))
	<-started
	f.mgr.Disconnect()

	// Disconnect silences the job: nothing more is sent for it.
	select {
	case extra := <-f.out.doneCh:
		t.Fatalf("env.done was sent after Disconnect: %+v", extra)
	case <-time.After(300 * time.Millisecond):
	}
	if !f.mgr.Wait(5 * time.Second) {
		t.Fatal("Disconnect did not finish the exec op")
	}
}
