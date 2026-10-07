package envx

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

func managedRunning() func(string) (dockerx.EnvInfo, error) {
	return func(string) (dockerx.EnvInfo, error) {
		return dockerx.EnvInfo{Exists: true, Running: true, Managed: true}, nil
	}
}

func TestExecStreamsOutputAndSucceeds(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	f.dock.execStreaming = func(_ context.Context, id string, spec dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
		if id != "c1" {
			t.Errorf("container id = %q, want c1", id)
		}
		if !reflect.DeepEqual(spec.Cmd, []string{"echo", "hi"}) {
			t.Errorf("cmd = %v", spec.Cmd)
		}
		onLine("stdout", "hi")
		return ptr(0), nil
	}

	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"echo", "hi"}}))
	d := f.out.onlyDone(t)
	if !d.OK {
		t.Fatalf("done = %+v, want ok", d)
	}
	if d.ExitCode == nil || *d.ExitCode != 0 {
		t.Errorf("exitCode = %v, want 0", d.ExitCode)
	}
	if d.TimedOut || d.Canceled || d.Error != nil {
		t.Errorf("done = %+v, want a clean run", d)
	}
	wantOut := []OutputMsg{{Type: TypeOutput, ID: "exec-1", Stream: "stdout", Data: "hi"}}
	if got := f.out.outputs(); !reflect.DeepEqual(got, wantOut) {
		t.Errorf("output = %+v, want %+v", got, wantOut)
	}
}

func TestExecNonZeroExitIsStillOK(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	f.dock.execStreaming = func(context.Context, string, dockerx.ExecSpec, func(string, string)) (*int, error) {
		return ptr(1), nil
	}
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"false"}}))
	d := f.out.onlyDone(t)
	if !d.OK {
		t.Errorf("done = %+v, want ok even for a non-zero exit", d)
	}
	if d.ExitCode == nil || *d.ExitCode != 1 {
		t.Errorf("exitCode = %v, want 1", d.ExitCode)
	}
}

func TestExecContainerNotManaged(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = func(string) (dockerx.EnvInfo, error) { return dockerx.EnvInfo{}, nil }
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"echo", "hi"}}))
	d := f.out.onlyDone(t)
	if d.OK || d.Error == nil || *d.Error != ErrContainerMissing {
		t.Errorf("done = %+v, want %q", d, ErrContainerMissing)
	}
	if f.rec.has("ExecStreaming c1") {
		t.Error("exec reached ExecStreaming for an unmanaged container")
	}
}

func TestExecCreateFailureIsNotOK(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	f.dock.execStreaming = func(context.Context, string, dockerx.ExecSpec, func(string, string)) (*int, error) {
		return nil, errors.New("create exec in container: no such container")
	}
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"echo", "hi"}}))
	d := f.out.onlyDone(t)
	if d.OK {
		t.Errorf("done = %+v, want ok=false: the command never ran", d)
	}
	if d.ExitCode != nil {
		t.Errorf("exitCode = %v, want null", *d.ExitCode)
	}
	if d.Error == nil || !strings.Contains(*d.Error, "no such container") {
		t.Errorf("error = %v", d.Error)
	}
}

func TestExecCancelKillsAndReportsNullExitCode(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	started := make(chan struct{})
	f.dock.execStreaming = func(ctx context.Context, _ string, _ dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"sleep", "60"}}))
	<-started
	f.mgr.Cancel("exec-1")

	d := f.out.onlyDone(t)
	if !d.OK {
		t.Errorf("done = %+v, want ok: the command did run", d)
	}
	if !d.Canceled || d.TimedOut {
		t.Errorf("done = %+v, want canceled", d)
	}
	if d.ExitCode != nil {
		t.Errorf("exitCode = %v, want null for a killed process", *d.ExitCode)
	}
	if d.Error != nil {
		t.Errorf("error = %q, want null: the cancel was deliberate", *d.Error)
	}
}

func TestExecTimeoutKillsAndReportsNullExitCode(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	f.dock.execStreaming = func(ctx context.Context, _ string, _ dockerx.ExecSpec, onLine func(string, string)) (*int, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.op(opFrame("exec-1", "exec", map[string]any{"containerId": "c1", "cmd": []string{"sleep", "60"}, "timeoutSec": 1}))

	d := f.out.onlyDone(t)
	if !d.OK {
		t.Errorf("done = %+v, want ok", d)
	}
	if !d.TimedOut || d.Canceled {
		t.Errorf("done = %+v, want timedOut", d)
	}
	if d.ExitCode != nil {
		t.Errorf("exitCode = %v, want null", *d.ExitCode)
	}
}

func TestCancelOfUnknownIDIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.mgr.Cancel("nobody")
	// Nothing to assert beyond "did not panic or block"; give any stray
	// goroutine a moment and confirm no frame was produced.
	time.Sleep(50 * time.Millisecond)
	if frames := f.out.all(); len(frames) != 0 {
		t.Errorf("frames = %+v, want none", frames)
	}
}

func TestExecEnvAndWorkdirPassThrough(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.inspectEnv = managedRunning()
	var gotSpec dockerx.ExecSpec
	f.dock.execStreaming = func(_ context.Context, _ string, spec dockerx.ExecSpec, _ func(string, string)) (*int, error) {
		gotSpec = spec
		return ptr(0), nil
	}
	f.op(opFrame("exec-1", "exec", map[string]any{
		"containerId": "c1",
		"cmd":         []string{"env"},
		"env":         map[string]any{"FOO": "bar"},
		"workdir":     "/workspace/sub",
	}))
	f.out.onlyDone(t)
	if gotSpec.Env["FOO"] != "bar" {
		t.Errorf("env = %v", gotSpec.Env)
	}
	if gotSpec.Workdir != "/workspace/sub" {
		t.Errorf("workdir = %q", gotSpec.Workdir)
	}
}
