package agentx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/egressctl"
)

// wantOrder is the sequence of PROTOCOL.md 2.6 for one successful task.
var wantOrder = []string{
	"EnsureImage " + testEgressImage + " missing",
	"EnsureEgress " + testEgressImage,
	"EnsureNetwork " + testNetwork,
	"ConnectNetwork " + testNetwork + " routini-egress routini-egress",
	"PUT " + egressctl.SessionsPath + testToken,
	"GET " + egressctl.CAPath,
	"EnsureImage " + testAgentImage + " always",
	"RunStreaming " + ContainerPrefix + testID,
	"DELETE " + egressctl.SessionsPath + testToken,
}

func TestStartRunsTheStepsInOrder(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.run = func(_ context.Context, _ dockerx.RunSpec, onLine func(stream, line string)) (*int, error) {
		onLine("stdout", "hello")
		onLine("stderr", "warning")
		return ptr(7), nil
	}

	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)

	if got := f.rec.list(); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("call order:\n got %v\nwant %v", got, wantOrder)
	}
	if exit.Type != TypeExit || exit.ID != testID {
		t.Errorf("exit = %+v", exit)
	}
	if exit.ExitCode == nil || *exit.ExitCode != 7 {
		t.Errorf("exitCode = %v, want 7", exit.ExitCode)
	}
	if exit.TimedOut || exit.Canceled || exit.Error != nil {
		t.Errorf("exit = %+v, want a clean run", exit)
	}
	want := &EgressStats{Requests: 41, Intercepted: 12, Blocked: []string{"evil.example"}}
	if !reflect.DeepEqual(exit.Egress, want) {
		t.Errorf("egress = %+v, want %+v", exit.Egress, want)
	}
	wantOut := []OutputMsg{
		{Type: TypeOutput, ID: testID, Stream: "stdout", Data: "hello"},
		{Type: TypeOutput, ID: testID, Stream: "stderr", Data: "warning"},
	}
	if got := f.out.outputs(); !reflect.DeepEqual(got, wantOut) {
		t.Errorf("output = %+v, want %+v", got, wantOut)
	}
	// agent.exit is the last frame of the task.
	all := f.out.all()
	if _, ok := all[len(all)-1].(ExitMsg); !ok {
		t.Errorf("last frame is not agent.exit: %+v", all)
	}
}

func TestInjectedEnvironment(t *testing.T) {
	f := newFixture(t, nil)
	f.start(startFrame(nil))
	f.out.onlyExit(t)

	spec := f.dock.lastSpec(t)
	proxy := "http://routini:" + testToken + "@routini-egress:3128"
	want := map[string]string{
		"ROUTINI_PROMPT":            "do the thing",
		"ANTHROPIC_API_KEY":         "routini-brokered-credential",
		"HTTPS_PROXY":               proxy,
		"HTTP_PROXY":                proxy,
		"https_proxy":               proxy,
		"http_proxy":                proxy,
		"NO_PROXY":                  "",
		"no_proxy":                  "",
		"GIT_HTTP_PROXY_AUTHMETHOD": "basic",
		"ROUTINI_CA_PEM":            testPEM,
	}
	if !reflect.DeepEqual(spec.Env, want) {
		t.Errorf("container env =\n %v\nwant\n %v", spec.Env, want)
	}
	// The bindings' secrets and the egress secret stay on the host.
	for k, v := range spec.Env {
		if strings.Contains(v, bindingSecret) {
			t.Errorf("env %s carries a binding secret", k)
		}
		if strings.Contains(v, f.dock.egressSecret(t)) {
			t.Errorf("env %s carries the egress secret", k)
		}
	}
	if spec.Name != ContainerPrefix+testID {
		t.Errorf("container name = %q", spec.Name)
	}
	if spec.Network != testNetwork || spec.Runtime != "runsc" || spec.Image != testAgentImage {
		t.Errorf("spec = %+v", spec)
	}
	if spec.User != "1000:1000" || spec.PidsLimit != 512 || spec.MemoryMb != 4096 || spec.Cpus != 2 {
		t.Errorf("spec limits = %+v", spec)
	}
	wantLabels := map[string]string{"routini.managed": "true", "routini.run": "run-12", "routini.step": "0"}
	if !reflect.DeepEqual(spec.Labels, wantLabels) {
		t.Errorf("labels = %v, want %v", spec.Labels, wantLabels)
	}
	if strings.Contains(f.out.json(t), bindingSecret) {
		t.Error("a binding secret was sent to the server")
	}
}

func TestEnvMissingLabelsAndEnvAreFine(t *testing.T) {
	f := newFixture(t, nil)
	f.start(startFrame(map[string]any{"env": nil, "labels": nil}))
	exit := f.out.onlyExit(t)
	if exit.Error != nil {
		t.Fatalf("error = %q", *exit.Error)
	}
	spec := f.dock.lastSpec(t)
	if len(spec.Env) != injectedEnvCount {
		t.Errorf("env = %v, want only the %d injected entries", spec.Env, injectedEnvCount)
	}
	// The label the runner matches on when cleaning up is always present.
	if spec.Labels[dockerx.LabelManaged] != "true" {
		t.Errorf("labels = %v", spec.Labels)
	}
}

func TestSessionPutBodyAndBearer(t *testing.T) {
	f := newFixture(t, nil)
	f.start(startFrame(nil))
	f.out.onlyExit(t)

	var got, want any
	if err := json.Unmarshal(f.ctrl.body(), &got); err != nil {
		t.Fatalf("PUT body is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(testSession), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PUT body = %v, want %v", got, want)
	}

	secret := f.dock.egressSecret(t)
	if len(secret) != 2*egressSecretBytes {
		t.Errorf("egress secret is %d characters, want %d", len(secret), 2*egressSecretBytes)
	}
	auths := f.ctrl.authHeaders()
	if len(auths) != 3 {
		t.Fatalf("control calls = %d, want 3", len(auths))
	}
	for _, a := range auths {
		if a != "Bearer "+secret {
			t.Errorf("Authorization = %q, want the egress secret as a bearer token", a)
		}
	}
	if strings.Contains(f.logs.String(), secret) || strings.Contains(f.logs.String(), bindingSecret) {
		t.Error("a secret was logged")
	}
}

func TestEachManagerHasItsOwnSecret(t *testing.T) {
	a := newFixture(t, nil)
	b := newFixture(t, nil)
	a.start(startFrame(nil))
	a.out.onlyExit(t)
	b.start(startFrame(nil))
	b.out.onlyExit(t)
	if a.dock.egressSecret(t) == b.dock.egressSecret(t) {
		t.Error("two Managers share one egress secret")
	}
}

func TestRefusals(t *testing.T) {
	tests := []struct {
		name    string
		options func(*Options)
		frame   map[string]any
		before  func(*fixture)
		want    string
	}{
		{
			name:    "agents disabled in config",
			options: func(o *Options) { o.Enabled = false },
			want:    ErrDisabled,
		},
		{
			name:    "no docker daemon",
			options: func(o *Options) { o.Docker = nil },
			want:    ErrDisabled,
		},
		{
			name:  "agent image not allowed",
			frame: map[string]any{"image": "docker.io/library/evil:1"},
			want:  "image not allowed by agentImagePrefixes: docker.io/library/evil:1",
		},
		{
			name:  "egress image not allowed",
			frame: map[string]any{"egress": egressOverride(map[string]any{"image": "docker.io/library/evil:1"})},
			want:  "image not allowed by agentImagePrefixes: docker.io/library/evil:1",
		},
		{
			name:    "empty allow-list allows nothing",
			options: func(o *Options) { o.ImagePrefixes = nil },
			want:    "image not allowed by agentImagePrefixes: " + testAgentImage,
		},
		{
			name:  "invalid env key",
			frame: map[string]any{"env": map[string]any{"BAD-KEY": "x"}},
			want:  ErrInvalidEnvKey,
		},
		{
			name:  "env key starting with a digit",
			frame: map[string]any{"env": map[string]any{"1FOO": "x"}},
			want:  ErrInvalidEnvKey,
		},
		{
			name:  "invalid id",
			frame: map[string]any{"id": "../../etc/passwd"},
			want:  ErrInvalidID,
		},
		{
			name:  "session without a token",
			frame: map[string]any{"egress": egressOverride(map[string]any{"session": json.RawMessage(`{"orgId":"org-1"}`)})},
			want:  ErrInvalidToken,
		},
		{
			name:  "token with path characters",
			frame: map[string]any{"egress": egressOverride(map[string]any{"session": json.RawMessage(`{"token":"../ca"}`)})},
			want:  ErrInvalidToken,
		},
		{
			name: "runner busy",
			before: func(f *fixture) {
				// Fill both slots with tasks that block until the test ends.
				release := make(chan struct{})
				f.t.Cleanup(func() { close(release) })
				f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
					select {
					case <-release:
					case <-ctx.Done():
					}
					return ptr(0), nil
				}
				for _, id := range []string{"busy-1", "busy-2"} {
					f.start(startFrame(map[string]any{"id": id}))
				}
				waitFor(f.t, func() bool { return f.mgr.Running() == 2 })
			},
			want: "runner busy (2 agents running)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.options)
			if tc.before != nil {
				tc.before(f)
			}
			refused := newSink()
			f.mgr.Start(f.decode(startFrame(tc.frame)), refused.send)

			exit := refused.onlyExit(t)
			if exit.Error == nil || *exit.Error != tc.want {
				t.Fatalf("error = %v, want %q", exit.Error, tc.want)
			}
			if exit.ExitCode != nil || exit.TimedOut || exit.Canceled || exit.Egress != nil {
				t.Errorf("exit = %+v, want a bare refusal", exit)
			}
			if len(refused.outputs()) != 0 {
				t.Errorf("a refusal produced output: %+v", refused.outputs())
			}
			// Nothing is created for a refused task.
			for _, line := range f.rec.list() {
				if strings.Contains(line, testID) {
					t.Errorf("a refused task reached Docker: %q", line)
				}
			}
		})
	}
}

func TestRefusalMessagesCarryNoSecret(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Enabled = false })
	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)
	if strings.Contains(*exit.Error, bindingSecret) || strings.Contains(*exit.Error, testToken) {
		t.Errorf("refusal leaks a secret: %q", *exit.Error)
	}
}

func TestStartWithoutIDIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.start(startFrame(map[string]any{"id": ""}))
	if frames := f.out.all(); len(frames) != 0 {
		t.Errorf("frames = %+v, want none", frames)
	}
}

func TestDuplicateIDIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return ptr(0), nil
	}
	f.start(startFrame(nil))
	waitFor(t, func() bool { return f.mgr.Running() == 1 })
	f.start(startFrame(nil))

	// The second frame produces nothing; the first task is still running.
	time.Sleep(150 * time.Millisecond)
	if n := len(f.out.exits()); n != 0 {
		t.Errorf("exits = %d, want 0 while the task runs", n)
	}
	if n := f.mgr.Running(); n != 1 {
		t.Errorf("Running() = %d, want 1", n)
	}
}

func TestTimeoutStopsTheContainer(t *testing.T) {
	f := newFixture(t, nil)
	stopped := make(chan struct{})
	f.dock.stop = func(string, time.Duration) error { close(stopped); return nil }
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, onLine func(stream, line string)) (*int, error) {
		onLine("stdout", "working")
		select {
		case <-stopped:
		case <-ctx.Done():
		}
		// A stopped container is killed, so Docker reports 137 here; the
		// protocol wants a null exitCode either way.
		return ptr(137), nil
	}

	f.mgr.Cancel("nobody") // unknown ids are ignored
	f.start(startFrame(map[string]any{"timeoutSec": 1}))

	exit := f.out.onlyExit(t)
	if !exit.TimedOut || exit.Canceled {
		t.Errorf("exit = %+v, want timedOut", exit)
	}
	if exit.ExitCode != nil {
		t.Errorf("exitCode = %v, want null for a killed container", *exit.ExitCode)
	}
	if exit.Error != nil {
		t.Errorf("error = %q, want null: the stop was deliberate", *exit.Error)
	}
	if exit.Egress == nil {
		t.Error("egress stats are missing: the session must still be closed")
	}
	if got := f.dock.stops(); !reflect.DeepEqual(got, []string{ContainerPrefix + testID}) {
		t.Errorf("Stop calls = %v", got)
	}
	if !f.rec.has("Stop " + ContainerPrefix + testID + " " + StopGrace.String()) {
		t.Errorf("Stop was not called with a %s grace: %v", StopGrace, f.rec.list())
	}
	if !f.rec.has("DELETE " + egressctl.SessionsPath + testToken) {
		t.Errorf("the session was not closed: %v", f.rec.list())
	}
}

func TestTimeoutFromTheFrame(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// Stop fails, which makes the Manager unblock the run itself.
	f.dock.stop = func(string, time.Duration) error { return errors.New("no such container") }

	f.start(startFrame(map[string]any{"timeoutSec": 1}))
	exit := f.out.onlyExit(t)
	if !exit.TimedOut {
		t.Errorf("exit = %+v, want timedOut", exit)
	}
}

func TestCancel(t *testing.T) {
	f := newFixture(t, nil)
	stopped := make(chan struct{})
	f.dock.stop = func(string, time.Duration) error { close(stopped); return nil }
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
		select {
		case <-stopped:
		case <-ctx.Done():
		}
		return ptr(137), nil
	}

	f.start(startFrame(nil))
	// Cancel once the container is running, so the stop is what ends it.
	waitFor(t, func() bool { return f.dock.runs() == 1 })
	f.mgr.Cancel(testID)

	exit := f.out.onlyExit(t)
	if !exit.Canceled || exit.TimedOut {
		t.Errorf("exit = %+v, want canceled", exit)
	}
	if exit.ExitCode != nil || exit.Error != nil {
		t.Errorf("exit = %+v, want a null exitCode and no error", exit)
	}
	if exit.Egress == nil {
		t.Error("egress stats are missing")
	}
	if got := f.dock.stops(); len(got) != 1 {
		t.Errorf("Stop calls = %v, want exactly one", got)
	}
	waitFor(t, func() bool { return f.mgr.Running() == 0 })
}

func TestCancelAllStopsEveryTaskAndKillsLeftovers(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxConcurrent = 3 })
	stop := make(chan struct{})
	var once sync.Once
	f.dock.stop = func(string, time.Duration) error {
		once.Do(func() { close(stop) })
		return nil
	}
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
		select {
		case <-stop:
		case <-ctx.Done():
		}
		return ptr(137), nil
	}

	ids := []string{"a1", "a2", "a3"}
	for _, id := range ids {
		f.start(startFrame(map[string]any{"id": id}))
	}
	waitFor(t, func() bool { return f.dock.runs() == 3 })
	f.mgr.CancelAll()

	for range ids {
		exit := f.out.waitExit(t)
		if !exit.Canceled {
			t.Errorf("exit %s = %+v, want canceled", exit.ID, exit)
		}
	}
	if !f.mgr.Wait(10 * time.Second) {
		t.Fatal("CancelAll did not finish")
	}
	if n := len(f.dock.stops()); n != 3 {
		t.Errorf("Stop calls = %d, want 3", n)
	}
	want := []map[string]string{{dockerx.LabelManaged: "true"}}
	if got := f.dock.kills(); !reflect.DeepEqual(got, want) {
		t.Errorf("KillByLabels = %v, want %v", got, want)
	}
	if n := f.mgr.Running(); n != 0 {
		t.Errorf("Running() = %d, want 0", n)
	}
	// Every task closed its session.
	deletes := 0
	for _, line := range f.rec.list() {
		if strings.HasPrefix(line, "DELETE ") {
			deletes++
		}
	}
	if deletes != 3 {
		t.Errorf("DELETE calls = %d, want 3", deletes)
	}
}

func TestCancelAllWithoutTasksStillKills(t *testing.T) {
	f := newFixture(t, nil)
	f.mgr.CancelAll()
	if !f.mgr.Wait(10 * time.Second) {
		t.Fatal("CancelAll did not finish")
	}
	if n := len(f.dock.kills()); n != 1 {
		t.Errorf("KillByLabels calls = %d, want 1", n)
	}
}

func TestCancelAllOnADisabledManagerDoesNothing(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Enabled = false })
	f.mgr.CancelAll()
	if !f.mgr.Wait(5 * time.Second) {
		t.Fatal("CancelAll did not finish")
	}
	if got := f.rec.list(); len(got) != 0 {
		t.Errorf("a disabled Manager called Docker: %v", got)
	}
}

func TestShutdownRefusesNewTasks(t *testing.T) {
	f := newFixture(t, nil)
	f.mgr.Shutdown()
	if !f.mgr.Wait(10 * time.Second) {
		t.Fatal("Shutdown did not finish")
	}
	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)
	if exit.Error == nil || *exit.Error != ErrShuttingDown {
		t.Errorf("error = %v, want %q", exit.Error, ErrShuttingDown)
	}
}

func TestFailingStepStillClosesAnOpenSession(t *testing.T) {
	tests := []struct {
		name       string
		arrange    func(*fixture)
		wantDelete bool
		wantErr    string
	}{
		{
			name: "step 2: egress image",
			arrange: func(f *fixture) {
				f.dock.ensureImage = func(ref, _ string) error {
					if ref == testEgressImage {
						return errors.New("no such image")
					}
					return nil
				}
			},
			wantErr: "ensure egress image",
		},
		{
			name: "step 2: egress container",
			arrange: func(f *fixture) {
				f.dock.ensureEgress = func(string, string) (string, error) { return "", errors.New("daemon down") }
			},
			wantErr: "ensure egress container",
		},
		{
			name: "step 2: network",
			arrange: func(f *fixture) {
				f.dock.ensureNetwork = func(string, map[string]string) error { return errors.New("bad network") }
			},
			wantErr: "ensure egress network",
		},
		{
			name: "step 2: connect",
			arrange: func(f *fixture) {
				f.dock.connect = func(string, string, string) error { return errors.New("not connected") }
			},
			wantErr: "connect egress container to network",
		},
		{
			name: "step 2: control URL is not on loopback",
			arrange: func(f *fixture) {
				f.dock.ensureEgress = func(string, string) (string, error) { return "http://evil.example:3129", nil }
			},
			wantErr: "not a loopback address",
		},
		{
			name: "step 3: put session",
			arrange: func(f *fixture) {
				f.ctrl.set(func(c *controlServer) { c.putStatus = http.StatusForbidden })
			},
			wantErr: "open egress session",
		},
		{
			name: "step 3: read ca",
			arrange: func(f *fixture) {
				f.ctrl.set(func(c *controlServer) { c.caStatus = http.StatusInternalServerError })
			},
			wantDelete: true,
			wantErr:    "read egress CA",
		},
		{
			name: "step 3: empty ca",
			arrange: func(f *fixture) {
				f.ctrl.set(func(c *controlServer) { c.pem = "" })
			},
			wantDelete: true,
			wantErr:    "returned no pem",
		},
		{
			name: "step 5: agent image",
			arrange: func(f *fixture) {
				f.dock.ensureImage = func(ref, _ string) error {
					if ref == testAgentImage {
						return errors.New("pull failed")
					}
					return nil
				}
			},
			wantDelete: true,
			wantErr:    "ensure agent image",
		},
		{
			name: "step 5: run",
			arrange: func(f *fixture) {
				f.dock.run = func(context.Context, dockerx.RunSpec, func(string, string)) (*int, error) {
					return nil, errors.New("create failed")
				}
			},
			wantDelete: true,
			wantErr:    "run agent container",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			tc.arrange(f)
			f.start(startFrame(nil))

			exit := f.out.onlyExit(t)
			if exit.ExitCode != nil {
				t.Errorf("exitCode = %v, want null", *exit.ExitCode)
			}
			if exit.Error == nil || !strings.Contains(*exit.Error, tc.wantErr) {
				t.Fatalf("error = %v, want one mentioning %q", exit.Error, tc.wantErr)
			}
			if strings.Contains(*exit.Error, testToken) || strings.Contains(*exit.Error, bindingSecret) ||
				strings.Contains(*exit.Error, f.mgr.secret) {
				t.Errorf("error leaks a secret: %q", *exit.Error)
			}
			gotDelete := f.rec.has("DELETE " + egressctl.SessionsPath + testToken)
			if gotDelete != tc.wantDelete {
				t.Errorf("session closed = %v, want %v; calls: %v", gotDelete, tc.wantDelete, f.rec.list())
			}
			if tc.wantDelete && exit.Egress == nil {
				t.Error("egress stats are missing although the session was closed")
			}
			if !tc.wantDelete && exit.Egress != nil {
				t.Errorf("egress = %+v, want null when no session was opened", exit.Egress)
			}
			if n := f.mgr.Running(); n != 0 {
				t.Errorf("Running() = %d, want 0", n)
			}
		})
	}
}

func TestEgressIsNullWhenTheSessionCannotBeClosed(t *testing.T) {
	f := newFixture(t, nil)
	f.ctrl.set(func(c *controlServer) { c.deleteStatus = http.StatusInternalServerError })

	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)
	if exit.Egress != nil {
		t.Errorf("egress = %+v, want null", exit.Egress)
	}
	// The task itself still succeeded.
	if exit.ExitCode == nil || *exit.ExitCode != 0 || exit.Error != nil {
		t.Errorf("exit = %+v, want a clean run", exit)
	}
	if !f.rec.has("DELETE " + egressctl.SessionsPath + testToken) {
		t.Errorf("DELETE was not attempted: %v", f.rec.list())
	}
}

func TestRemovalFailureHidesTheExitCode(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.run = func(context.Context, dockerx.RunSpec, func(string, string)) (*int, error) {
		// dockerx reports both when the run succeeded but the clean-up did not.
		return ptr(0), errors.New("remove container: busy")
	}
	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)
	if exit.ExitCode != nil {
		t.Errorf("exitCode = %v, want null when anything failed", *exit.ExitCode)
	}
	if exit.Error == nil || !strings.Contains(*exit.Error, "remove container") {
		t.Errorf("error = %v", exit.Error)
	}
}

func TestLongErrorsAreShortened(t *testing.T) {
	f := newFixture(t, nil)
	f.dock.run = func(context.Context, dockerx.RunSpec, func(string, string)) (*int, error) {
		return nil, errors.New(strings.Repeat("x", 4096))
	}
	f.start(startFrame(nil))
	exit := f.out.onlyExit(t)
	if exit.Error == nil {
		t.Fatal("error is missing")
	}
	if len(*exit.Error) > maxErrorLen+3 {
		t.Errorf("error is %d characters, want at most %d", len(*exit.Error), maxErrorLen+3)
	}
}

func TestRunningCountsTasks(t *testing.T) {
	f := newFixture(t, nil)
	if n := f.mgr.Running(); n != 0 {
		t.Fatalf("Running() = %d, want 0", n)
	}
	release := make(chan struct{})
	f.dock.run = func(ctx context.Context, _ dockerx.RunSpec, _ func(string, string)) (*int, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return ptr(0), nil
	}
	f.start(startFrame(nil))
	waitFor(t, func() bool { return f.mgr.Running() == 1 })
	close(release)
	f.out.onlyExit(t)
	waitFor(t, func() bool { return f.mgr.Running() == 0 })
}

func TestConcurrentTasksEachGetOneExit(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxConcurrent = 4 })
	ids := []string{"p1", "p2", "p3", "p4"}
	for _, id := range ids {
		f.start(startFrame(map[string]any{"id": id}))
	}
	seen := map[string]int{}
	for range ids {
		seen[f.out.waitExit(t).ID]++
	}
	for _, id := range ids {
		if seen[id] != 1 {
			t.Errorf("task %s got %d agent.exit frames, want 1", id, seen[id])
		}
	}
	select {
	case extra := <-f.out.exitCh:
		t.Fatalf("a fifth agent.exit was sent: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestEgressSpecUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantToken string
		wantErr   bool
	}{
		{name: "token parsed", raw: `{"image":"i","network":"n","session":{"token":"t1"}}`, wantToken: "t1"},
		{name: "no session", raw: `{"image":"i","network":"n"}`},
		{name: "session without token", raw: `{"image":"i","network":"n","session":{"orgId":"o"}}`},
		{name: "token is not a string", raw: `{"image":"i","network":"n","session":{"token":1}}`, wantErr: true},
		{name: "session is not an object", raw: `{"image":"i","network":"n","session":7}`, wantErr: true},
		{name: "egress is not an object", raw: `[]`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var eg EgressSpec
			err := json.Unmarshal([]byte(tc.raw), &eg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("err = nil, want an error")
				}
				if strings.Contains(err.Error(), "token") {
					t.Errorf("error echoes the session: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if eg.Token != tc.wantToken {
				t.Errorf("token = %q, want %q", eg.Token, tc.wantToken)
			}
			if tc.wantToken != "" && !json.Valid(eg.Session) {
				t.Errorf("session = %q, want the raw body", eg.Session)
			}
		})
	}
}

func TestTokenIsNotReadFromTheFrame(t *testing.T) {
	// A "token" next to the session must not be mistaken for the session's.
	var eg EgressSpec
	raw := `{"image":"i","network":"n","token":"spoofed","session":{"token":"real"}}`
	if err := json.Unmarshal([]byte(raw), &eg); err != nil {
		t.Fatal(err)
	}
	if eg.Token != "real" {
		t.Errorf("token = %q, want the session's", eg.Token)
	}
}

func TestAllowedImage(t *testing.T) {
	tests := []struct {
		ref      string
		prefixes []string
		want     bool
	}{
		{ref: "ghcr.io/nvasion/x:1", prefixes: []string{"ghcr.io/nvasion/"}, want: true},
		{ref: "ghcr.io/nvasion-evil/x:1", prefixes: []string{"ghcr.io/nvasion/"}, want: false},
		{ref: "b:1", prefixes: []string{"a", "b"}, want: true},
		{ref: "", prefixes: []string{""}, want: false},
		{ref: "anything", prefixes: []string{""}, want: false},
		{ref: "anything", prefixes: nil, want: false},
	}
	for _, tc := range tests {
		if got := allowedImage(tc.ref, tc.prefixes); got != tc.want {
			t.Errorf("allowedImage(%q, %v) = %v, want %v", tc.ref, tc.prefixes, got, tc.want)
		}
	}
}

func TestTimeoutFor(t *testing.T) {
	tests := []struct {
		sec  *int
		want time.Duration
	}{
		{sec: nil, want: DefaultTimeoutSec * time.Second},
		{sec: ptr(0), want: DefaultTimeoutSec * time.Second},
		{sec: ptr(-1), want: DefaultTimeoutSec * time.Second},
		{sec: ptr(30), want: 30 * time.Second},
		// PROTOCOL.md 2.6: no clamp, agent time is the customer's own.
		{sec: ptr(1 << 20), want: (1 << 20) * time.Second},
	}
	for _, tc := range tests {
		if got := timeoutFor(tc.sec); got != tc.want {
			t.Errorf("timeoutFor(%v) = %s, want %s", tc.sec, got, tc.want)
		}
	}
}

// Control URL validation and redaction now live in internal/egressctl; see
// TestNewRejectsBadURLs and TestRedactURLDropsTheToken there. This test keeps
// the agentx-level integration: a closed control server must still fail
// without leaking the session token into the agent.exit error or the log.
func TestRedactURLDropsTheToken(t *testing.T) {
	f := newFixture(t, nil)
	// A closed server makes the control call fail with an *url.Error whose
	// URL holds the session token.
	f.ctrl.Close()
	f.start(startFrame(nil))

	exit := f.out.onlyExit(t)
	if exit.Error == nil {
		t.Fatal("error is missing")
	}
	if strings.Contains(*exit.Error, testToken) {
		t.Errorf("error leaks the session token: %q", *exit.Error)
	}
	if strings.Contains(f.logs.String(), testToken) {
		t.Errorf("the session token was logged: %s", f.logs.String())
	}
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not hold within 10s")
}
