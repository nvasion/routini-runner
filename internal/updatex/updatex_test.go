package updatex

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExec records invocations and answers from a script.
type fakeExec struct {
	mu    sync.Mutex
	calls [][]string
	out   map[string]string // last arg -> output
	err   map[string]error
	hold  chan struct{}
}

func (f *fakeExec) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{name}, args...))
	f.mu.Unlock()
	last := args[len(args)-1]
	if f.hold != nil && last != "--check" {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []byte(f.out[last]), f.err[last]
}

func (f *fakeExec) callList() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

func helperFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "routini-runner-update")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// collect returns a send func and a way to wait for its single result.
func collect(t *testing.T) (func(any), func() ResultMsg) {
	t.Helper()
	ch := make(chan ResultMsg, 4)
	send := func(v any) { ch <- v.(ResultMsg) }
	wait := func() ResultMsg {
		t.Helper()
		select {
		case r := <-ch:
			select {
			case extra := <-ch:
				t.Fatalf("a second result was sent: %+v", extra)
			case <-time.After(50 * time.Millisecond):
			}
			return r
		case <-time.After(2 * time.Second):
			t.Fatal("no result")
			return ResultMsg{}
		}
	}
	return send, wait
}

func TestValidTag(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.3.0": true, "v10.20.30": true,
		"0.3.0": false, "v0.3": false, "v0.3.0-rc1": false, "v0.3.0 --enable-agents": false,
		"--enable-agents": false, "v0.3.0;reboot": false, "": false,
	} {
		if got := ValidTag(v); got != want {
			t.Errorf("ValidTag(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAvailable(t *testing.T) {
	helper := helperFile(t)
	tests := []struct {
		name   string
		helper string
		out    string
		err    error
		want   bool
	}{
		{"helper answers ok", helper, "ok\n", nil, true},
		{"sudo needs a password", helper, "sudo: a password is required", errors.New("exit status 1"), false},
		{"unexpected output", helper, "maybe", nil, false},
		{"helper not installed", filepath.Join(t.TempDir(), "missing"), "ok", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExec{out: map[string]string{"--check": tc.out}, err: map[string]error{"--check": tc.err}}
			u := New(Options{Helper: tc.helper, Exec: f.exec})
			if got := u.Available(context.Background()); got != tc.want {
				t.Errorf("Available = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStartRunsTheHelperThroughSudo(t *testing.T) {
	helper := helperFile(t)
	f := &fakeExec{out: map[string]string{"v0.3.0": "checksum verified\ninstalled routini-runner 0.3.0\nrestart queued\n"}}
	u := New(Options{Helper: helper, Current: "0.2.0", Exec: f.exec})
	send, wait := collect(t)

	u.Start(true, Msg{ID: "u1", Version: "v0.3.0"}, send)
	r := wait()

	if !r.OK || r.Error != nil || r.Type != "runner.update.result" || r.ID != "u1" || r.Version != "v0.3.0" {
		t.Fatalf("result = %+v", r)
	}
	if !strings.HasSuffix(r.Output, "restart queued") {
		t.Errorf("output = %q", r.Output)
	}
	want := [][]string{{"sudo", "-n", helper, "v0.3.0"}}
	if got := f.callList(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestStartReportsHelperFailure(t *testing.T) {
	f := &fakeExec{
		out: map[string]string{"v0.3.0": "error: checksum mismatch for routini-runner_0.3.0_linux_amd64.tar.gz"},
		err: map[string]error{"v0.3.0": errors.New("exit status 1")},
	}
	u := New(Options{Helper: helperFile(t), Current: "0.2.0", Exec: f.exec})
	send, wait := collect(t)

	u.Start(true, Msg{ID: "u2", Version: "v0.3.0"}, send)
	r := wait()

	if r.OK || r.Error == nil || !strings.Contains(*r.Error, "update to v0.3.0 failed") {
		t.Fatalf("result = %+v", r)
	}
	if !strings.Contains(r.Output, "checksum mismatch") {
		t.Errorf("output = %q, want the helper's message", r.Output)
	}
}

func TestStartRefusals(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		version string
		want    string
	}{
		{"updates not enabled", false, "v0.3.0", ErrDisabled},
		{"not a tag", true, "latest", ErrVersion},
		{"argument injection", true, "v0.3.0 --enable-agents", ErrVersion},
		{"same version", true, "v0.2.0", "already running v0.2.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExec{}
			u := New(Options{Helper: helperFile(t), Current: "0.2.0", Exec: f.exec})
			send, wait := collect(t)

			u.Start(tc.enabled, Msg{ID: "u3", Version: tc.version}, send)
			r := wait()

			if r.OK || r.Error == nil || *r.Error != tc.want {
				t.Errorf("result = %+v, want error %q", r, tc.want)
			}
			if calls := f.callList(); len(calls) != 0 {
				t.Errorf("the helper ran: %v", calls)
			}
		})
	}
}

func TestStartRunsOneUpdateAtATime(t *testing.T) {
	f := &fakeExec{hold: make(chan struct{}), out: map[string]string{"v0.3.0": "ok"}}
	u := New(Options{Helper: helperFile(t), Current: "0.2.0", Exec: f.exec})
	firstSend, firstWait := collect(t)
	secondSend, secondWait := collect(t)

	u.Start(true, Msg{ID: "first", Version: "v0.3.0"}, firstSend)
	deadline := time.Now().Add(2 * time.Second)
	for len(f.callList()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	u.Start(true, Msg{ID: "second", Version: "v0.3.0"}, secondSend)
	if r := secondWait(); r.OK || r.Error == nil || *r.Error != ErrBusy {
		t.Errorf("second = %+v, want %q", r, ErrBusy)
	}
	close(f.hold)
	if r := firstWait(); !r.OK {
		t.Errorf("first = %+v, want ok", r)
	}
}

func TestOutputIsTrimmedToTheEnd(t *testing.T) {
	long := strings.Repeat("x", maxOutput) + "\nfinal line"
	if got := lastBytes([]byte(long), maxOutput); len(got) > maxOutput || !strings.HasSuffix(got, "final line") {
		t.Errorf("lastBytes kept %d bytes ending %q", len(got), got[len(got)-10:])
	}
}
