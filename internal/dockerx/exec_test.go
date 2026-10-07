package dockerx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const testExecContainerID = "exec-container-0123456789"

// pidfileRe matches the pidfile path ExecStreaming generates for every exec.
var pidfileRe = regexp.MustCompile(`^/tmp/routini-exec-[0-9a-f]{32}\.pid$`)

// execFake wires a fakeAPI up for ExecStreaming. The attach stream is
// stream+tail followed by a clean EOF: tests that need the stream to stay
// open until some later event (a cancellation) set up their own hooks
// instead of using this default.
type execFake struct {
	api *fakeAPI

	stream []byte
	tail   []byte

	mu          sync.Mutex
	createCmds  [][]string
	execInspect func(execID string) (container.ExecInspect, error)
}

func newExecFake(t *testing.T) *execFake {
	t.Helper()
	f := &execFake{}
	execN := 0
	f.api = &fakeAPI{
		containerExecCreate: func(_ context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
			if id != testExecContainerID {
				t.Errorf("exec created in container %q, want %q", id, testExecContainerID)
			}
			f.mu.Lock()
			execN++
			n := execN
			f.createCmds = append(f.createCmds, opts.Cmd)
			f.mu.Unlock()
			return types.IDResponse{ID: fmt.Sprintf("exec-%d", n)}, nil
		},
		containerExecAttach: func(_ context.Context, execID string, _ container.ExecAttachOptions) (types.HijackedResponse, error) {
			srv, cli := net.Pipe()
			t.Cleanup(func() { srv.Close(); cli.Close() })
			r := io.MultiReader(bytes.NewReader(f.stream), bytes.NewReader(f.tail))
			return types.HijackedResponse{Conn: cli, Reader: bufio.NewReader(r)}, nil
		},
		containerExecStart: func(context.Context, string, container.ExecStartOptions) error {
			return nil
		},
		containerExecInspect: func(_ context.Context, execID string) (container.ExecInspect, error) {
			if f.execInspect != nil {
				return f.execInspect(execID)
			}
			return container.ExecInspect{ExitCode: 0}, nil
		},
	}
	return f
}

func (f *execFake) cmds() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.createCmds...)
}

func (f *execFake) run(ctx context.Context, spec ExecSpec) (*int, error, []string) {
	var lines []string
	code, err := (&dockerClient{api: f.api}).ExecStreaming(ctx, testExecContainerID, spec, func(stream, line string) {
		lines = append(lines, stream+":"+line)
	})
	return code, err, lines
}

func TestExecStreamingWrapperCmdAndPidfile(t *testing.T) {
	f := newExecFake(t)
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"echo", "hi"}})

	cmds := f.cmds()
	if len(cmds) != 1 {
		t.Fatalf("exec creates = %d, want 1", len(cmds))
	}
	cmd := cmds[0]
	if len(cmd) < 5 {
		t.Fatalf("Cmd = %v, too short", cmd)
	}
	if cmd[0] != "bash" || cmd[1] != "-c" || cmd[2] != execWrapperScript {
		t.Errorf("Cmd[0:3] = %v, want the bash wrapper", cmd[:3])
	}
	pidfile := cmd[3]
	if !pidfileRe.MatchString(pidfile) {
		t.Errorf("pidfile = %q, does not match %s", pidfile, pidfileRe)
	}
	if want := []string{"echo", "hi"}; !reflect.DeepEqual(cmd[4:], want) {
		t.Errorf("Cmd[4:] = %v, want the spec's command %v", cmd[4:], want)
	}
}

func TestExecStreamingPidfilesAreUnique(t *testing.T) {
	f := newExecFake(t)
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"true"}})
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"true"}})

	cmds := f.cmds()
	if len(cmds) != 2 {
		t.Fatalf("exec creates = %d, want 2", len(cmds))
	}
	if cmds[0][3] == cmds[1][3] {
		t.Errorf("two execs got the same pidfile %q", cmds[0][3])
	}
}

func TestExecStreamingDefaultsWorkdir(t *testing.T) {
	var got string
	f := newExecFake(t)
	create := f.api.containerExecCreate
	f.api.containerExecCreate = func(ctx context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
		got = opts.WorkingDir
		return create(ctx, id, opts)
	}
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"true"}})
	if got != workspaceDir {
		t.Errorf("WorkingDir = %q, want %q", got, workspaceDir)
	}
}

func TestExecStreamingUsesGivenWorkdir(t *testing.T) {
	var got string
	f := newExecFake(t)
	create := f.api.containerExecCreate
	f.api.containerExecCreate = func(ctx context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
		got = opts.WorkingDir
		return create(ctx, id, opts)
	}
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"true"}, Workdir: "/tmp/work"})
	if got != "/tmp/work" {
		t.Errorf("WorkingDir = %q, want %q", got, "/tmp/work")
	}
}

func TestExecStreamingUsesSpecEnv(t *testing.T) {
	var got []string
	f := newExecFake(t)
	create := f.api.containerExecCreate
	f.api.containerExecCreate = func(ctx context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
		got = opts.Env
		return create(ctx, id, opts)
	}
	_, _, _ = f.run(context.Background(), ExecSpec{Cmd: []string{"true"}, Env: map[string]string{"B": "2", "A": "1"}})
	if want := []string{"A=1", "B=2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Env = %v, want %v sorted by key", got, want)
	}
}

func TestExecStreamingDeliversLinesAndExitCode(t *testing.T) {
	f := newExecFake(t)
	f.stream = framed(t,
		outFrame{stdcopy.Stdout, "hello\n"},
		outFrame{stdcopy.Stderr, "oops\n"},
	)
	f.execInspect = func(string) (container.ExecInspect, error) {
		return container.ExecInspect{ExitCode: 7}, nil
	}

	code, err, lines := f.run(context.Background(), ExecSpec{Cmd: []string{"sh"}})
	if err != nil {
		t.Fatalf("ExecStreaming: %v", err)
	}
	if code == nil || *code != 7 {
		t.Fatalf("exitCode = %v, want 7", code)
	}
	want := []string{"stdout:hello", "stderr:oops"}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}
}

func TestExecStreamingOnCancelKillsTreeAndReturnsNilExitCode(t *testing.T) {
	f := newExecFake(t)
	// The main exec's stream only ends once the kill exec's start closes
	// daemonSide, so cancellation is the only thing that can end this test.
	daemonSide, clientSide := net.Pipe()
	t.Cleanup(func() { daemonSide.Close(); clientSide.Close() })

	var killStarted bool
	f.api.containerExecAttach = func(_ context.Context, execID string, _ container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.HijackedResponse{Conn: clientSide, Reader: bufio.NewReader(clientSide)}, nil
	}
	f.api.containerExecStart = func(context.Context, string, container.ExecStartOptions) error {
		killStarted = true
		daemonSide.Close() // ends the main exec's stream, as the real kill would
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel once the first exec is attached, i.e. once ExecStreaming is
	// blocked reading its stream.
	orig := f.api.containerExecAttach
	f.api.containerExecAttach = func(c context.Context, execID string, opts container.ExecAttachOptions) (types.HijackedResponse, error) {
		att, err := orig(c, execID, opts)
		go cancel()
		return att, err
	}

	code, err, _ := f.run(ctx, ExecSpec{Cmd: []string{"sleep", "100"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to wrap context.Canceled", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil after cancellation", *code)
	}
	if !killStarted {
		t.Error("want the kill-tree exec to have been started")
	}

	cmds := f.cmds()
	if len(cmds) != 2 {
		t.Fatalf("exec creates = %d, want 2 (the command, then the kill)", len(cmds))
	}
	killCmd := cmds[1]
	if want := []string{"bash", "-c", killTreeScript}; !reflect.DeepEqual(killCmd[:3], want) {
		t.Errorf("kill Cmd[0:3] = %v, want %v", killCmd[:3], want)
	}
	// The kill exec's pidfile argument must match the first exec's.
	if killCmd[3] != cmds[0][3] {
		t.Errorf("kill pidfile = %q, want the original exec's pidfile %q", killCmd[3], cmds[0][3])
	}
}

func TestExecStreamingRejectsBadEnv(t *testing.T) {
	api := &fakeAPI{} // no hooks: any daemon call fails the test
	code, err := (&dockerClient{api: api}).ExecStreaming(context.Background(), testExecContainerID,
		ExecSpec{Cmd: []string{"true"}, Env: map[string]string{"1BAD": "x"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid env key") {
		t.Fatalf("got %v, want a validation error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
	if len(api.log()) != 0 {
		t.Errorf("calls = %v, want none before validation passes", api.log())
	}
}

func TestExecStreamingRejectsBadContainerID(t *testing.T) {
	api := &fakeAPI{}
	code, err := (&dockerClient{api: api}).ExecStreaming(context.Background(), "../escape", ExecSpec{Cmd: []string{"true"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid container id") {
		t.Fatalf("got %v, want a validation error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
}

func TestExecTTY(t *testing.T) {
	var resized container.ResizeOptions
	daemonSide, clientSide := net.Pipe()
	t.Cleanup(func() { daemonSide.Close(); clientSide.Close() })

	api := &fakeAPI{
		containerExecCreate: func(_ context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
			if id != testExecContainerID {
				t.Errorf("exec created in container %q, want %q", id, testExecContainerID)
			}
			if want := []string{"bash", "-l"}; !reflect.DeepEqual(opts.Cmd, want) {
				t.Errorf("Cmd = %v, want %v", opts.Cmd, want)
			}
			if !opts.Tty {
				t.Error("Tty = false, want true")
			}
			if opts.User != DefaultUser {
				t.Errorf("User = %q, want %q", opts.User, DefaultUser)
			}
			if opts.WorkingDir != workspaceDir {
				t.Errorf("WorkingDir = %q, want %q", opts.WorkingDir, workspaceDir)
			}
			want := []string{"TERM=xterm-256color", "LANG=C.UTF-8"}
			if !reflect.DeepEqual(opts.Env, want) {
				t.Errorf("Env = %v, want %v", opts.Env, want)
			}
			return types.IDResponse{ID: "tty-exec"}, nil
		},
		containerExecAttach: func(_ context.Context, execID string, opts container.ExecAttachOptions) (types.HijackedResponse, error) {
			if !opts.Tty {
				t.Error("attach Tty = false, want true")
			}
			return types.HijackedResponse{Conn: clientSide, Reader: bufio.NewReader(clientSide)}, nil
		},
		containerExecResize: func(_ context.Context, execID string, opts container.ResizeOptions) error {
			resized = opts
			return nil
		},
		containerExecInspect: func(context.Context, string) (container.ExecInspect, error) {
			return container.ExecInspect{ExitCode: 9}, nil
		},
	}

	tty, err := (&dockerClient{api: api}).ExecTTY(context.Background(), testExecContainerID, 80, 24)
	if err != nil {
		t.Fatalf("ExecTTY: %v", err)
	}
	if resized.Width != 80 || resized.Height != 24 {
		t.Errorf("resize = %+v, want width 80 height 24", resized)
	}

	done := make(chan struct{})
	var code *int
	go func() {
		code, _ = tty.Wait()
		close(done)
	}()
	tty.Close()
	<-done
	if code == nil || *code != 9 {
		t.Errorf("exit code = %v, want 9", code)
	}
}

func TestExecTTYRejectsBadContainerID(t *testing.T) {
	api := &fakeAPI{}
	if _, err := (&dockerClient{api: api}).ExecTTY(context.Background(), "../escape", 80, 24); err == nil {
		t.Fatal("want a validation error")
	}
}

func TestExecTTYAttachError(t *testing.T) {
	api := &fakeAPI{
		containerExecCreate: func(context.Context, string, container.ExecOptions) (types.IDResponse, error) {
			return types.IDResponse{ID: "tty-exec"}, nil
		},
		containerExecAttach: func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
			return types.HijackedResponse{}, errors.New("hijack refused")
		},
	}
	if _, err := (&dockerClient{api: api}).ExecTTY(context.Background(), testExecContainerID, 80, 24); err == nil || !strings.Contains(err.Error(), "attach exec") {
		t.Fatalf("got %v, want a wrapped attach error", err)
	}
}

func TestExecTTYResizeErrorClosesSession(t *testing.T) {
	daemonSide, clientSide := net.Pipe()
	t.Cleanup(func() { daemonSide.Close(); clientSide.Close() })
	api := &fakeAPI{
		containerExecCreate: func(context.Context, string, container.ExecOptions) (types.IDResponse, error) {
			return types.IDResponse{ID: "tty-exec"}, nil
		},
		containerExecAttach: func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
			return types.HijackedResponse{Conn: clientSide, Reader: bufio.NewReader(clientSide)}, nil
		},
		containerExecResize: func(context.Context, string, container.ResizeOptions) error {
			return errors.New("no such exec")
		},
	}
	if _, err := (&dockerClient{api: api}).ExecTTY(context.Background(), testExecContainerID, 80, 24); err == nil || !strings.Contains(err.Error(), "resize exec") {
		t.Fatalf("got %v, want a wrapped resize error", err)
	}
}

func TestExecTTYReadWriteAndNaturalEOF(t *testing.T) {
	daemonSide, clientSide := net.Pipe()
	t.Cleanup(func() { daemonSide.Close(); clientSide.Close() })
	var written []byte
	go func() {
		buf := make([]byte, 64)
		n, _ := daemonSide.Read(buf)
		written = buf[:n]
		daemonSide.Write([]byte("echo"))
		daemonSide.Close() // the session ending on its own, not via Close
	}()

	api := &fakeAPI{
		containerExecCreate: func(context.Context, string, container.ExecOptions) (types.IDResponse, error) {
			return types.IDResponse{ID: "tty-exec"}, nil
		},
		containerExecAttach: func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
			return types.HijackedResponse{Conn: clientSide, Reader: bufio.NewReader(clientSide)}, nil
		},
		containerExecResize: func(context.Context, string, container.ResizeOptions) error { return nil },
		containerExecInspect: func(context.Context, string) (container.ExecInspect, error) {
			return container.ExecInspect{ExitCode: 3}, nil
		},
	}
	tty, err := (&dockerClient{api: api}).ExecTTY(context.Background(), testExecContainerID, 80, 24)
	if err != nil {
		t.Fatalf("ExecTTY: %v", err)
	}

	if _, err := tty.Write([]byte("hi")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := tty.Read(buf) // the echoed reply
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "echo" {
		t.Errorf("Read = %q, want %q", got, "echo")
	}
	if got := string(written); got != "hi" {
		t.Errorf("daemon saw %q, want %q", got, "hi")
	}

	// The next Read hits EOF because daemonSide closed, which must unblock
	// Wait without an explicit Close.
	if _, err := tty.Read(buf); err == nil {
		t.Fatal("want the second Read to report the session ending")
	}
	code, err := tty.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code == nil || *code != 3 {
		t.Errorf("exit code = %v, want 3", code)
	}
}

func TestExecStreamingAttachError(t *testing.T) {
	f := newExecFake(t)
	f.api.containerExecAttach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.HijackedResponse{}, errors.New("hijack refused")
	}
	code, err, _ := f.run(context.Background(), ExecSpec{Cmd: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "attach exec") {
		t.Fatalf("got %v, want a wrapped attach error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
}

func TestExecStreamingCreateError(t *testing.T) {
	api := &fakeAPI{
		containerExecCreate: func(context.Context, string, container.ExecOptions) (types.IDResponse, error) {
			return types.IDResponse{}, errors.New("no such container")
		},
	}
	code, err := (&dockerClient{api: api}).ExecStreaming(context.Background(), testExecContainerID, ExecSpec{Cmd: []string{"true"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "create exec") {
		t.Fatalf("got %v, want a wrapped create error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
}

func TestExecStreamingExecInspectError(t *testing.T) {
	f := newExecFake(t)
	f.execInspect = func(string) (container.ExecInspect, error) {
		return container.ExecInspect{}, errors.New("no such exec")
	}
	code, err, _ := f.run(context.Background(), ExecSpec{Cmd: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "inspect exec") {
		t.Fatalf("got %v, want a wrapped inspect error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
}
