package dockerx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/pkg/stdcopy"
)

const testContainerID = "run-id-0123456789"

// outFrame is one chunk of container output on a given stream.
type outFrame struct {
	fd   stdcopy.StdType
	data string
}

// framed renders frames the way the Engine API multiplexes an attached
// container's stdout and stderr.
func framed(t *testing.T, frames ...outFrame) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, fr := range frames {
		if _, err := stdcopy.NewStdWriter(&buf, fr.fd).Write([]byte(fr.data)); err != nil {
			t.Fatalf("frame %q: %v", fr.data, err)
		}
	}
	return buf.Bytes()
}

// errReader fails on every read, standing in for a broken attach stream.
type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

// runFake wires a fakeAPI up for RunStreaming. Tests replace the hooks they
// care about before calling run.
type runFake struct {
	api *fakeAPI

	// stream is what the attached container "writes"; it is followed by tail,
	// which lets a test keep the stream open or break it.
	stream []byte
	tail   io.Reader

	removeErr error
	removed   []string
	stopped   []string

	waitCh chan container.WaitResponse
	errCh  chan error
}

func newRunFake(t *testing.T) *runFake {
	t.Helper()
	f := &runFake{
		waitCh: make(chan container.WaitResponse, 1),
		errCh:  make(chan error, 1),
	}
	// A pipe gives the attach response a real net.Conn, so closing it unblocks
	// the reader exactly as it does against a daemon.
	daemonSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		daemonSide.Close()
		clientSide.Close()
	})
	f.tail = clientSide

	f.api = &fakeAPI{
		containerCreate: func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{ID: testContainerID}, nil
		},
		containerAttach: func(_ context.Context, _ string, opts container.AttachOptions) (types.HijackedResponse, error) {
			if !opts.Stream || !opts.Stdout || !opts.Stderr {
				t.Errorf("attach options = %+v, want a stdout and stderr stream", opts)
			}
			if opts.Stdin {
				t.Error("stdin must not be attached")
			}
			r := io.MultiReader(bytes.NewReader(f.stream), f.tail)
			return types.HijackedResponse{Conn: clientSide, Reader: bufio.NewReader(r)}, nil
		},
		containerWait: func(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
			return f.waitCh, f.errCh
		},
		containerStart: noopStart,
		containerStop: func(_ context.Context, id string, _ container.StopOptions) error {
			f.stopped = append(f.stopped, id)
			return nil
		},
		containerRemove: func(_ context.Context, id string, opts container.RemoveOptions) error {
			if !opts.Force {
				t.Error("the container must be force-removed")
			}
			f.removed = append(f.removed, id)
			return f.removeErr
		},
	}
	return f
}

// run calls RunStreaming and returns the exit code, the error and the lines.
func (f *runFake) run(ctx context.Context, spec RunSpec) (*int, error, []string) {
	var lines []string
	code, err := (&dockerClient{api: f.api}).RunStreaming(ctx, spec, func(stream, line string) {
		lines = append(lines, stream+":"+line)
	})
	return code, err, lines
}

// closeStream ends the attach stream, which is what a container's exit does.
func (f *runFake) closeStream() { f.tail = strings.NewReader("") }

func TestRunStreamingDeliversLinesAndExitCode(t *testing.T) {
	f := newRunFake(t)
	f.stream = framed(t,
		outFrame{stdcopy.Stdout, "hello\nworld\n"},
		outFrame{stdcopy.Stderr, "oops\r\n"},
		outFrame{stdcopy.Stdout, "tail without newline"},
	)
	f.closeStream()
	f.waitCh <- container.WaitResponse{StatusCode: 3}

	code, err, lines := f.run(context.Background(), validSpec())
	if err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	if code == nil || *code != 3 {
		t.Fatalf("exitCode = %v, want 3", code)
	}
	want := []string{"stdout:hello", "stdout:world", "stderr:oops", "stdout:tail without newline"}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}
	if !reflect.DeepEqual(f.removed, []string{testContainerID}) {
		t.Errorf("removed = %v, want the container removed exactly once", f.removed)
	}
}

func TestRunStreamingCreateOrder(t *testing.T) {
	f := newRunFake(t)
	f.closeStream()
	f.waitCh <- container.WaitResponse{StatusCode: 0}

	if _, err, _ := f.run(context.Background(), validSpec()); err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	want := []string{
		"ContainerCreate(routini-agent-task)",
		"ContainerAttach(" + testContainerID + ")",
		"ContainerWait(" + testContainerID + ",next-exit)",
		"ContainerStart(" + testContainerID + ")",
		"ContainerRemove(" + testContainerID + ",force=true,volumes=false)",
	}
	if got := f.api.log(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestRunStreamingWithoutCallback(t *testing.T) {
	f := newRunFake(t)
	f.stream = framed(t, outFrame{stdcopy.Stdout, "ignored\n"})
	f.closeStream()
	f.waitCh <- container.WaitResponse{StatusCode: 0}

	code, err := (&dockerClient{api: f.api}).RunStreaming(context.Background(), validSpec(), nil)
	if err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	if code == nil || *code != 0 {
		t.Fatalf("exitCode = %v, want 0", code)
	}
}

func TestRunStreamingReportsRemovalFailure(t *testing.T) {
	f := newRunFake(t)
	f.closeStream()
	f.removeErr = errors.New("device busy")
	f.waitCh <- container.WaitResponse{StatusCode: 0}

	code, err, _ := f.run(context.Background(), validSpec())
	if code == nil || *code != 0 {
		t.Errorf("exitCode = %v, want the run's own result", code)
	}
	if err == nil {
		t.Fatal("a container that could not be removed must be reported")
	}
	if !strings.Contains(err.Error(), "remove container") || !strings.Contains(err.Error(), "device busy") {
		t.Errorf("error %q does not describe the removal failure", err)
	}
}

func TestRunStreamingRemovesOnEveryFailure(t *testing.T) {
	cases := []struct {
		name    string
		break_  func(f *runFake)
		wantErr string
	}{
		{
			name: "attach fails",
			break_: func(f *runFake) {
				f.api.containerAttach = func(context.Context, string, container.AttachOptions) (types.HijackedResponse, error) {
					return types.HijackedResponse{}, errors.New("hijack refused")
				}
			},
			wantErr: "attach to container",
		},
		{
			name: "start fails",
			break_: func(f *runFake) {
				f.api.containerStart = func(context.Context, string, container.StartOptions) error {
					return errors.New("no such runtime")
				}
			},
			wantErr: "start container",
		},
		{
			name: "the wait fails",
			break_: func(f *runFake) {
				f.closeStream()
				f.errCh <- errors.New("daemon gone")
			},
			wantErr: "wait for container",
		},
		{
			name: "the daemon reports a run failure",
			break_: func(f *runFake) {
				f.closeStream()
				f.waitCh <- container.WaitResponse{
					Error: &container.WaitExitError{Message: "oom killed"},
				}
			},
			wantErr: "oom killed",
		},
		{
			name: "the stream breaks",
			break_: func(f *runFake) {
				f.tail = &errReader{err: errors.New("connection reset")}
			},
			wantErr: "stream output of container",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRunFake(t)
			tc.break_(f)

			code, err, _ := f.run(context.Background(), validSpec())
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
			if code != nil {
				t.Errorf("exitCode = %d, want nil on failure", *code)
			}
			if !reflect.DeepEqual(f.removed, []string{testContainerID}) {
				t.Errorf("removed = %v, want the container removed anyway", f.removed)
			}
		})
	}
}

func TestRunStreamingCreateFailureRemovesNothing(t *testing.T) {
	f := newRunFake(t)
	f.api.containerCreate = func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
		return container.CreateResponse{}, errors.New("name taken")
	}

	code, err, _ := f.run(context.Background(), validSpec())
	if err == nil || !strings.Contains(err.Error(), "create container") {
		t.Fatalf("got %v, want a wrapped create error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
	if len(f.removed) != 0 {
		t.Errorf("removed = %v, want nothing: no container was created", f.removed)
	}
}

func TestRunStreamingOnCancel(t *testing.T) {
	f := newRunFake(t)
	// A line without its newline is buffered when the cancellation lands; it
	// must still reach the callback.
	f.stream = framed(t, outFrame{stdcopy.Stdout, "partial"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.api.containerStart = func(context.Context, string, container.StartOptions) error {
		cancel() // the caller gives up while the container is running
		return nil
	}

	code, err, lines := f.run(ctx, validSpec())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to wrap context.Canceled", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil after cancellation", *code)
	}
	if want := []string{"stdout:partial"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q flushed before returning", lines, want)
	}
	if !reflect.DeepEqual(f.stopped, []string{testContainerID}) {
		t.Errorf("stopped = %v, want a graceful stop attempt", f.stopped)
	}
	if !reflect.DeepEqual(f.removed, []string{testContainerID}) {
		t.Errorf("removed = %v, want the container removed on cancellation", f.removed)
	}
}

func TestRunStreamingRejectsBadSpec(t *testing.T) {
	f := &fakeAPI{} // no hooks: any daemon call fails the test
	spec := validSpec()
	spec.Name = "../escape"

	code, err := (&dockerClient{api: f}).RunStreaming(context.Background(), spec, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid container name") {
		t.Fatalf("got %v, want a validation error", err)
	}
	if code != nil {
		t.Errorf("exitCode = %d, want nil", *code)
	}
	if len(f.log()) != 0 {
		t.Errorf("calls = %v, want none before validation passes", f.log())
	}
}
