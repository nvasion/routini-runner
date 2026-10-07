package dockerx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

// execWrapperScript records the exec's own pid in the file named by $0
// before replacing itself with the real command ($@). ExecStreaming uses the
// pidfile to find the whole process tree to kill on cancellation.
const execWrapperScript = `echo $$ > "$0"; "$@"`

// killTreeScript kills the process tree rooted at the pid recorded in the
// pidfile named by $0: SIGTERM, a 2s grace period, then SIGKILL. A missing
// pidfile (the wrapper never got to write it) is not an error.
const killTreeScript = `tree() { for c in $(cat /proc/$1/task/*/children 2>/dev/null); do tree $c; done; echo $1; }
root=$(cat "$0" 2>/dev/null) || exit 0
pids=$(tree $root)
kill -TERM $pids 2>/dev/null; sleep 2; kill -KILL $pids 2>/dev/null; true`

// resizeTimeout bounds a TTY resize call, which otherwise shares the hijacked
// exec's own context in name only: the session may outlive any one request.
const resizeTimeout = 5 * time.Second

// ExecStreaming runs one command inside an environment container, streaming
// its output line by line exactly like RunStreaming. When ctx is cancelled
// before the command ends, the command's whole process tree is killed and a
// nil exit code is returned; otherwise the command's own exit code, read
// back with ContainerExecInspect, is returned.
func (d *dockerClient) ExecStreaming(ctx context.Context, id string, spec ExecSpec, onLine func(stream, line string)) (*int, error) {
	if err := validateName("container id", id); err != nil {
		return nil, err
	}
	if err := validateEnv(spec.Env); err != nil {
		return nil, err
	}
	if onLine == nil {
		onLine = func(string, string) {}
	}

	workdir := spec.Workdir
	if workdir == "" {
		workdir = workspaceDir
	}
	pidfile := pidfilePath()
	cmd := append([]string{"bash", "-c", execWrapperScript, pidfile}, spec.Cmd...)

	execID, err := d.createExec(ctx, id, container.ExecOptions{
		User:         DefaultUser,
		WorkingDir:   workdir,
		Env:          envSlice(spec.Env),
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, err
	}

	att, err := d.api.ContainerExecAttach(ctx, execID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("dockerx: attach exec in container %s: %w", shortID(id), err)
	}
	defer att.Close()

	stdout := newLineWriter(func(line string) { onLine("stdout", line) })
	stderr := newLineWriter(func(line string) { onLine("stderr", line) })
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := stdcopy.StdCopy(stdout, stderr, att.Reader)
		copyDone <- copyErr
	}()

	var copyErr error
	select {
	case copyErr = <-copyDone:
	case <-ctx.Done():
		d.killExecTree(id, pidfile)
		att.Close() // unblocks StdCopy if the stream is still open
		copyErr = <-copyDone
	}
	stdout.Flush()
	stderr.Flush()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("dockerx: exec in container %s: %w", shortID(id), ctxErr)
	}
	if copyErr != nil {
		return nil, fmt.Errorf("dockerx: stream exec output in container %s: %w", shortID(id), copyErr)
	}
	return d.execExitCode(ctx, execID)
}

// killExecTree best-effort kills the process tree the wrapper script
// recorded in pidfile, on a fresh context since ctx (ExecStreaming's) is
// already done. Its outcome is deliberately not reported, the same way
// stopBestEffort's is not in run.go: ExecStreaming always hands the caller a
// nil exit code once it is cancelled, regardless of whether the kill
// actually lands.
func (d *dockerClient) killExecTree(id, pidfile string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	execID, err := d.createExec(ctx, id, container.ExecOptions{
		User: DefaultUser,
		Cmd:  []string{"bash", "-c", killTreeScript, pidfile},
	})
	if err != nil {
		return
	}
	_ = d.api.ContainerExecStart(ctx, execID, container.ExecStartOptions{Detach: true})
}

// ExecTTY starts an interactive login shell inside an environment container,
// sized to cols by rows.
func (d *dockerClient) ExecTTY(ctx context.Context, id string, cols, rows uint) (TTY, error) {
	if err := validateName("container id", id); err != nil {
		return nil, err
	}
	execID, err := d.createExec(ctx, id, container.ExecOptions{
		Cmd:          []string{"bash", "-l"},
		Env:          []string{"TERM=xterm-256color", "LANG=C.UTF-8"},
		User:         DefaultUser,
		WorkingDir:   workspaceDir,
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, err
	}
	att, err := d.api.ContainerExecAttach(ctx, execID, container.ExecAttachOptions{Tty: true})
	if err != nil {
		return nil, fmt.Errorf("dockerx: attach exec in container %s: %w", shortID(id), err)
	}
	tty := newExecTTY(d, execID, att)
	if err := tty.Resize(cols, rows); err != nil {
		tty.Close()
		return nil, fmt.Errorf("dockerx: resize exec in container %s: %w", shortID(id), err)
	}
	return tty, nil
}

// createExec creates one exec instance in container id and returns its id.
func (d *dockerClient) createExec(ctx context.Context, id string, opts container.ExecOptions) (string, error) {
	resp, err := d.api.ContainerExecCreate(ctx, id, opts)
	if err != nil {
		return "", fmt.Errorf("dockerx: create exec in container %s: %w", shortID(id), err)
	}
	return resp.ID, nil
}

// execExitCode reads an exec's exit code back from the daemon.
func (d *dockerClient) execExitCode(ctx context.Context, execID string) (*int, error) {
	info, err := d.api.ContainerExecInspect(ctx, execID)
	if err != nil {
		return nil, fmt.Errorf("dockerx: inspect exec: %w", err)
	}
	code := info.ExitCode
	return &code, nil
}

// pidfilePath returns a pidfile path with a random name, so that concurrent
// execs in the same container never collide.
func pidfilePath() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing would mean the host's entropy source is
		// broken; a fixed name still lets the exec run, just without the
		// collision guarantee.
		return "/tmp/routini-exec-0.pid"
	}
	return "/tmp/routini-exec-" + hex.EncodeToString(buf) + ".pid"
}

// execTTY implements TTY on top of one hijacked exec connection.
type execTTY struct {
	d      *dockerClient
	execID string
	att    types.HijackedResponse

	once sync.Once
	done chan struct{}
}

func newExecTTY(d *dockerClient, execID string, att types.HijackedResponse) *execTTY {
	return &execTTY{d: d, execID: execID, att: att, done: make(chan struct{})}
}

// Read reports EOF (or any other error) as the session ending, which is what
// unblocks Wait.
func (t *execTTY) Read(p []byte) (int, error) {
	n, err := t.att.Reader.Read(p)
	if err != nil {
		t.markDone()
	}
	return n, err
}

func (t *execTTY) Write(p []byte) (int, error) {
	return t.att.Conn.Write(p)
}

func (t *execTTY) Close() error {
	t.markDone()
	t.att.Close()
	return nil
}

func (t *execTTY) Resize(cols, rows uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), resizeTimeout)
	defer cancel()
	if err := t.d.api.ContainerExecResize(ctx, t.execID, container.ResizeOptions{Height: rows, Width: cols}); err != nil {
		return fmt.Errorf("dockerx: resize exec: %w", err)
	}
	return nil
}

// Wait blocks until the session's stream ends (a read error, including a
// plain EOF, or Close) and then reports its exit code.
func (t *execTTY) Wait() (*int, error) {
	<-t.done
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	return t.d.execExitCode(ctx, t.execID)
}

func (t *execTTY) markDone() {
	t.once.Do(func() { close(t.done) })
}
