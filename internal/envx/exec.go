package envx

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
)

type stopReason int

const (
	notStopped stopReason = iota
	stopCanceled
	stopTimedOut
)

// execJob is one running exec op, tracked so Cancel can find it and
// Disconnect can silence it.
type execJob struct {
	id     string
	send   SendFunc
	cancel context.CancelFunc

	// silent is set when the connection drops: nothing more is sent for
	// this op, the same way execx and agentx silence an aborted job.
	silent atomic.Bool

	mu     sync.Mutex
	reason stopReason
}

func (j *execJob) sendMsg(v any) {
	if !j.silent.Load() {
		j.send(v)
	}
}

// stop records why the op is being stopped (the first reason wins) and
// cancels its context, which makes dockerx kill the command's process tree.
func (j *execJob) stop(r stopReason) {
	j.mu.Lock()
	if j.reason == notStopped {
		j.reason = r
	}
	j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
}

func (j *execJob) getReason() stopReason {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.reason
}

func (m *Manager) addExec(j *execJob) {
	m.mu.Lock()
	m.execs[j.id] = j
	m.mu.Unlock()
}

func (m *Manager) removeExec(id string) {
	m.mu.Lock()
	delete(m.execs, id)
	m.mu.Unlock()
}

func (m *Manager) execSnapshot() []*execJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*execJob, 0, len(m.execs))
	for _, j := range m.execs {
		out = append(out, j)
	}
	return out
}

// Cancel handles env.cancel. It only has an effect on a running exec op
// (PROTOCOL.md 2.8); unknown ids are ignored.
func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	j := m.execs[id]
	m.mu.Unlock()
	if j == nil {
		return
	}
	m.logf("env exec %s: cancel requested", id)
	j.stop(stopCanceled)
}

// runExec handles the exec op: it streams env.output per line and always
// sends exactly one env.done. A timeout or env.cancel kills the command's
// process tree the same way exec.start does (PROTOCOL.md 2.3 and 2.8);
// exitCode is then null and timedOut or canceled is set. ok is true
// whenever the command ran at all, whatever its own exit code.
func (m *Manager) runExec(msg OpMsg, send SendFunc) {
	var a struct {
		ContainerID string            `json:"containerId"`
		Cmd         []string          `json:"cmd"`
		Env         map[string]string `json:"env"`
		Workdir     string            `json:"workdir"`
		TimeoutSec  *int              `json:"timeoutSec"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}

	checkCtx, cancelCheck := context.WithTimeout(context.Background(), quickOpTimeout)
	info, err := m.docker().InspectEnv(checkCtx, a.ContainerID)
	cancelCheck()
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if !info.Managed {
		send(doneErr(msg.ID, ErrContainerMissing))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &execJob{id: msg.ID, send: send, cancel: cancel}
	m.addExec(job)
	defer m.removeExec(msg.ID)

	timeoutSec := DefaultTimeoutSec
	if a.TimeoutSec != nil && *a.TimeoutSec > 0 {
		timeoutSec = *a.TimeoutSec
	}
	timer := time.AfterFunc(time.Duration(timeoutSec)*time.Second, func() { job.stop(stopTimedOut) })
	defer timer.Stop()

	spec := dockerx.ExecSpec{Cmd: a.Cmd, Env: a.Env, Workdir: a.Workdir}
	code, runErr := m.docker().ExecStreaming(ctx, a.ContainerID, spec, func(stream, line string) {
		job.sendMsg(OutputMsg{Type: TypeOutput, ID: msg.ID, Stream: stream, Data: line})
	})
	cancel()

	done := DoneMsg{Type: TypeDone, ID: msg.ID}
	switch job.getReason() {
	case stopTimedOut:
		done.OK = true
		done.TimedOut = true
	case stopCanceled:
		done.OK = true
		done.Canceled = true
	default:
		if runErr != nil {
			errMsg := runErr.Error()
			done.Error = &errMsg
		} else {
			done.OK = true
			done.ExitCode = code
		}
	}
	job.sendMsg(done)
}
