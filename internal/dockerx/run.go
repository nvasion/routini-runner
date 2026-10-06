package dockerx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	// signalKill is the signal name the Engine API expects for a hard kill.
	signalKill = "KILL"
	// cleanupTimeout bounds the stop and remove calls that must run on a
	// fresh context because the caller's context is already done.
	cleanupTimeout = 30 * time.Second
	// cancelGrace is how long a cancelled container gets to exit on SIGTERM
	// before it is force-removed. It matches execx's kill grace.
	cancelGrace = 5 * time.Second
	// shortIDLen is the number of container id characters put in messages.
	shortIDLen = 12
)

// RunStreaming runs one agent container to completion, reporting its output
// line by line. The container is always removed afterwards, including on
// error and on context cancellation. When the run succeeded but the container
// could not be removed, both a non-nil exitCode and a non-nil error are
// returned.
func (d *dockerClient) RunStreaming(ctx context.Context, spec RunSpec, onLine func(stream, line string)) (exitCode *int, err error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if onLine == nil {
		onLine = func(string, string) {}
	}

	cfg, host := containerConfig(spec)
	created, err := d.api.ContainerCreate(ctx, cfg, host, nil, nil, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("dockerx: create container %s: %w", spec.Name, err)
	}
	id := created.ID
	defer func() {
		// Removal runs on every path. A failure here is reported alongside
		// whatever the run itself produced, never dropped: a leaked container
		// would hold on to the agent network and its resources.
		if rmErr := d.removeContainer(id); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("dockerx: remove container %s: %w", spec.Name, rmErr))
		}
	}()

	// Attach before starting so that no output can be missed.
	att, err := d.api.ContainerAttach(ctx, id, container.AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("dockerx: attach to container %s: %w", spec.Name, err)
	}
	defer att.Close()

	stdout := newLineWriter(func(line string) { onLine("stdout", line) })
	stderr := newLineWriter(func(line string) { onLine("stderr", line) })
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := stdcopy.StdCopy(stdout, stderr, att.Reader)
		copyDone <- copyErr
	}()

	// Register the wait before starting, so the exit of a very short-lived
	// container cannot be missed.
	waitCh, waitErrCh := d.api.ContainerWait(ctx, id, container.WaitConditionNextExit)
	if err := d.api.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("dockerx: start container %s: %w", spec.Name, err)
	}

	// Drain the output first: the stream ends when the container exits, so
	// every line reaches onLine before the exit code is reported.
	var copyErr error
	select {
	case copyErr = <-copyDone:
	case <-ctx.Done():
		d.stopBestEffort(id, cancelGrace)
		att.Close() // unblocks StdCopy if the stream is still open
		copyErr = <-copyDone
	}
	stdout.Flush()
	stderr.Flush()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("dockerx: run container %s: %w", spec.Name, ctxErr)
	}
	if copyErr != nil {
		return nil, fmt.Errorf("dockerx: stream output of container %s: %w", spec.Name, copyErr)
	}
	select {
	case waitErr := <-waitErrCh:
		return nil, fmt.Errorf("dockerx: wait for container %s: %w", spec.Name, waitErr)
	case res := <-waitCh:
		if res.Error != nil && res.Error.Message != "" {
			return nil, fmt.Errorf("dockerx: container %s failed: %s", spec.Name, res.Error.Message)
		}
		code := int(res.StatusCode)
		return &code, nil
	}
}

// Stop stops the named container within grace, then kills whatever is left.
func (d *dockerClient) Stop(ctx context.Context, name string, grace time.Duration) error {
	if err := validateName("container name", name); err != nil {
		return err
	}
	if err := d.api.ContainerStop(ctx, name, stopOptions(grace)); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("dockerx: stop container %s: %w", name, err)
	}
	if err := d.killContainer(ctx, name); err != nil {
		return err
	}
	return nil
}

// KillByLabels kills and removes every container carrying all of labels. It
// refuses an empty label set, which would match every container on the host.
func (d *dockerClient) KillByLabels(ctx context.Context, labels map[string]string) error {
	if len(labels) == 0 {
		return errors.New("dockerx: killByLabels needs at least one label")
	}
	if err := validateLabels(labels); err != nil {
		return err
	}
	args := filters.NewArgs()
	for k, v := range labels {
		args.Add("label", k+"="+v)
	}
	list, err := d.api.ContainerList(ctx, container.ListOptions{All: true, Filters: args})
	if err != nil {
		return fmt.Errorf("dockerx: list containers by label: %w", err)
	}

	var errs []error
	for _, c := range list {
		// Defence in depth: only ever act on a container that really does
		// carry every requested label.
		if !hasAllLabels(c.Labels, labels) {
			continue
		}
		if err := d.killContainer(ctx, c.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := d.api.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("dockerx: remove container %s: %w", shortID(c.ID), err))
		}
	}
	return errors.Join(errs...)
}

// killContainer sends SIGKILL. A container that has already exited answers
// 409 and one that is gone answers 404; both mean there is nothing to kill.
func (d *dockerClient) killContainer(ctx context.Context, idOrName string) error {
	err := d.api.ContainerKill(ctx, idOrName, signalKill)
	if err != nil && !errdefs.IsNotFound(err) && !errdefs.IsConflict(err) {
		return fmt.Errorf("dockerx: kill container %s: %w", shortID(idOrName), err)
	}
	return nil
}

// removeContainer force-removes a container on a fresh context, so that it is
// cleaned up even when the caller's context is already cancelled.
func (d *dockerClient) removeContainer(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := d.api.ContainerRemove(ctx, id, container.RemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	return nil
}

// stopBestEffort asks a container to exit within grace, on a fresh context
// since the caller's one is cancelled by the time this is used. Its outcome
// is not reported: the force-remove that follows is what guarantees cleanup,
// and that one does report its errors.
func (d *dockerClient) stopBestEffort(id string, grace time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_ = d.api.ContainerStop(ctx, id, stopOptions(grace))
}

// stopOptions converts a grace period to the Engine API's whole-second
// timeout, never going negative (which would mean "wait forever").
func stopOptions(grace time.Duration) container.StopOptions {
	secs := 0
	if grace > 0 {
		secs = int(grace.Round(time.Second) / time.Second)
	}
	return container.StopOptions{Timeout: &secs}
}

func hasAllLabels(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// shortID trims a container id for use in messages.
func shortID(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}
	return id
}
