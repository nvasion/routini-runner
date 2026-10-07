package dockerx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
)

// The egress proxy container. Exactly one of these runs per host; agent
// containers reach the internet only through it.
const (
	EgressContainerName = "routini-egress"
	// EgressCAVolume holds the proxy's generated CA so that it survives a
	// recreation of the container.
	EgressCAVolume = "routini-egress-ca"
	EgressCADir    = "/var/lib/routini-egress"
	// RoleEgress is the LabelRole value of the egress container.
	RoleEgress = "egress"

	// EgressControlPort is published on loopback with an ephemeral host port.
	EgressControlPort = nat.Port("3129/tcp")
	// EgressProxyPort is reachable from the internal network only and is
	// deliberately never published on the host.
	EgressProxyPort = nat.Port("3128/tcp")

	loopbackIP      = "127.0.0.1"
	egressSecretEnv = "ROUTINI_EGRESS_SECRET"
	egressCADirEnv  = "ROUTINI_EGRESS_CA_DIR"
)

// EnsureEgress keeps exactly one running egress container and returns its
// control URL. An existing container is reused unless its image or its secret
// differs, in which case it is replaced; the CA volume is kept either way.
func (d *dockerClient) EnsureEgress(ctx context.Context, ref, secret string) (string, error) {
	if err := validateRef(ref); err != nil {
		return "", err
	}
	if secret == "" {
		return "", errors.New("dockerx: egress secret is missing")
	}
	if strings.ContainsAny(secret, "\x00\n") {
		return "", errors.New("dockerx: egress secret contains a NUL or newline")
	}

	keep, err := d.reusableEgress(ctx, ref, secret)
	if err != nil {
		return "", err
	}
	if keep != nil {
		url, err := d.runningEgressURL(ctx, keep)
		if err == nil {
			if err := d.awaitEgress(ctx, keep.ID, url, secret); err == nil {
				return url, nil
			}
			// It was running but does not answer: start over below.
		}
		// Up to date but unusable, for instance because its control port is
		// not bound to loopback or the proxy is wedged: replace it rather than
		// hand back a bad URL.
		if rmErr := d.removeEgressContainer(ctx); rmErr != nil {
			if err != nil {
				return "", errors.Join(err, rmErr)
			}
			return "", rmErr
		}
	}
	url, id, err := d.createEgress(ctx, ref, secret)
	if err != nil {
		return "", err
	}
	if err := d.awaitEgress(ctx, id, url, secret); err != nil {
		return "", err
	}
	return url, nil
}

// EgressReadyTimeout bounds how long EnsureEgress waits for a routini-egress
// control API to answer.
var EgressReadyTimeout = 15 * time.Second

// awaitEgress waits until the egress control API answers. When it does not,
// the error carries the end of the container's log: that is where the real
// cause is (a crash on startup), not in the "connection reset" the caller
// would otherwise see.
func (d *dockerClient) awaitEgress(ctx context.Context, id, url, secret string) error {
	if d.egressReady == nil {
		return nil
	}
	err := d.egressReady(ctx, url, secret)
	if err == nil {
		return nil
	}
	if why := d.crashReason(id); why != "" {
		return fmt.Errorf("dockerx: %s did not start: %w; its log says: %s", EgressContainerName, err, why)
	}
	return fmt.Errorf("dockerx: %s did not start: %w", EgressContainerName, err)
}

// waitEgressReady polls GET <controlURL>/ca until it answers 200 or
// EgressReadyTimeout passes.
func waitEgressReady(ctx context.Context, controlURL, secret string) error {
	ctx, cancel := context.WithTimeout(ctx, EgressReadyTimeout)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, controlURL+"/ca", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		res, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("control API answered HTTP %d", res.StatusCode)
		} else {
			last = errors.New("control API not answering")
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// crashLogLines is how much of the container's output crashReason reads.
const crashLogLines = 40

// crashReason picks the line that explains a crash from the end of the
// container's output: the first line naming an error (a Node stack trace puts
// "Error: EACCES ..." above a dozen frames), else the last few lines. At most
// 300 bytes, on one line.
func (d *dockerClient) crashReason(id string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rc, err := d.api.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true, Tail: strconv.Itoa(crashLogLines)})
	if err != nil {
		return ""
	}
	defer rc.Close()
	var out bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &out, io.LimitReader(rc, 64<<10)); err != nil && out.Len() == 0 {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(out.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	why := ""
	for _, l := range lines {
		if strings.Contains(l, "Error") || strings.Contains(l, "error") {
			why = l
			break
		}
	}
	if why == "" && len(lines) > 0 {
		why = strings.Join(lines[max(0, len(lines)-3):], " | ")
	}
	if len(why) > 300 {
		why = why[:300]
	}
	return strings.ToValidUTF8(why, "�")
}

// reusableEgress returns the existing egress container when it still matches
// ref and secret. A drifted container is removed and a nil result returned,
// meaning a fresh one has to be created.
func (d *dockerClient) reusableEgress(ctx context.Context, ref, secret string) (*types.ContainerJSON, error) {
	c, err := d.api.ContainerInspect(ctx, EgressContainerName)
	switch {
	case errdefs.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("dockerx: inspect container %s: %w", EgressContainerName, err)
	}
	if egressDrifted(c, ref, secret) || egressCrashed(c) || d.egressImageStale(ctx, c, ref) {
		if err := d.removeEgressContainer(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &c, nil
}

// egressCrashed reports a container that is restarting or exited with an
// error: starting it again would only repeat the crash (for instance an image
// that cannot write its CA), so it is recreated instead, from a fresh pull.
func egressCrashed(c types.ContainerJSON) bool {
	if c.ContainerJSONBase == nil || c.State == nil {
		return false
	}
	return c.State.Restarting || (!c.State.Running && c.State.ExitCode != 0)
}

// egressImageStale reports whether the local tag ref now names a different
// image than the container runs (a newer one was pulled). Best effort: when
// the image cannot be inspected the container is kept.
func (d *dockerClient) egressImageStale(ctx context.Context, c types.ContainerJSON, ref string) bool {
	if c.ContainerJSONBase == nil || c.Image == "" {
		return false
	}
	img, _, err := d.api.ImageInspectWithRaw(ctx, ref)
	return err == nil && img.ID != "" && img.ID != c.Image
}

// egressDrifted reports whether the existing container no longer matches the
// wanted image or secret. An inspect response without a configuration counts
// as drifted, so the container is recreated rather than trusted.
func egressDrifted(c types.ContainerJSON, ref, secret string) bool {
	if c.ContainerJSONBase == nil || c.Config == nil {
		return true
	}
	if c.Config.Image != ref {
		return true
	}
	return envValue(c.Config.Env, egressSecretEnv) != secret
}

// envValue returns the value of key in a Docker "KEY=value" list.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// runningEgressURL starts the container if it is stopped and returns its
// control URL.
func (d *dockerClient) runningEgressURL(ctx context.Context, c *types.ContainerJSON) (string, error) {
	if c.State == nil || !c.State.Running {
		if err := d.api.ContainerStart(ctx, c.ID, container.StartOptions{}); err != nil {
			return "", fmt.Errorf("dockerx: start container %s: %w", EgressContainerName, err)
		}
	}
	return d.egressControlURL(ctx, c.ID)
}

// createEgress creates and starts the egress container and returns its control
// URL and id. With refreshEgress it pulls the image first, so a republished
// image (a fixed :latest) is used without anyone pulling it on the host; a
// failed pull falls back to the local image.
func (d *dockerClient) createEgress(ctx context.Context, ref, secret string) (string, string, error) {
	if d.refreshEgress {
		_ = d.pullImage(ctx, ref)
	}
	cfg, host := egressConfig(ref, secret)
	created, err := d.api.ContainerCreate(ctx, cfg, host, nil, nil, EgressContainerName)
	if err != nil {
		return "", "", fmt.Errorf("dockerx: create container %s: %w", EgressContainerName, err)
	}
	if err := d.api.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return "", "", fmt.Errorf("dockerx: start container %s: %w", EgressContainerName, err)
	}
	url, err := d.egressControlURL(ctx, created.ID)
	return url, created.ID, err
}

// removeEgressContainer force-removes the egress container, keeping its
// volumes so the CA in EgressCAVolume outlives it.
func (d *dockerClient) removeEgressContainer(ctx context.Context) error {
	err := d.api.ContainerRemove(ctx, EgressContainerName, container.RemoveOptions{
		Force:         true,
		RemoveVolumes: false,
	})
	if err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("dockerx: remove container %s: %w", EgressContainerName, err)
	}
	return nil
}

// egressControlURL reads the ephemeral host port Docker bound the control
// port to and renders the loopback URL callers use to talk to the proxy.
func (d *dockerClient) egressControlURL(ctx context.Context, id string) (string, error) {
	c, err := d.api.ContainerInspect(ctx, id)
	if err != nil {
		return "", fmt.Errorf("dockerx: inspect container %s: %w", EgressContainerName, err)
	}
	if c.NetworkSettings == nil {
		return "", fmt.Errorf("dockerx: container %s reported no network settings", EgressContainerName)
	}
	for _, b := range c.NetworkSettings.Ports[EgressControlPort] {
		if b.HostIP != loopbackIP {
			continue
		}
		port, err := strconv.Atoi(b.HostPort)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		return "http://" + net.JoinHostPort(loopbackIP, strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("dockerx: container %s has no %s binding on %s",
		EgressContainerName, EgressControlPort, loopbackIP)
}

// egressConfig builds the egress container's configuration. It is pure, so
// the published port, the CA volume and the labels can be asserted in tests.
func egressConfig(ref, secret string) (*container.Config, *container.HostConfig) {
	cfg := &container.Config{
		Image: ref,
		Cmd:   strslice.StrSlice{"node", "dist/egress.js"},
		Env: []string{
			egressSecretEnv + "=" + secret,
			egressCADirEnv + "=" + EgressCADir,
		},
		Labels: map[string]string{
			LabelManaged: "true",
			LabelRole:    RoleEgress,
		},
		// Only the control port is exposed here; EgressProxyPort stays
		// reachable from the internal network alone.
		ExposedPorts: nat.PortSet{EgressControlPort: struct{}{}},
	}
	host := &container.HostConfig{
		// An empty HostPort asks Docker for an ephemeral port, and the
		// explicit host IP keeps the control API off every other interface.
		PortBindings: nat.PortMap{
			EgressControlPort: []nat.PortBinding{{HostIP: loopbackIP, HostPort: ""}},
		},
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		Mounts: []mount.Mount{{
			Type:   mount.TypeVolume,
			Source: EgressCAVolume,
			Target: EgressCADir,
		}},
	}
	return cfg, host
}
