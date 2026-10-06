package dockerx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/errdefs"
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
			return url, nil
		}
		// Up to date but unusable, for instance because its control port is
		// not bound to loopback: replace it rather than hand back a bad URL.
		if rmErr := d.removeEgressContainer(ctx); rmErr != nil {
			return "", errors.Join(err, rmErr)
		}
	}
	return d.createEgress(ctx, ref, secret)
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
	if egressDrifted(c, ref, secret) {
		if err := d.removeEgressContainer(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &c, nil
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

func (d *dockerClient) createEgress(ctx context.Context, ref, secret string) (string, error) {
	cfg, host := egressConfig(ref, secret)
	created, err := d.api.ContainerCreate(ctx, cfg, host, nil, nil, EgressContainerName)
	if err != nil {
		return "", fmt.Errorf("dockerx: create container %s: %w", EgressContainerName, err)
	}
	if err := d.api.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("dockerx: start container %s: %w", EgressContainerName, err)
	}
	return d.egressControlURL(ctx, created.ID)
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
