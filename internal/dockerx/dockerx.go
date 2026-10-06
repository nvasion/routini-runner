// Package dockerx is the runner's Docker client: the small slice of the
// Engine API the agent features need (PROTOCOL.md section 2.6). It keeps the
// agent sandbox's hardening defaults in one place and exposes them through the
// Docker interface so callers never touch the Engine API directly.
package dockerx

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// EnvDockerHost is the environment variable that overrides the configured
// Docker host (see internal/config).
const EnvDockerHost = "DOCKER_HOST"

// Pull policies accepted by EnsureImage. An empty policy means PullMissing.
const (
	PullMissing = "missing"
	PullAlways  = "always"
)

// Container hardening defaults applied by RunStreaming when a RunSpec leaves
// the field at its zero value.
const (
	DefaultUser      = "1000:1000"
	DefaultPidsLimit = 512
)

// Labels set on every container this package creates.
const (
	LabelManaged = "routini.managed"
	LabelRole    = "routini.role"
)

// RunSpec describes one agent container run.
type RunSpec struct {
	Name    string
	Image   string
	User    string // default DefaultUser
	Network string
	Runtime string // empty means Docker's default runtime

	Env    map[string]string
	Labels map[string]string

	Cpus      float64
	MemoryMb  int64
	PidsLimit int64 // default DefaultPidsLimit
}

// Docker is the subset of the Engine API the runner uses.
type Docker interface {
	// Ping reports the Docker daemon's version, confirming it is reachable.
	Ping(ctx context.Context) (version string, err error)

	// EnsureImage makes ref available locally. pull is PullMissing (pull only
	// when the image is absent) or PullAlways. No registry auth is used.
	EnsureImage(ctx context.Context, ref, pull string) error

	// EnsureNetwork creates an internal bridge network called name with the
	// given labels unless it already exists.
	EnsureNetwork(ctx context.Context, name string, labels map[string]string) error

	// EnsureEgress keeps exactly one egress container running and returns its
	// control URL on the loopback interface.
	EnsureEgress(ctx context.Context, image, secret string) (controlURL string, err error)

	// ConnectNetwork attaches container to network under alias. Being
	// connected already is not an error.
	ConnectNetwork(ctx context.Context, network, container, alias string) error

	// RunStreaming creates, starts and streams one container, calling onLine
	// once per output line with stream "stdout" or "stderr". The container is
	// always removed, including on error and on context cancellation.
	// exitCode is nil when the container never reported one.
	RunStreaming(ctx context.Context, spec RunSpec, onLine func(stream, line string)) (exitCode *int, err error)

	// Stop stops the named container, allowing grace for a clean shutdown,
	// then kills whatever is left. A missing container is not an error.
	Stop(ctx context.Context, name string, grace time.Duration) error

	// KillByLabels kills and removes every container carrying all of labels.
	// It refuses an empty label set.
	KillByLabels(ctx context.Context, labels map[string]string) error
}

// apiClient is the part of client.APIClient this package calls. It exists so
// the behaviour around the Engine API can be tested without a daemon.
type apiClient interface {
	Ping(ctx context.Context) (types.Ping, error)
	ServerVersion(ctx context.Context) (types.Version, error)

	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
	ImagePull(ctx context.Context, ref string, options image.PullOptions) (io.ReadCloser, error)

	NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error)
	NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error)
	NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error

	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *ocispec.Platform, containerName string) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerAttach(ctx context.Context, containerID string, options container.AttachOptions) (types.HijackedResponse, error)
	ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan container.WaitResponse, <-chan error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error)
	ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error
	ContainerKill(ctx context.Context, containerID, signal string) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
}

// dockerClient implements Docker on top of the Engine API.
type dockerClient struct {
	api apiClient
}

// New returns a Docker client. It reads the usual DOCKER_* environment
// variables and negotiates the API version with the daemon; dockerHost is used
// only when it is non-empty and DOCKER_HOST is unset. Connecting is lazy, so a
// successful New does not mean the daemon is reachable: call Ping for that.
func New(dockerHost string) (Docker, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if dockerHost != "" && os.Getenv(EnvDockerHost) == "" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	api, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("dockerx: create docker client: %w", err)
	}
	return &dockerClient{api: api}, nil
}

// Ping reports the daemon's version.
func (d *dockerClient) Ping(ctx context.Context) (string, error) {
	if _, err := d.api.Ping(ctx); err != nil {
		return "", fmt.Errorf("dockerx: ping docker daemon: %w", err)
	}
	v, err := d.api.ServerVersion(ctx)
	if err != nil {
		return "", fmt.Errorf("dockerx: read docker version: %w", err)
	}
	if v.Version == "" {
		return "", fmt.Errorf("dockerx: docker daemon reported no version")
	}
	return v.Version, nil
}
