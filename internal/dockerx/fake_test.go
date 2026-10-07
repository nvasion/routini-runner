package dockerx

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fakeAPI is an apiClient whose every method is a test hook. A call with no
// hook set fails loudly, so a test only has to describe the calls it expects.
type fakeAPI struct {
	ping          func(ctx context.Context) (types.Ping, error)
	serverVersion func(ctx context.Context) (types.Version, error)

	imageInspect func(ctx context.Context, ref string) (types.ImageInspect, []byte, error)
	imagePull    func(ctx context.Context, ref string, opts image.PullOptions) (io.ReadCloser, error)

	networkInspect func(ctx context.Context, name string, opts network.InspectOptions) (network.Inspect, error)
	networkCreate  func(ctx context.Context, name string, opts network.CreateOptions) (network.CreateResponse, error)
	networkConnect func(ctx context.Context, net, ctr string, cfg *network.EndpointSettings) error

	containerCreate  func(ctx context.Context, cfg *container.Config, host *container.HostConfig, net *network.NetworkingConfig, name string) (container.CreateResponse, error)
	containerStart   func(ctx context.Context, id string, opts container.StartOptions) error
	containerAttach  func(ctx context.Context, id string, opts container.AttachOptions) (types.HijackedResponse, error)
	containerWait    func(ctx context.Context, id string, cond container.WaitCondition) (<-chan container.WaitResponse, <-chan error)
	containerInspect func(ctx context.Context, id string) (types.ContainerJSON, error)
	containerList    func(ctx context.Context, opts container.ListOptions) ([]types.Container, error)
	containerStop    func(ctx context.Context, id string, opts container.StopOptions) error
	containerKill    func(ctx context.Context, id, signal string) error
	containerRemove  func(ctx context.Context, id string, opts container.RemoveOptions) error

	containerExecCreate  func(ctx context.Context, id string, opts container.ExecOptions) (types.IDResponse, error)
	containerExecStart   func(ctx context.Context, execID string, cfg container.ExecStartOptions) error
	containerExecAttach  func(ctx context.Context, execID string, cfg container.ExecAttachOptions) (types.HijackedResponse, error)
	containerExecInspect func(ctx context.Context, execID string) (container.ExecInspect, error)
	containerExecResize  func(ctx context.Context, execID string, opts container.ResizeOptions) error

	volumeInspect func(ctx context.Context, id string) (volume.Volume, error)
	volumeCreate  func(ctx context.Context, opts volume.CreateOptions) (volume.Volume, error)
	volumeRemove  func(ctx context.Context, id string, force bool) error

	mu    sync.Mutex
	calls []string
}

func (f *fakeAPI) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

// log returns the recorded calls in order.
func (f *fakeAPI) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func unexpected(method string) error {
	return fmt.Errorf("fakeAPI: unexpected call to %s", method)
}

func (f *fakeAPI) Ping(ctx context.Context) (types.Ping, error) {
	f.record("Ping")
	if f.ping == nil {
		return types.Ping{}, unexpected("Ping")
	}
	return f.ping(ctx)
}

func (f *fakeAPI) ServerVersion(ctx context.Context) (types.Version, error) {
	f.record("ServerVersion")
	if f.serverVersion == nil {
		return types.Version{}, unexpected("ServerVersion")
	}
	return f.serverVersion(ctx)
}

func (f *fakeAPI) ImageInspectWithRaw(ctx context.Context, ref string) (types.ImageInspect, []byte, error) {
	f.record("ImageInspectWithRaw(%s)", ref)
	if f.imageInspect == nil {
		return types.ImageInspect{}, nil, unexpected("ImageInspectWithRaw")
	}
	return f.imageInspect(ctx, ref)
}

func (f *fakeAPI) ImagePull(ctx context.Context, ref string, opts image.PullOptions) (io.ReadCloser, error) {
	f.record("ImagePull(%s)", ref)
	if f.imagePull == nil {
		return nil, unexpected("ImagePull")
	}
	return f.imagePull(ctx, ref, opts)
}

func (f *fakeAPI) NetworkInspect(ctx context.Context, name string, opts network.InspectOptions) (network.Inspect, error) {
	f.record("NetworkInspect(%s)", name)
	if f.networkInspect == nil {
		return network.Inspect{}, unexpected("NetworkInspect")
	}
	return f.networkInspect(ctx, name, opts)
}

func (f *fakeAPI) NetworkCreate(ctx context.Context, name string, opts network.CreateOptions) (network.CreateResponse, error) {
	f.record("NetworkCreate(%s)", name)
	if f.networkCreate == nil {
		return network.CreateResponse{}, unexpected("NetworkCreate")
	}
	return f.networkCreate(ctx, name, opts)
}

func (f *fakeAPI) NetworkConnect(ctx context.Context, net, ctr string, cfg *network.EndpointSettings) error {
	f.record("NetworkConnect(%s,%s)", net, ctr)
	if f.networkConnect == nil {
		return unexpected("NetworkConnect")
	}
	return f.networkConnect(ctx, net, ctr, cfg)
}

func (f *fakeAPI) ContainerCreate(ctx context.Context, cfg *container.Config, host *container.HostConfig, netCfg *network.NetworkingConfig, _ *ocispec.Platform, name string) (container.CreateResponse, error) {
	f.record("ContainerCreate(%s)", name)
	if f.containerCreate == nil {
		return container.CreateResponse{}, unexpected("ContainerCreate")
	}
	return f.containerCreate(ctx, cfg, host, netCfg, name)
}

func (f *fakeAPI) ContainerStart(ctx context.Context, id string, opts container.StartOptions) error {
	f.record("ContainerStart(%s)", id)
	if f.containerStart == nil {
		return unexpected("ContainerStart")
	}
	return f.containerStart(ctx, id, opts)
}

func (f *fakeAPI) ContainerAttach(ctx context.Context, id string, opts container.AttachOptions) (types.HijackedResponse, error) {
	f.record("ContainerAttach(%s)", id)
	if f.containerAttach == nil {
		return types.HijackedResponse{}, unexpected("ContainerAttach")
	}
	return f.containerAttach(ctx, id, opts)
}

func (f *fakeAPI) ContainerWait(ctx context.Context, id string, cond container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	f.record("ContainerWait(%s,%s)", id, cond)
	if f.containerWait == nil {
		errCh := make(chan error, 1)
		errCh <- unexpected("ContainerWait")
		return nil, errCh
	}
	return f.containerWait(ctx, id, cond)
}

func (f *fakeAPI) ContainerInspect(ctx context.Context, id string) (types.ContainerJSON, error) {
	f.record("ContainerInspect(%s)", id)
	if f.containerInspect == nil {
		return types.ContainerJSON{}, unexpected("ContainerInspect")
	}
	return f.containerInspect(ctx, id)
}

func (f *fakeAPI) ContainerList(ctx context.Context, opts container.ListOptions) ([]types.Container, error) {
	f.record("ContainerList(%s)", opts.Filters.Get("label"))
	if f.containerList == nil {
		return nil, unexpected("ContainerList")
	}
	return f.containerList(ctx, opts)
}

func (f *fakeAPI) ContainerStop(ctx context.Context, id string, opts container.StopOptions) error {
	timeout := -1
	if opts.Timeout != nil {
		timeout = *opts.Timeout
	}
	f.record("ContainerStop(%s,%d)", id, timeout)
	if f.containerStop == nil {
		return unexpected("ContainerStop")
	}
	return f.containerStop(ctx, id, opts)
}

func (f *fakeAPI) ContainerKill(ctx context.Context, id, signal string) error {
	f.record("ContainerKill(%s,%s)", id, signal)
	if f.containerKill == nil {
		return unexpected("ContainerKill")
	}
	return f.containerKill(ctx, id, signal)
}

func (f *fakeAPI) ContainerRemove(ctx context.Context, id string, opts container.RemoveOptions) error {
	f.record("ContainerRemove(%s,force=%t,volumes=%t)", id, opts.Force, opts.RemoveVolumes)
	if f.containerRemove == nil {
		return unexpected("ContainerRemove")
	}
	return f.containerRemove(ctx, id, opts)
}

func (f *fakeAPI) ContainerExecCreate(ctx context.Context, id string, opts container.ExecOptions) (types.IDResponse, error) {
	f.record("ContainerExecCreate(%s)", id)
	if f.containerExecCreate == nil {
		return types.IDResponse{}, unexpected("ContainerExecCreate")
	}
	return f.containerExecCreate(ctx, id, opts)
}

func (f *fakeAPI) ContainerExecStart(ctx context.Context, execID string, cfg container.ExecStartOptions) error {
	f.record("ContainerExecStart(%s)", execID)
	if f.containerExecStart == nil {
		return unexpected("ContainerExecStart")
	}
	return f.containerExecStart(ctx, execID, cfg)
}

func (f *fakeAPI) ContainerExecAttach(ctx context.Context, execID string, cfg container.ExecAttachOptions) (types.HijackedResponse, error) {
	f.record("ContainerExecAttach(%s)", execID)
	if f.containerExecAttach == nil {
		return types.HijackedResponse{}, unexpected("ContainerExecAttach")
	}
	return f.containerExecAttach(ctx, execID, cfg)
}

func (f *fakeAPI) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	f.record("ContainerExecInspect(%s)", execID)
	if f.containerExecInspect == nil {
		return container.ExecInspect{}, unexpected("ContainerExecInspect")
	}
	return f.containerExecInspect(ctx, execID)
}

func (f *fakeAPI) ContainerExecResize(ctx context.Context, execID string, opts container.ResizeOptions) error {
	f.record("ContainerExecResize(%s)", execID)
	if f.containerExecResize == nil {
		return unexpected("ContainerExecResize")
	}
	return f.containerExecResize(ctx, execID, opts)
}

func (f *fakeAPI) VolumeInspect(ctx context.Context, id string) (volume.Volume, error) {
	f.record("VolumeInspect(%s)", id)
	if f.volumeInspect == nil {
		return volume.Volume{}, unexpected("VolumeInspect")
	}
	return f.volumeInspect(ctx, id)
}

func (f *fakeAPI) VolumeCreate(ctx context.Context, opts volume.CreateOptions) (volume.Volume, error) {
	f.record("VolumeCreate(%s)", opts.Name)
	if f.volumeCreate == nil {
		return volume.Volume{}, unexpected("VolumeCreate")
	}
	return f.volumeCreate(ctx, opts)
}

func (f *fakeAPI) VolumeRemove(ctx context.Context, id string, force bool) error {
	f.record("VolumeRemove(%s,force=%t)", id, force)
	if f.volumeRemove == nil {
		return unexpected("VolumeRemove")
	}
	return f.volumeRemove(ctx, id, force)
}

// noopStart and noopRemove succeed without recording anything, for the calls
// a test does not care about.
func noopStart(context.Context, string, container.StartOptions) error { return nil }

func noopRemove(context.Context, string, container.RemoveOptions) error { return nil }
