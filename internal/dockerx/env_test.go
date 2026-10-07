package dockerx

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
)

func validEnvSpec() EnvSpec {
	return EnvSpec{
		Name:    "routini-env-task-1",
		Image:   "ghcr.io/nvasion/routini-agent-claude:0.3.0",
		Volume:  "routini-env-task-1",
		Network: "routini-sb-org1",
		Labels:  map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"},
		Env:     map[string]string{"ROUTINI_PROMPT": "hi"},

		Cpus:      2,
		MemoryMb:  4096,
		PidsLimit: 512,
	}
}

func TestEnvContainerConfigHardening(t *testing.T) {
	// Everything optional left at its zero value: the defaults must still
	// produce a locked-down container.
	cfg, host := envContainerConfig(EnvSpec{Name: "routini-env-a", Image: "img", Volume: "routini-env-a"})

	if cfg.User != DefaultUser {
		t.Errorf("User = %q, want %q", cfg.User, DefaultUser)
	}
	if want := []string{"tail", "-f", "/dev/null"}; !reflect.DeepEqual([]string(cfg.Entrypoint), want) {
		t.Errorf("Entrypoint = %v, want %v", cfg.Entrypoint, want)
	}
	if len(cfg.Cmd) != 0 {
		t.Errorf("Cmd = %v, want empty", cfg.Cmd)
	}
	if cfg.WorkingDir != workspaceDir {
		t.Errorf("WorkingDir = %q, want %q", cfg.WorkingDir, workspaceDir)
	}
	if host.Init == nil || !*host.Init {
		t.Error("Init must be true")
	}
	if want := []string{"ALL"}; !reflect.DeepEqual([]string(host.CapDrop), want) {
		t.Errorf("CapDrop = %v, want %v", host.CapDrop, want)
	}
	if want := []string{"no-new-privileges:true"}; !reflect.DeepEqual(host.SecurityOpt, want) {
		t.Errorf("SecurityOpt = %v, want %v", host.SecurityOpt, want)
	}
	if host.PidsLimit == nil || *host.PidsLimit != DefaultPidsLimit {
		t.Errorf("PidsLimit = %v, want %d", host.PidsLimit, DefaultPidsLimit)
	}
	if host.RestartPolicy.Name != container.RestartPolicyDisabled {
		t.Errorf("RestartPolicy = %q, want %q", host.RestartPolicy.Name, container.RestartPolicyDisabled)
	}
	if host.AutoRemove {
		t.Error("AutoRemove = true, want false")
	}
	if host.Runtime != "" {
		t.Errorf("Runtime = %q, want Docker's default", host.Runtime)
	}
}

func TestEnvContainerConfigMapping(t *testing.T) {
	spec := validEnvSpec()
	spec.Runtime = "runsc"
	spec.PidsLimit = 256
	spec.Cpus = 1.5
	spec.Env = map[string]string{"B": "2", "A": "1"}

	cfg, host := envContainerConfig(spec)

	if cfg.Image != spec.Image {
		t.Errorf("Image = %q, want %q", cfg.Image, spec.Image)
	}
	if want := []string{"A=1", "B=2"}; !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v sorted by key", cfg.Env, want)
	}
	if !reflect.DeepEqual(cfg.Labels, spec.Labels) {
		t.Errorf("Labels = %v, want %v", cfg.Labels, spec.Labels)
	}
	wantMount := mount.Mount{Type: mount.TypeVolume, Source: spec.Volume, Target: workspaceDir}
	if !reflect.DeepEqual(host.Mounts, []mount.Mount{wantMount}) {
		t.Errorf("Mounts = %v, want %v", host.Mounts, wantMount)
	}
	if string(host.NetworkMode) != spec.Network {
		t.Errorf("NetworkMode = %q, want %q", host.NetworkMode, spec.Network)
	}
	if want := int64(4096) * bytesPerMiB; host.Memory != want {
		t.Errorf("Memory = %d, want %d bytes", host.Memory, want)
	}
	if want := int64(1_500_000_000); host.NanoCPUs != want {
		t.Errorf("NanoCPUs = %d, want %d", host.NanoCPUs, want)
	}
	if *host.PidsLimit != 256 {
		t.Errorf("PidsLimit = %d, want 256", *host.PidsLimit)
	}
	if host.Runtime != "runsc" {
		t.Errorf("Runtime = %q, want runsc", host.Runtime)
	}
}

func TestEnvContainerConfigCopiesLabels(t *testing.T) {
	spec := validEnvSpec()
	cfg, _ := envContainerConfig(spec)

	spec.Labels["late"] = "x"
	if _, ok := cfg.Labels["late"]; ok {
		t.Error("mutating the spec's labels changed the container config")
	}
}

func TestEnvSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*EnvSpec)
		wantErr string
	}{
		{"valid", func(*EnvSpec) {}, ""},
		{"no name", func(s *EnvSpec) { s.Name = "" }, "environment name is missing"},
		{"bad name", func(s *EnvSpec) { s.Name = "../etc" }, "invalid environment name"},
		{"uppercase name", func(s *EnvSpec) { s.Name = "routini-env-Task" }, "invalid environment name"},
		{"no volume", func(s *EnvSpec) { s.Volume = "" }, "volume name is missing"},
		{"bad volume", func(s *EnvSpec) { s.Volume = "not-an-env-volume" }, "invalid volume name"},
		{"no network", func(s *EnvSpec) { s.Network = "" }, "network name is missing"},
		{"bad network", func(s *EnvSpec) { s.Network = "not-sandboxed" }, "invalid network name"},
		{"no image", func(s *EnvSpec) { s.Image = "" }, "image reference is missing"},
		{"bad image", func(s *EnvSpec) { s.Image = "img; rm -rf /" }, "invalid image reference"},
		{"bad runtime", func(s *EnvSpec) { s.Runtime = "runsc; sh" }, "invalid runtime"},
		{"bad env key", func(s *EnvSpec) { s.Env = map[string]string{"1BAD": "x"} }, "invalid env key"},
		{"env value with NUL", func(s *EnvSpec) { s.Env = map[string]string{"K": "a\x00b"} }, "contains a NUL"},
		{"missing managed label", func(s *EnvSpec) {
			s.Labels = map[string]string{LabelEnvironment: "env-1"}
		}, "must include routini.managed=true"},
		{"managed label false", func(s *EnvSpec) {
			s.Labels = map[string]string{LabelManaged: "false", LabelEnvironment: "env-1"}
		}, "must include routini.managed=true"},
		{"missing environment label", func(s *EnvSpec) {
			s.Labels = map[string]string{LabelManaged: "true"}
		}, "non-empty routini.environment"},
		{"empty environment label", func(s *EnvSpec) {
			s.Labels = map[string]string{LabelManaged: "true", LabelEnvironment: ""}
		}, "non-empty routini.environment"},
		{"label key with equals", func(s *EnvSpec) {
			s.Labels = map[string]string{LabelManaged: "true", LabelEnvironment: "x", "a=b": "x"}
		}, "invalid label key"},
		{"negative cpus", func(s *EnvSpec) { s.Cpus = -1 }, "cpus must not be negative"},
		{"negative memory", func(s *EnvSpec) { s.MemoryMb = -1 }, "memoryMb must not be negative"},
		{"negative pids", func(s *EnvSpec) { s.PidsLimit = -1 }, "pidsLimit must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validEnvSpec()
			tc.mutate(&spec)
			err := spec.validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("got no error, want one containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestStartEnvContainerRejectsBadSpec(t *testing.T) {
	api := &fakeAPI{} // no hooks: any daemon call fails the test
	spec := validEnvSpec()
	spec.Name = "not-an-env-name"

	id, err := (&dockerClient{api: api}).StartEnvContainer(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "invalid environment name") {
		t.Fatalf("got %v, want a validation error", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
	if len(api.log()) != 0 {
		t.Errorf("calls = %v, want none before validation passes", api.log())
	}
}

func TestStartEnvContainerRemovesOnStartFailure(t *testing.T) {
	var removed []string
	api := &fakeAPI{
		containerCreate: func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{ID: "env-id"}, nil
		},
		containerStart: func(context.Context, string, container.StartOptions) error {
			return errors.New("no such runtime")
		},
		containerRemove: func(_ context.Context, id string, opts container.RemoveOptions) error {
			if !opts.Force {
				t.Error("the container must be force-removed")
			}
			removed = append(removed, id)
			return nil
		},
	}

	id, err := (&dockerClient{api: api}).StartEnvContainer(context.Background(), validEnvSpec())
	if err == nil || !strings.Contains(err.Error(), "start container") {
		t.Fatalf("got %v, want a wrapped start error", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty on failure", id)
	}
	if !reflect.DeepEqual(removed, []string{"env-id"}) {
		t.Errorf("removed = %v, want the container removed", removed)
	}
}

func TestStartEnvContainerReturnsIDOnSuccess(t *testing.T) {
	api := &fakeAPI{
		containerCreate: func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{ID: "env-id"}, nil
		},
		containerStart: noopStart,
	}

	id, err := (&dockerClient{api: api}).StartEnvContainer(context.Background(), validEnvSpec())
	if err != nil {
		t.Fatalf("StartEnvContainer: %v", err)
	}
	if id != "env-id" {
		t.Errorf("id = %q, want %q", id, "env-id")
	}
}

func TestInspectEnvMissingContainer(t *testing.T) {
	api := &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{}, notFound()
		},
	}
	info, err := (&dockerClient{api: api}).InspectEnv(context.Background(), "routini-env-gone")
	if err != nil {
		t.Fatalf("InspectEnv: %v", err)
	}
	if info != (EnvInfo{}) {
		t.Errorf("info = %+v, want the zero value for a missing container", info)
	}
}

func TestInspectEnvManaged(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *container.Config
		running bool
		want    EnvInfo
	}{
		{
			name:    "managed and running",
			cfg:     &container.Config{Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}},
			running: true,
			want:    EnvInfo{Exists: true, Running: true, Managed: true, EnvID: "env-1"},
		},
		{
			name:    "managed but stopped",
			cfg:     &container.Config{Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}},
			running: false,
			want:    EnvInfo{Exists: true, Running: false, Managed: true, EnvID: "env-1"},
		},
		{
			name:    "managed label only",
			cfg:     &container.Config{Labels: map[string]string{LabelManaged: "true"}},
			running: true,
			want:    EnvInfo{Exists: true, Running: true, Managed: false, EnvID: ""},
		},
		{
			name:    "environment label only",
			cfg:     &container.Config{Labels: map[string]string{LabelEnvironment: "env-1"}},
			running: true,
			want:    EnvInfo{Exists: true, Running: true, Managed: false, EnvID: "env-1"},
		},
		{
			name:    "no config at all",
			cfg:     nil,
			running: false,
			want:    EnvInfo{Exists: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{
				containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						ContainerJSONBase: &types.ContainerJSONBase{State: &types.ContainerState{Running: tc.running}},
						Config:            tc.cfg,
					}, nil
				},
			}
			info, err := (&dockerClient{api: api}).InspectEnv(context.Background(), "routini-env-a")
			if err != nil {
				t.Fatalf("InspectEnv: %v", err)
			}
			if info != tc.want {
				t.Errorf("info = %+v, want %+v", info, tc.want)
			}
		})
	}
}

func TestRemoveEnvContainerMissingIsFine(t *testing.T) {
	api := &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{}, notFound()
		},
	}
	if err := (&dockerClient{api: api}).RemoveEnvContainer(context.Background(), "routini-env-gone"); err != nil {
		t.Fatalf("RemoveEnvContainer: %v", err)
	}
}

func TestRemoveEnvContainerRefusesUnmanaged(t *testing.T) {
	cases := []struct {
		name string
		cfg  *container.Config
	}{
		{"no config", nil},
		{"no labels", &container.Config{}},
		{"managed label only", &container.Config{Labels: map[string]string{LabelManaged: "true"}}},
		{"environment label only", &container.Config{Labels: map[string]string{LabelEnvironment: "env-1"}}},
		{"managed label false", &container.Config{Labels: map[string]string{LabelManaged: "false", LabelEnvironment: "env-1"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{
				containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
					return types.ContainerJSON{Config: tc.cfg}, nil
				},
			}
			err := (&dockerClient{api: api}).RemoveEnvContainer(context.Background(), "some-id")
			if err == nil || !strings.Contains(err.Error(), "not a Routini environment container") {
				t.Fatalf("got %v, want the unmanaged refusal", err)
			}
		})
	}
}

func TestRemoveEnvContainerRemovesManaged(t *testing.T) {
	var removed []string
	api := &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{
				Config: &container.Config{Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}},
			}, nil
		},
		containerRemove: func(_ context.Context, id string, opts container.RemoveOptions) error {
			if !opts.Force {
				t.Error("want a forced removal")
			}
			removed = append(removed, id)
			return nil
		},
	}
	if err := (&dockerClient{api: api}).RemoveEnvContainer(context.Background(), "env-id"); err != nil {
		t.Fatalf("RemoveEnvContainer: %v", err)
	}
	if !reflect.DeepEqual(removed, []string{"env-id"}) {
		t.Errorf("removed = %v, want [env-id]", removed)
	}
}

func TestInspectVolumeMissing(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, notFound()
		},
	}
	info, err := (&dockerClient{api: api}).InspectVolume(context.Background(), "routini-env-gone")
	if err != nil {
		t.Fatalf("InspectVolume: %v", err)
	}
	if !reflect.DeepEqual(info, VolumeInfo{}) {
		t.Errorf("info = %+v, want the zero value for a missing volume", info)
	}
}

func TestInspectVolumeFound(t *testing.T) {
	labels := map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{Name: "routini-env-a", Labels: labels}, nil
		},
	}
	info, err := (&dockerClient{api: api}).InspectVolume(context.Background(), "routini-env-a")
	if err != nil {
		t.Fatalf("InspectVolume: %v", err)
	}
	want := VolumeInfo{Exists: true, Labels: labels}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("info = %+v, want %+v", info, want)
	}
}

func TestInspectVolumeRejectsBadName(t *testing.T) {
	api := &fakeAPI{}
	_, err := (&dockerClient{api: api}).InspectVolume(context.Background(), "not-a-volume")
	if err == nil || !strings.Contains(err.Error(), "invalid volume name") {
		t.Fatalf("got %v, want a validation error", err)
	}
	if len(api.log()) != 0 {
		t.Errorf("calls = %v, want none before validation passes", api.log())
	}
}

func TestInspectVolumeInspectError(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, errors.New("daemon unreachable")
		},
	}
	_, err := (&dockerClient{api: api}).InspectVolume(context.Background(), "routini-env-a")
	if err == nil || !strings.Contains(err.Error(), "inspect volume") {
		t.Fatalf("got %v, want a wrapped inspect error", err)
	}
}

func TestEnsureVolumeCreatesWhenAbsent(t *testing.T) {
	var created volume.CreateOptions
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, notFound()
		},
		volumeCreate: func(_ context.Context, opts volume.CreateOptions) (volume.Volume, error) {
			created = opts
			return volume.Volume{Name: opts.Name}, nil
		},
	}
	labels := map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}
	if err := (&dockerClient{api: api}).EnsureVolume(context.Background(), "routini-env-a", labels); err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	if created.Name != "routini-env-a" {
		t.Errorf("created name = %q, want routini-env-a", created.Name)
	}
	if !reflect.DeepEqual(created.Labels, labels) {
		t.Errorf("created labels = %v, want %v", created.Labels, labels)
	}
}

func TestEnsureVolumeLeavesExistingAlone(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{Name: "routini-env-a"}, nil
		},
		volumeCreate: func(context.Context, volume.CreateOptions) (volume.Volume, error) {
			t.Fatal("VolumeCreate must not be called when the volume already exists")
			return volume.Volume{}, nil
		},
	}
	if err := (&dockerClient{api: api}).EnsureVolume(context.Background(), "routini-env-a", nil); err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
}

func TestEnsureVolumeRejectsBadName(t *testing.T) {
	api := &fakeAPI{}
	if err := (&dockerClient{api: api}).EnsureVolume(context.Background(), "not-a-volume", nil); err == nil {
		t.Fatal("want a validation error")
	}
	if len(api.log()) != 0 {
		t.Errorf("calls = %v, want none before validation passes", api.log())
	}
}

func TestRemoveVolumeMissingIsFine(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, notFound()
		},
	}
	if err := (&dockerClient{api: api}).RemoveVolume(context.Background(), "routini-env-gone"); err != nil {
		t.Fatalf("RemoveVolume: %v", err)
	}
}

func TestRemoveVolumeRefusesUnmanaged(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
	}{
		{"no labels", nil},
		{"managed false", map[string]string{LabelManaged: "false"}},
		{"unrelated label", map[string]string{"other": "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{
				volumeInspect: func(context.Context, string) (volume.Volume, error) {
					return volume.Volume{Name: "routini-env-a", Labels: tc.labels}, nil
				},
			}
			err := (&dockerClient{api: api}).RemoveVolume(context.Background(), "routini-env-a")
			if err == nil || !strings.Contains(err.Error(), "not a Routini volume") {
				t.Fatalf("got %v, want the unmanaged refusal", err)
			}
		})
	}
}

func TestRemoveVolumeRemovesManaged(t *testing.T) {
	var removedForce bool
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{Name: "routini-env-a", Labels: map[string]string{LabelManaged: "true"}}, nil
		},
		volumeRemove: func(_ context.Context, id string, force bool) error {
			if id != "routini-env-a" {
				t.Errorf("removed id = %q, want routini-env-a", id)
			}
			removedForce = force
			return nil
		},
	}
	if err := (&dockerClient{api: api}).RemoveVolume(context.Background(), "routini-env-a"); err != nil {
		t.Fatalf("RemoveVolume: %v", err)
	}
	if !removedForce {
		t.Error("want a forced removal")
	}
}

func TestCountEnvContainers(t *testing.T) {
	api := &fakeAPI{
		containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
			return []types.Container{
				{ID: "a", Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}},
				{ID: "b", Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-2"}},
				// Defence in depth: a result that slipped through the
				// daemon's own filter without both labels must not count.
				{ID: "c", Labels: map[string]string{LabelManaged: "true"}},
				{ID: "d", Labels: map[string]string{LabelEnvironment: "env-3"}},
			}, nil
		},
	}
	n, err := (&dockerClient{api: api}).CountEnvContainers(context.Background())
	if err != nil {
		t.Fatalf("CountEnvContainers: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

func TestCountEnvContainersListError(t *testing.T) {
	api := &fakeAPI{
		containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
			return nil, errors.New("daemon unreachable")
		},
	}
	if _, err := (&dockerClient{api: api}).CountEnvContainers(context.Background()); err == nil {
		t.Fatal("want the list error surfaced")
	}
}

func TestEnsureVolumeInspectError(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, errors.New("daemon unreachable")
		},
	}
	err := (&dockerClient{api: api}).EnsureVolume(context.Background(), "routini-env-a", nil)
	if err == nil || !strings.Contains(err.Error(), "inspect volume") {
		t.Fatalf("got %v, want a wrapped inspect error", err)
	}
}

func TestEnsureVolumeCreateError(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{}, notFound()
		},
		volumeCreate: func(context.Context, volume.CreateOptions) (volume.Volume, error) {
			return volume.Volume{}, errors.New("no space left on device")
		},
	}
	err := (&dockerClient{api: api}).EnsureVolume(context.Background(), "routini-env-a", nil)
	if err == nil || !strings.Contains(err.Error(), "create volume") {
		t.Fatalf("got %v, want a wrapped create error", err)
	}
}

func TestRemoveVolumeRemoveError(t *testing.T) {
	api := &fakeAPI{
		volumeInspect: func(context.Context, string) (volume.Volume, error) {
			return volume.Volume{Labels: map[string]string{LabelManaged: "true"}}, nil
		},
		volumeRemove: func(context.Context, string, bool) error {
			return errors.New("volume is in use")
		},
	}
	err := (&dockerClient{api: api}).RemoveVolume(context.Background(), "routini-env-a")
	if err == nil || !strings.Contains(err.Error(), "remove volume") {
		t.Fatalf("got %v, want a wrapped remove error", err)
	}
}

func TestInspectEnvInspectError(t *testing.T) {
	api := &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{}, errors.New("daemon unreachable")
		},
	}
	_, err := (&dockerClient{api: api}).InspectEnv(context.Background(), "routini-env-a")
	if err == nil || !strings.Contains(err.Error(), "inspect container") {
		t.Fatalf("got %v, want a wrapped inspect error", err)
	}
}

func TestRemoveEnvContainerRemoveError(t *testing.T) {
	api := &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{
				Config: &container.Config{Labels: map[string]string{LabelManaged: "true", LabelEnvironment: "env-1"}},
			}, nil
		},
		containerRemove: func(context.Context, string, container.RemoveOptions) error {
			return errors.New("device busy")
		},
	}
	err := (&dockerClient{api: api}).RemoveEnvContainer(context.Background(), "env-id")
	if err == nil || !strings.Contains(err.Error(), "remove container") {
		t.Fatalf("got %v, want a wrapped remove error", err)
	}
}

func TestStartEnvContainerCreateError(t *testing.T) {
	api := &fakeAPI{
		containerCreate: func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{}, errors.New("name taken")
		},
	}
	id, err := (&dockerClient{api: api}).StartEnvContainer(context.Background(), validEnvSpec())
	if err == nil || !strings.Contains(err.Error(), "create container") {
		t.Fatalf("got %v, want a wrapped create error", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
}

func TestStartEnvContainerReportsRemovalFailureOnStartFailure(t *testing.T) {
	api := &fakeAPI{
		containerCreate: func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{ID: "env-id"}, nil
		},
		containerStart: func(context.Context, string, container.StartOptions) error {
			return errors.New("no such runtime")
		},
		containerRemove: func(context.Context, string, container.RemoveOptions) error {
			return errors.New("device busy")
		},
	}
	_, err := (&dockerClient{api: api}).StartEnvContainer(context.Background(), validEnvSpec())
	if err == nil || !strings.Contains(err.Error(), "no such runtime") || !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("got %v, want both the start and removal failures reported", err)
	}
}
