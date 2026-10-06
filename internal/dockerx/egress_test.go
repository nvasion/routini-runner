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
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/nat"
)

const (
	testEgressImage  = "ghcr.io/nvasion/routini-egress:0.3.0"
	testEgressSecret = "s3cr3t"
)

func notFound() error { return errdefs.NotFound(errors.New("No such container")) }

// egressContainer builds an inspect response for the egress container.
func egressContainer(image, secret string, running bool, hostIP, hostPort string) types.ContainerJSON {
	return types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:    "egress-id",
			Name:  "/" + EgressContainerName,
			State: &types.ContainerState{Running: running},
		},
		Config: &container.Config{
			Image: image,
			Env: []string{
				egressSecretEnv + "=" + secret,
				egressCADirEnv + "=" + EgressCADir,
			},
		},
		NetworkSettings: &types.NetworkSettings{
			NetworkSettingsBase: types.NetworkSettingsBase{
				Ports: nat.PortMap{
					EgressControlPort: []nat.PortBinding{{HostIP: hostIP, HostPort: hostPort}},
				},
			},
		},
	}
}

// egressFake counts what EnsureEgress did to the daemon.
type egressFake struct {
	inspect  func(id string) (types.ContainerJSON, error)
	onStart  func(id string)
	onRemove func(id string)

	created        int
	started        int
	removed        int
	removedVolumes bool

	api *fakeAPI
}

func newEgressFake(t *testing.T) *egressFake {
	t.Helper()
	f := &egressFake{}
	f.api = &fakeAPI{
		containerInspect: func(_ context.Context, id string) (types.ContainerJSON, error) {
			if f.inspect == nil {
				return types.ContainerJSON{}, notFound()
			}
			return f.inspect(id)
		},
		containerCreate: func(_ context.Context, _ *container.Config, _ *container.HostConfig, _ *network.NetworkingConfig, name string) (container.CreateResponse, error) {
			if name != EgressContainerName {
				t.Errorf("created container %q, want %q", name, EgressContainerName)
			}
			f.created++
			return container.CreateResponse{ID: "created-id"}, nil
		},
		containerStart: func(_ context.Context, id string, _ container.StartOptions) error {
			f.started++
			if f.onStart != nil {
				f.onStart(id)
			}
			return nil
		},
		containerRemove: func(_ context.Context, id string, opts container.RemoveOptions) error {
			f.removed++
			f.removedVolumes = f.removedVolumes || opts.RemoveVolumes
			if f.onRemove != nil {
				f.onRemove(id)
			}
			return nil
		},
	}
	return f
}

func (f *egressFake) docker() Docker { return &dockerClient{api: f.api} }

func TestEgressConfig(t *testing.T) {
	cfg, host := egressConfig(testEgressImage, testEgressSecret)

	if cfg.Image != testEgressImage {
		t.Errorf("Image = %q, want %q", cfg.Image, testEgressImage)
	}
	if want := []string{"node", "dist/egress.js"}; !reflect.DeepEqual([]string(cfg.Cmd), want) {
		t.Errorf("Cmd = %v, want %v", cfg.Cmd, want)
	}
	wantEnv := []string{
		"ROUTINI_EGRESS_SECRET=" + testEgressSecret,
		"ROUTINI_EGRESS_CA_DIR=/var/lib/routini-egress",
	}
	if !reflect.DeepEqual(cfg.Env, wantEnv) {
		t.Errorf("Env = %v, want %v", cfg.Env, wantEnv)
	}
	wantLabels := map[string]string{"routini.managed": "true", "routini.role": "egress"}
	if !reflect.DeepEqual(cfg.Labels, wantLabels) {
		t.Errorf("Labels = %v, want %v", cfg.Labels, wantLabels)
	}

	// The control port is published on loopback only, with an ephemeral host
	// port, and the proxy port is never published.
	if _, ok := cfg.ExposedPorts[EgressControlPort]; !ok {
		t.Errorf("ExposedPorts = %v, want %s", cfg.ExposedPorts, EgressControlPort)
	}
	if _, ok := cfg.ExposedPorts[EgressProxyPort]; ok {
		t.Errorf("ExposedPorts = %v, must not expose %s", cfg.ExposedPorts, EgressProxyPort)
	}
	if _, ok := host.PortBindings[EgressProxyPort]; ok {
		t.Errorf("PortBindings = %v, must not publish %s", host.PortBindings, EgressProxyPort)
	}
	bindings := host.PortBindings[EgressControlPort]
	if len(bindings) != 1 {
		t.Fatalf("PortBindings[%s] = %v, want exactly one binding", EgressControlPort, bindings)
	}
	if bindings[0].HostIP != "127.0.0.1" {
		t.Errorf("HostIP = %q, want 127.0.0.1", bindings[0].HostIP)
	}
	if bindings[0].HostPort != "" {
		t.Errorf("HostPort = %q, want an ephemeral port", bindings[0].HostPort)
	}

	if host.RestartPolicy.Name != container.RestartPolicyUnlessStopped {
		t.Errorf("RestartPolicy = %q, want unless-stopped", host.RestartPolicy.Name)
	}
	wantMount := mount.Mount{Type: mount.TypeVolume, Source: EgressCAVolume, Target: EgressCADir}
	if !reflect.DeepEqual(host.Mounts, []mount.Mount{wantMount}) {
		t.Errorf("Mounts = %v, want %v", host.Mounts, wantMount)
	}
	if host.Privileged || len(host.CapAdd) != 0 {
		t.Error("the egress container must not be privileged")
	}
}

func TestEgressDrifted(t *testing.T) {
	cases := []struct {
		name string
		in   types.ContainerJSON
		want bool
	}{
		{"same image and secret", egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "4711"), false},
		{"other image", egressContainer("ghcr.io/nvasion/routini-egress:0.2.0", testEgressSecret, true, loopbackIP, "4711"), true},
		{"other secret", egressContainer(testEgressImage, "rotated", true, loopbackIP, "4711"), true},
		{"no secret", egressContainer(testEgressImage, "", true, loopbackIP, "4711"), true},
		{"no config", types.ContainerJSON{ContainerJSONBase: &types.ContainerJSONBase{ID: "x"}}, true},
		{"no base", types.ContainerJSON{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := egressDrifted(tc.in, testEgressImage, testEgressSecret); got != tc.want {
				t.Errorf("egressDrifted = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestEnvValue(t *testing.T) {
	env := []string{"A=1", "NOEQUALS", "B=with=equals", "C="}
	cases := map[string]string{"A": "1", "B": "with=equals", "C": "", "NOEQUALS": "", "MISSING": ""}
	for key, want := range cases {
		if got := envValue(env, key); got != want {
			t.Errorf("envValue(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestEnsureEgressCreatesWhenAbsent(t *testing.T) {
	f := newEgressFake(t)
	f.inspect = func(id string) (types.ContainerJSON, error) {
		if id == EgressContainerName {
			return types.ContainerJSON{}, notFound()
		}
		return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "4711"), nil
	}

	url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if url != "http://127.0.0.1:4711" {
		t.Errorf("controlURL = %q, want http://127.0.0.1:4711", url)
	}
	if f.created != 1 || f.started != 1 {
		t.Errorf("created %d and started %d containers, want 1 and 1", f.created, f.started)
	}
	if f.removed != 0 {
		t.Error("nothing should be removed when no container exists")
	}
}

func TestEnsureEgressReusesMatchingContainer(t *testing.T) {
	f := newEgressFake(t)
	f.inspect = func(string) (types.ContainerJSON, error) {
		return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "5000"), nil
	}

	url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if url != "http://127.0.0.1:5000" {
		t.Errorf("controlURL = %q, want http://127.0.0.1:5000", url)
	}
	if f.created != 0 || f.removed != 0 || f.started != 0 {
		t.Errorf("created %d, removed %d, started %d; a matching running container must be left alone",
			f.created, f.removed, f.started)
	}
}

func TestEnsureEgressStartsStoppedContainer(t *testing.T) {
	f := newEgressFake(t)
	running := false
	f.inspect = func(string) (types.ContainerJSON, error) {
		return egressContainer(testEgressImage, testEgressSecret, running, loopbackIP, "5001"), nil
	}
	f.onStart = func(string) { running = true }

	url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if url != "http://127.0.0.1:5001" {
		t.Errorf("controlURL = %q, want http://127.0.0.1:5001", url)
	}
	if f.started != 1 {
		t.Errorf("started %d times, want 1", f.started)
	}
	if f.created != 0 || f.removed != 0 {
		t.Error("a matching stopped container must be started, not replaced")
	}
}

func TestEnsureEgressRecreatesOnDrift(t *testing.T) {
	cases := []struct {
		name          string
		image, secret string
	}{
		{"new image", "ghcr.io/nvasion/routini-egress:0.1.0", testEgressSecret},
		{"rotated secret", testEgressImage, "old-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newEgressFake(t)
			stale := true
			f.inspect = func(id string) (types.ContainerJSON, error) {
				if id == EgressContainerName && stale {
					return egressContainer(tc.image, tc.secret, true, loopbackIP, "1"), nil
				}
				return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "6000"), nil
			}
			f.onRemove = func(string) { stale = false }

			url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
			if err != nil {
				t.Fatalf("EnsureEgress: %v", err)
			}
			if url != "http://127.0.0.1:6000" {
				t.Errorf("controlURL = %q, want the new container's port", url)
			}
			if f.removed != 1 || f.created != 1 {
				t.Errorf("removed %d and created %d containers, want 1 and 1", f.removed, f.created)
			}
			if f.removedVolumes {
				t.Error("the CA volume must survive a recreation")
			}
		})
	}
}

func TestEnsureEgressReplacesContainerWithoutLoopbackBinding(t *testing.T) {
	f := newEgressFake(t)
	bad := true
	f.inspect = func(string) (types.ContainerJSON, error) {
		if bad {
			// Published on every interface: unusable, must be replaced.
			return egressContainer(testEgressImage, testEgressSecret, true, "0.0.0.0", "7000"), nil
		}
		return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "7001"), nil
	}
	f.onRemove = func(string) { bad = false }

	url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err != nil {
		t.Fatalf("EnsureEgress: %v", err)
	}
	if url != "http://127.0.0.1:7001" {
		t.Errorf("controlURL = %q, want the replacement's port", url)
	}
	if f.removed != 1 || f.created != 1 {
		t.Errorf("removed %d and created %d containers, want 1 and 1", f.removed, f.created)
	}
}

func TestEnsureEgressReportsInspectFailure(t *testing.T) {
	f := newEgressFake(t)
	f.inspect = func(string) (types.ContainerJSON, error) {
		return types.ContainerJSON{}, errors.New("daemon gone")
	}

	_, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
	if err == nil {
		t.Fatal("want an error when the container cannot be inspected")
	}
	if !strings.Contains(err.Error(), "daemon gone") {
		t.Errorf("error %q does not wrap the cause", err)
	}
	if strings.Contains(err.Error(), testEgressSecret) {
		t.Errorf("error leaks the egress secret: %v", err)
	}
	if f.created != 0 {
		t.Error("a failed inspect must not create a container")
	}
}

func TestEnsureEgressFailurePaths(t *testing.T) {
	absent := func(id string) (types.ContainerJSON, error) {
		if id == EgressContainerName {
			return types.ContainerJSON{}, notFound()
		}
		return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "4711"), nil
	}

	t.Run("create fails", func(t *testing.T) {
		f := newEgressFake(t)
		f.inspect = absent
		f.api.containerCreate = func(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, string) (container.CreateResponse, error) {
			return container.CreateResponse{}, errors.New("name taken")
		}
		if _, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret); err == nil ||
			!strings.Contains(err.Error(), "create container") {
			t.Fatalf("got %v, want a wrapped create error", err)
		}
	})

	t.Run("start fails", func(t *testing.T) {
		f := newEgressFake(t)
		f.inspect = absent
		f.api.containerStart = func(context.Context, string, container.StartOptions) error {
			return errors.New("port already allocated")
		}
		if _, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret); err == nil ||
			!strings.Contains(err.Error(), "start container") {
			t.Fatalf("got %v, want a wrapped start error", err)
		}
	})

	t.Run("restarting a stopped container fails", func(t *testing.T) {
		f := newEgressFake(t)
		f.inspect = func(string) (types.ContainerJSON, error) {
			return egressContainer(testEgressImage, testEgressSecret, false, loopbackIP, "5001"), nil
		}
		f.api.containerStart = func(context.Context, string, container.StartOptions) error {
			return errors.New("cgroup error")
		}
		// The start failure makes the container unusable, so it is replaced;
		// the replacement cannot start either, and that error is reported.
		_, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
		if err == nil || !strings.Contains(err.Error(), "start container") {
			t.Fatalf("got %v, want a wrapped start error", err)
		}
		if f.removed != 1 {
			t.Errorf("removed %d containers, want the unusable one replaced", f.removed)
		}
	})

	t.Run("reports both the unusable container and the failed removal", func(t *testing.T) {
		f := newEgressFake(t)
		f.inspect = func(string) (types.ContainerJSON, error) {
			// Up to date, but published on every interface.
			return egressContainer(testEgressImage, testEgressSecret, true, "0.0.0.0", "7000"), nil
		}
		f.api.containerRemove = func(context.Context, string, container.RemoveOptions) error {
			return errors.New("device busy")
		}
		_, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
		if err == nil {
			t.Fatal("want an error")
		}
		for _, want := range []string{"binding on 127.0.0.1", "device busy"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
		if f.created != 0 {
			t.Error("no replacement must be created while the old one is still there")
		}
	})

	t.Run("remove of a drifted container fails", func(t *testing.T) {
		f := newEgressFake(t)
		f.inspect = func(string) (types.ContainerJSON, error) {
			return egressContainer("other-image:1", testEgressSecret, true, loopbackIP, "1"), nil
		}
		f.api.containerRemove = func(context.Context, string, container.RemoveOptions) error {
			return errors.New("device busy")
		}
		if _, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret); err == nil ||
			!strings.Contains(err.Error(), "remove container") {
			t.Fatalf("got %v, want a wrapped remove error", err)
		}
	})

	t.Run("remove tolerates a container that is already gone", func(t *testing.T) {
		f := newEgressFake(t)
		stale := true
		f.inspect = func(id string) (types.ContainerJSON, error) {
			if id == EgressContainerName && stale {
				return egressContainer("other-image:1", testEgressSecret, true, loopbackIP, "1"), nil
			}
			return egressContainer(testEgressImage, testEgressSecret, true, loopbackIP, "6000"), nil
		}
		f.api.containerRemove = func(context.Context, string, container.RemoveOptions) error {
			stale = false
			f.removed++
			return notFound()
		}
		url, err := f.docker().EnsureEgress(context.Background(), testEgressImage, testEgressSecret)
		if err != nil {
			t.Fatalf("EnsureEgress: %v", err)
		}
		if url != "http://127.0.0.1:6000" {
			t.Errorf("controlURL = %q, want the replacement's port", url)
		}
	})
}

func TestEnsureEgressValidation(t *testing.T) {
	cases := []struct {
		name          string
		image, secret string
		wantErr       string
	}{
		{"no image", "", testEgressSecret, "image reference is missing"},
		{"bad image", "egress image", testEgressSecret, "invalid image reference"},
		{"no secret", testEgressImage, "", "egress secret is missing"},
		{"secret with newline", testEgressImage, "a\nb", "NUL or newline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No hooks are set, so touching the daemon at all would error out.
			d := &dockerClient{api: &fakeAPI{}}
			_, err := d.EnsureEgress(context.Background(), tc.image, tc.secret)
			if err == nil {
				t.Fatalf("want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestEgressControlURLErrors(t *testing.T) {
	cases := []struct {
		name  string
		ports nat.PortMap
	}{
		{"no binding at all", nil},
		{"bound to every interface", nat.PortMap{EgressControlPort: []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "8080"}}}},
		{"no host port", nat.PortMap{EgressControlPort: []nat.PortBinding{{HostIP: loopbackIP}}}},
		{"host port out of range", nat.PortMap{EgressControlPort: []nat.PortBinding{{HostIP: loopbackIP, HostPort: "99999"}}}},
		{"only the proxy port", nat.PortMap{EgressProxyPort: []nat.PortBinding{{HostIP: loopbackIP, HostPort: "3128"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &dockerClient{api: &fakeAPI{
				containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						ContainerJSONBase: &types.ContainerJSONBase{ID: "x"},
						NetworkSettings: &types.NetworkSettings{
							NetworkSettingsBase: types.NetworkSettingsBase{Ports: tc.ports},
						},
					}, nil
				},
			}}
			if _, err := d.egressControlURL(context.Background(), "x"); err == nil {
				t.Fatal("want an error for an unusable control port")
			}
		})
	}
}

func TestEgressControlURLInspectFailure(t *testing.T) {
	d := &dockerClient{api: &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{}, errors.New("daemon gone")
		},
	}}
	if _, err := d.egressControlURL(context.Background(), "x"); err == nil ||
		!strings.Contains(err.Error(), "inspect container") {
		t.Fatalf("got %v, want a wrapped inspect error", err)
	}
}

func TestEgressControlURLWithoutNetworkSettings(t *testing.T) {
	d := &dockerClient{api: &fakeAPI{
		containerInspect: func(context.Context, string) (types.ContainerJSON, error) {
			return types.ContainerJSON{ContainerJSONBase: &types.ContainerJSONBase{ID: "x"}}, nil
		},
	}}
	if _, err := d.egressControlURL(context.Background(), "x"); err == nil {
		t.Fatal("want an error when the daemon reports no network settings")
	}
}
