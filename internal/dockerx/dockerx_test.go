package dockerx

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
)

func TestNewHostSelection(t *testing.T) {
	cases := []struct {
		name       string
		dockerHost string
		envHost    string
		want       string
	}{
		{"configured host is used", "unix:///run/routini/docker.sock", "", "unix:///run/routini/docker.sock"},
		{"DOCKER_HOST wins", "unix:///run/routini/docker.sock", "unix:///run/env/docker.sock", "unix:///run/env/docker.sock"},
		{"env only", "", "unix:///run/env/docker.sock", "unix:///run/env/docker.sock"},
		{"neither: library default", "", "", client.DefaultDockerHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// An empty DOCKER_HOST reads as unset, both here and in the
			// docker client's own FromEnv option.
			t.Setenv(EnvDockerHost, tc.envHost)
			d, err := New(tc.dockerHost)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			api, ok := d.(*dockerClient).api.(*client.Client)
			if !ok {
				t.Fatalf("api is %T, want *client.Client", d.(*dockerClient).api)
			}
			if got := api.DaemonHost(); got != tc.want {
				t.Errorf("DaemonHost = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewRejectsBadHost(t *testing.T) {
	t.Setenv(EnvDockerHost, "")
	if _, err := New("::not a url::"); err == nil {
		t.Fatal("want an error for an unparseable docker host")
	} else if !strings.Contains(err.Error(), "dockerx:") {
		t.Errorf("error %q is not wrapped with context", err)
	}
}

func TestPing(t *testing.T) {
	t.Run("reports the daemon version", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{
			ping:          func(context.Context) (types.Ping, error) { return types.Ping{APIVersion: "1.47"}, nil },
			serverVersion: func(context.Context) (types.Version, error) { return types.Version{Version: "27.3.1"}, nil },
		}}
		got, err := d.Ping(context.Background())
		if err != nil {
			t.Fatalf("Ping: %v", err)
		}
		if got != "27.3.1" {
			t.Errorf("version = %q, want 27.3.1", got)
		}
	})

	t.Run("wraps an unreachable daemon", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{
			ping: func(context.Context) (types.Ping, error) {
				return types.Ping{}, errors.New("connection refused")
			},
		}}
		if _, err := d.Ping(context.Background()); err == nil {
			t.Fatal("want an error")
		} else if !strings.Contains(err.Error(), "ping docker daemon") {
			t.Errorf("error %q lacks context", err)
		}
	})

	t.Run("wraps a version failure", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{
			ping:          func(context.Context) (types.Ping, error) { return types.Ping{}, nil },
			serverVersion: func(context.Context) (types.Version, error) { return types.Version{}, errors.New("boom") },
		}}
		if _, err := d.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "read docker version") {
			t.Fatalf("got %v, want a wrapped version error", err)
		}
	})

	t.Run("rejects an empty version", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{
			ping:          func(context.Context) (types.Ping, error) { return types.Ping{}, nil },
			serverVersion: func(context.Context) (types.Version, error) { return types.Version{}, nil },
		}}
		if _, err := d.Ping(context.Background()); err == nil {
			t.Fatal("want an error when the daemon reports no version")
		}
	})
}

func TestPullPolicy(t *testing.T) {
	for _, in := range []string{"", PullMissing} {
		if got, err := pullPolicy(in); err != nil || got != PullMissing {
			t.Errorf("pullPolicy(%q) = %q, %v; want %q, nil", in, got, err, PullMissing)
		}
	}
	if got, err := pullPolicy(PullAlways); err != nil || got != PullAlways {
		t.Errorf("pullPolicy(always) = %q, %v", got, err)
	}
	if _, err := pullPolicy("Always"); err == nil {
		t.Error("the policy must be matched case-sensitively")
	}
	if _, err := pullPolicy("never"); err == nil {
		t.Error("want an error for an unknown policy")
	}
}

// trackedReader reports whether the pull stream was closed.
type trackedReader struct {
	io.Reader
	closed bool
}

func (r *trackedReader) Close() error {
	r.closed = true
	return nil
}

func TestEnsureImage(t *testing.T) {
	const ref = "ghcr.io/nvasion/routini-agent-claude:0.3.0"
	const progress = `{"status":"Pulling from nvasion/x"}` + "\n" + `{"status":"Download complete"}` + "\n"

	t.Run("missing: skips the pull when present", func(t *testing.T) {
		f := &fakeAPI{imageInspect: func(context.Context, string) (types.ImageInspect, []byte, error) {
			return types.ImageInspect{ID: "sha256:abc"}, nil, nil
		}}
		if err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, PullMissing); err != nil {
			t.Fatalf("EnsureImage: %v", err)
		}
		if want := []string{"ImageInspectWithRaw(" + ref + ")"}; !reflect.DeepEqual(f.log(), want) {
			t.Errorf("calls = %v, want %v", f.log(), want)
		}
	})

	t.Run("missing: pulls when absent", func(t *testing.T) {
		body := &trackedReader{Reader: strings.NewReader(progress)}
		f := &fakeAPI{
			imageInspect: func(context.Context, string) (types.ImageInspect, []byte, error) {
				return types.ImageInspect{}, nil, errdefs.NotFound(errors.New("no such image"))
			},
			imagePull: func(_ context.Context, _ string, opts image.PullOptions) (io.ReadCloser, error) {
				if opts.RegistryAuth != "" || opts.PrivilegeFunc != nil {
					t.Error("EnsureImage must not send registry credentials")
				}
				return body, nil
			},
		}
		if err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, ""); err != nil {
			t.Fatalf("EnsureImage: %v", err)
		}
		want := []string{"ImageInspectWithRaw(" + ref + ")", "ImagePull(" + ref + ")"}
		if !reflect.DeepEqual(f.log(), want) {
			t.Errorf("calls = %v, want %v", f.log(), want)
		}
		if !body.closed {
			t.Error("the pull stream must be closed")
		}
	})

	t.Run("always: pulls without inspecting", func(t *testing.T) {
		f := &fakeAPI{imagePull: func(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(progress)), nil
		}}
		if err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, PullAlways); err != nil {
			t.Fatalf("EnsureImage: %v", err)
		}
		if want := []string{"ImagePull(" + ref + ")"}; !reflect.DeepEqual(f.log(), want) {
			t.Errorf("calls = %v, want %v", f.log(), want)
		}
	})

	t.Run("reports a failure inside the progress stream", func(t *testing.T) {
		f := &fakeAPI{imagePull: func(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(
				`{"status":"Pulling"}` + "\n" + `{"errorDetail":{"message":"denied"},"error":"denied"}` + "\n")), nil
		}}
		err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, PullAlways)
		if err == nil {
			t.Fatal("want an error reported by the progress stream")
		}
		if !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), ref) {
			t.Errorf("error %q should name the cause and the reference", err)
		}
	})

	t.Run("wraps an inspect failure", func(t *testing.T) {
		f := &fakeAPI{imageInspect: func(context.Context, string) (types.ImageInspect, []byte, error) {
			return types.ImageInspect{}, nil, errors.New("boom")
		}}
		if err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, PullMissing); err == nil ||
			!strings.Contains(err.Error(), "inspect image") {
			t.Fatalf("got %v, want a wrapped inspect error", err)
		}
	})

	t.Run("wraps a pull failure", func(t *testing.T) {
		f := &fakeAPI{imagePull: func(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
			return nil, errors.New("manifest unknown")
		}}
		if err := (&dockerClient{api: f}).EnsureImage(context.Background(), ref, PullAlways); err == nil ||
			!strings.Contains(err.Error(), "pull image") {
			t.Fatalf("got %v, want a wrapped pull error", err)
		}
	})

	t.Run("rejects bad input before calling the daemon", func(t *testing.T) {
		for _, tc := range []struct{ ref, pull string }{
			{"", PullMissing},
			{"bad ref", PullMissing},
			{"ok:1", "sometimes"},
		} {
			if err := (&dockerClient{api: &fakeAPI{}}).EnsureImage(context.Background(), tc.ref, tc.pull); err == nil {
				t.Errorf("EnsureImage(%q, %q) = nil, want an error", tc.ref, tc.pull)
			}
		}
	})
}

func TestDrainPullProgress(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"empty", "", ""},
		{"progress only", `{"status":"a"}` + "\n" + `{"status":"b"}`, ""},
		{"error field", `{"error":"denied"}`, "denied"},
		{"error detail wins", `{"error":"short","errorDetail":{"message":"long reason"}}`, "long reason"},
		{"first error wins", `{"error":"first"}` + "\n" + `{"error":"second"}`, "first"},
		{"truncated json", `{"status":"a"} {"stat`, "read progress stream"},
		{"error then truncated json", `{"error":"denied"} {"stat`, "denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := drainPullProgress(strings.NewReader(tc.in))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestEnsureNetwork(t *testing.T) {
	const name = "routini-agents"
	labels := map[string]string{LabelManaged: "true"}

	t.Run("does nothing when it exists", func(t *testing.T) {
		f := &fakeAPI{networkInspect: func(context.Context, string, network.InspectOptions) (network.Inspect, error) {
			return network.Inspect{Name: name}, nil
		}}
		if err := (&dockerClient{api: f}).EnsureNetwork(context.Background(), name, labels); err != nil {
			t.Fatalf("EnsureNetwork: %v", err)
		}
		if want := []string{"NetworkInspect(" + name + ")"}; !reflect.DeepEqual(f.log(), want) {
			t.Errorf("calls = %v, want %v", f.log(), want)
		}
	})

	t.Run("creates an internal bridge network", func(t *testing.T) {
		var got network.CreateOptions
		f := &fakeAPI{
			networkInspect: func(context.Context, string, network.InspectOptions) (network.Inspect, error) {
				return network.Inspect{}, errdefs.NotFound(errors.New("no such network"))
			},
			networkCreate: func(_ context.Context, _ string, opts network.CreateOptions) (network.CreateResponse, error) {
				got = opts
				return network.CreateResponse{ID: "net-id"}, nil
			},
		}
		if err := (&dockerClient{api: f}).EnsureNetwork(context.Background(), name, labels); err != nil {
			t.Fatalf("EnsureNetwork: %v", err)
		}
		if got.Driver != "bridge" {
			t.Errorf("Driver = %q, want bridge", got.Driver)
		}
		if !got.Internal {
			t.Error("Internal = false, want true: agents must not reach the internet directly")
		}
		if !reflect.DeepEqual(got.Labels, labels) {
			t.Errorf("Labels = %v, want %v", got.Labels, labels)
		}
	})

	t.Run("tolerates a lost creation race", func(t *testing.T) {
		for _, raceErr := range []error{
			errdefs.Conflict(errors.New("network already exists")),
			errors.New(`network with name routini-agents already exists`),
		} {
			f := &fakeAPI{
				networkInspect: func(context.Context, string, network.InspectOptions) (network.Inspect, error) {
					return network.Inspect{}, errdefs.NotFound(errors.New("no such network"))
				},
				networkCreate: func(context.Context, string, network.CreateOptions) (network.CreateResponse, error) {
					return network.CreateResponse{}, raceErr
				},
			}
			if err := (&dockerClient{api: f}).EnsureNetwork(context.Background(), name, labels); err != nil {
				t.Errorf("EnsureNetwork with %v: %v", raceErr, err)
			}
		}
	})

	t.Run("reports an inspect failure", func(t *testing.T) {
		f := &fakeAPI{networkInspect: func(context.Context, string, network.InspectOptions) (network.Inspect, error) {
			return network.Inspect{}, errors.New("daemon gone")
		}}
		if err := (&dockerClient{api: f}).EnsureNetwork(context.Background(), name, labels); err == nil ||
			!strings.Contains(err.Error(), "inspect network") {
			t.Fatalf("got %v, want a wrapped inspect error", err)
		}
	})

	t.Run("reports other failures", func(t *testing.T) {
		f := &fakeAPI{
			networkInspect: func(context.Context, string, network.InspectOptions) (network.Inspect, error) {
				return network.Inspect{}, errdefs.NotFound(errors.New("no such network"))
			},
			networkCreate: func(context.Context, string, network.CreateOptions) (network.CreateResponse, error) {
				return network.CreateResponse{}, errors.New("out of subnets")
			},
		}
		if err := (&dockerClient{api: f}).EnsureNetwork(context.Background(), name, labels); err == nil ||
			!strings.Contains(err.Error(), "create network") {
			t.Fatalf("got %v, want a wrapped create error", err)
		}
	})

	t.Run("rejects bad input before calling the daemon", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{}}
		if err := d.EnsureNetwork(context.Background(), "", nil); err == nil {
			t.Error("want an error for an empty name")
		}
		if err := d.EnsureNetwork(context.Background(), "net work", nil); err == nil {
			t.Error("want an error for an invalid name")
		}
		if err := d.EnsureNetwork(context.Background(), "ok", map[string]string{"": "x"}); err == nil {
			t.Error("want an error for an invalid label")
		}
	})
}

func TestConnectNetwork(t *testing.T) {
	t.Run("passes the alias", func(t *testing.T) {
		var got *network.EndpointSettings
		f := &fakeAPI{networkConnect: func(_ context.Context, _, _ string, cfg *network.EndpointSettings) error {
			got = cfg
			return nil
		}}
		if err := (&dockerClient{api: f}).ConnectNetwork(context.Background(), "routini-agents", "routini-egress", "egress"); err != nil {
			t.Fatalf("ConnectNetwork: %v", err)
		}
		if want := []string{"egress"}; !reflect.DeepEqual(got.Aliases, want) {
			t.Errorf("Aliases = %v, want %v", got.Aliases, want)
		}
	})

	t.Run("omits an empty alias", func(t *testing.T) {
		var got *network.EndpointSettings
		f := &fakeAPI{networkConnect: func(_ context.Context, _, _ string, cfg *network.EndpointSettings) error {
			got = cfg
			return nil
		}}
		if err := (&dockerClient{api: f}).ConnectNetwork(context.Background(), "n", "c", ""); err != nil {
			t.Fatalf("ConnectNetwork: %v", err)
		}
		if len(got.Aliases) != 0 {
			t.Errorf("Aliases = %v, want none", got.Aliases)
		}
	})

	t.Run("tolerates an existing endpoint", func(t *testing.T) {
		for _, benign := range []error{
			errdefs.Conflict(errors.New("endpoint already exists")),
			errdefs.Forbidden(errors.New("container already connected")),
			errors.New("endpoint with name routini-egress already exists in network routini-agents"),
		} {
			f := &fakeAPI{networkConnect: func(context.Context, string, string, *network.EndpointSettings) error {
				return benign
			}}
			if err := (&dockerClient{api: f}).ConnectNetwork(context.Background(), "n", "c", "a"); err != nil {
				t.Errorf("ConnectNetwork with %v: %v", benign, err)
			}
		}
	})

	t.Run("reports other failures", func(t *testing.T) {
		f := &fakeAPI{networkConnect: func(context.Context, string, string, *network.EndpointSettings) error {
			return errdefs.NotFound(errors.New("no such network"))
		}}
		if err := (&dockerClient{api: f}).ConnectNetwork(context.Background(), "n", "c", "a"); err == nil ||
			!strings.Contains(err.Error(), "connect container") {
			t.Fatalf("got %v, want a wrapped connect error", err)
		}
	})

	t.Run("rejects bad input before calling the daemon", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{}}
		for _, tc := range []struct{ net, ctr, alias string }{
			{"", "c", "a"},
			{"n", "", "a"},
			{"n", "c", "bad alias"},
			{"n/../x", "c", "a"},
		} {
			if err := d.ConnectNetwork(context.Background(), tc.net, tc.ctr, tc.alias); err == nil {
				t.Errorf("ConnectNetwork(%q, %q, %q) = nil, want an error", tc.net, tc.ctr, tc.alias)
			}
		}
	})
}

func TestIsAlreadyThere(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"conflict", errdefs.Conflict(errors.New("boom")), true},
		{"message", errors.New("Network ALREADY EXISTS"), true},
		{"unrelated", errors.New("permission denied"), false},
		{"not found", errdefs.NotFound(errors.New("missing")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlreadyThere(tc.err); got != tc.want {
				t.Errorf("isAlreadyThere(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestStopOptions(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want int
	}{
		{0, 0},
		{-5 * time.Second, 0},
		{10 * time.Second, 10},
		{1500 * time.Millisecond, 2},
		{400 * time.Millisecond, 0},
	}
	for _, tc := range cases {
		got := stopOptions(tc.in)
		if got.Timeout == nil {
			t.Fatalf("stopOptions(%v) left Timeout nil, which would mean wait forever", tc.in)
		}
		if *got.Timeout != tc.want {
			t.Errorf("stopOptions(%v).Timeout = %d, want %d", tc.in, *got.Timeout, tc.want)
		}
	}
}

func TestStop(t *testing.T) {
	t.Run("stops then kills", func(t *testing.T) {
		f := &fakeAPI{
			containerStop: func(context.Context, string, container.StopOptions) error { return nil },
			containerKill: func(context.Context, string, string) error { return nil },
		}
		if err := (&dockerClient{api: f}).Stop(context.Background(), "agent-1", 5*time.Second); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		want := []string{"ContainerStop(agent-1,5)", "ContainerKill(agent-1,KILL)"}
		if !reflect.DeepEqual(f.log(), want) {
			t.Errorf("calls = %v, want %v", f.log(), want)
		}
	})

	t.Run("tolerates a missing or already exited container", func(t *testing.T) {
		f := &fakeAPI{
			containerStop: func(context.Context, string, container.StopOptions) error { return notFound() },
			containerKill: func(context.Context, string, string) error {
				return errdefs.Conflict(errors.New("container is not running"))
			},
		}
		if err := (&dockerClient{api: f}).Stop(context.Background(), "agent-1", time.Second); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	})

	t.Run("reports a stop failure", func(t *testing.T) {
		f := &fakeAPI{containerStop: func(context.Context, string, container.StopOptions) error {
			return errors.New("daemon busy")
		}}
		if err := (&dockerClient{api: f}).Stop(context.Background(), "agent-1", time.Second); err == nil ||
			!strings.Contains(err.Error(), "stop container") {
			t.Fatalf("got %v, want a wrapped stop error", err)
		}
	})

	t.Run("reports a kill failure", func(t *testing.T) {
		f := &fakeAPI{
			containerStop: func(context.Context, string, container.StopOptions) error { return nil },
			containerKill: func(context.Context, string, string) error { return errors.New("no permission") },
		}
		if err := (&dockerClient{api: f}).Stop(context.Background(), "agent-1", time.Second); err == nil ||
			!strings.Contains(err.Error(), "kill container") {
			t.Fatalf("got %v, want a wrapped kill error", err)
		}
	})

	t.Run("rejects a bad name before calling the daemon", func(t *testing.T) {
		if err := (&dockerClient{api: &fakeAPI{}}).Stop(context.Background(), "", time.Second); err == nil {
			t.Error("want an error for an empty name")
		}
	})
}

func TestKillByLabels(t *testing.T) {
	labels := map[string]string{LabelManaged: "true", "routini.run": "run-7"}

	t.Run("kills and removes every match", func(t *testing.T) {
		f := &fakeAPI{
			containerList: func(_ context.Context, opts container.ListOptions) ([]types.Container, error) {
				if !opts.All {
					t.Error("exited containers must be listed too")
				}
				if got := len(opts.Filters.Get("label")); got != len(labels) {
					t.Errorf("filtered on %d labels, want %d", got, len(labels))
				}
				return []types.Container{
					{ID: "aaaaaaaaaaaabbbb", Labels: labels},
					{ID: "ccccccccccccdddd", Labels: map[string]string{LabelManaged: "true", "routini.run": "run-7", "extra": "x"}},
				}, nil
			},
			containerKill:   func(context.Context, string, string) error { return nil },
			containerRemove: noopRemove,
		}
		if err := (&dockerClient{api: f}).KillByLabels(context.Background(), labels); err != nil {
			t.Fatalf("KillByLabels: %v", err)
		}
		// The recorded label filter follows map iteration order, so only the
		// calls after the list are compared.
		want := []string{
			"ContainerKill(aaaaaaaaaaaabbbb,KILL)",
			"ContainerRemove(aaaaaaaaaaaabbbb,force=true,volumes=false)",
			"ContainerKill(ccccccccccccdddd,KILL)",
			"ContainerRemove(ccccccccccccdddd,force=true,volumes=false)",
		}
		got := f.log()
		if len(got) == 0 || !strings.HasPrefix(got[0], "ContainerList(") {
			t.Fatalf("calls = %v, want the list call first", got)
		}
		if !reflect.DeepEqual(got[1:], want) {
			t.Errorf("calls after the list = %v, want %v", got[1:], want)
		}
	})

	t.Run("skips a container that lacks a label", func(t *testing.T) {
		f := &fakeAPI{
			containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
				return []types.Container{{ID: "unrelated", Labels: map[string]string{LabelManaged: "true"}}}, nil
			},
		}
		if err := (&dockerClient{api: f}).KillByLabels(context.Background(), labels); err != nil {
			t.Fatalf("KillByLabels: %v", err)
		}
		if len(f.log()) != 1 {
			t.Errorf("calls = %v, want the list call only", f.log())
		}
	})

	t.Run("tolerates containers that are already gone", func(t *testing.T) {
		f := &fakeAPI{
			containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
				return []types.Container{{ID: "gone", Labels: labels}}, nil
			},
			containerKill:   func(context.Context, string, string) error { return notFound() },
			containerRemove: func(context.Context, string, container.RemoveOptions) error { return notFound() },
		}
		if err := (&dockerClient{api: f}).KillByLabels(context.Background(), labels); err != nil {
			t.Fatalf("KillByLabels: %v", err)
		}
	})

	t.Run("collects failures and keeps going", func(t *testing.T) {
		f := &fakeAPI{
			containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
				return []types.Container{{ID: "one", Labels: labels}, {ID: "two", Labels: labels}}, nil
			},
			containerKill: func(_ context.Context, id, _ string) error {
				if id == "one" {
					return errors.New("kill refused")
				}
				return nil
			},
			containerRemove: func(_ context.Context, id string, _ container.RemoveOptions) error {
				return errors.New("remove refused")
			},
		}
		err := (&dockerClient{api: f}).KillByLabels(context.Background(), labels)
		if err == nil {
			t.Fatal("want an error")
		}
		for _, want := range []string{"kill refused", "remove refused"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("reports a list failure", func(t *testing.T) {
		f := &fakeAPI{containerList: func(context.Context, container.ListOptions) ([]types.Container, error) {
			return nil, errors.New("daemon gone")
		}}
		if err := (&dockerClient{api: f}).KillByLabels(context.Background(), labels); err == nil ||
			!strings.Contains(err.Error(), "list containers by label") {
			t.Fatalf("got %v, want a wrapped list error", err)
		}
	})

	t.Run("refuses an empty label set", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{}}
		for _, in := range []map[string]string{nil, {}} {
			if err := d.KillByLabels(context.Background(), in); err == nil {
				t.Error("an empty label set would match every container and must be refused")
			}
		}
	})

	t.Run("rejects an invalid label", func(t *testing.T) {
		d := &dockerClient{api: &fakeAPI{}}
		if err := d.KillByLabels(context.Background(), map[string]string{"a=b": "x"}); err == nil {
			t.Error("want an error for a label key containing '='")
		}
	})
}
