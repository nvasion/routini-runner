package dockerx

import (
	"reflect"
	"strings"
	"testing"
)

func validSpec() RunSpec {
	return RunSpec{
		Name:      "routini-agent-task",
		Image:     "ghcr.io/nvasion/routini-agent-claude:0.3.0",
		Network:   "routini-agents",
		Env:       map[string]string{"ROUTINI_PROMPT": "hi"},
		Labels:    map[string]string{LabelManaged: "true"},
		Cpus:      2,
		MemoryMb:  4096,
		PidsLimit: 512,
	}
}

func TestContainerConfigHardening(t *testing.T) {
	// Everything optional left at its zero value: the defaults must still
	// produce a locked-down container.
	cfg, host := containerConfig(RunSpec{Name: "a", Image: "img"})

	if cfg.User != DefaultUser {
		t.Errorf("User = %q, want %q", cfg.User, DefaultUser)
	}
	if host.PidsLimit == nil {
		t.Fatal("PidsLimit is nil, want the default")
	}
	if *host.PidsLimit != DefaultPidsLimit {
		t.Errorf("PidsLimit = %d, want %d", *host.PidsLimit, DefaultPidsLimit)
	}
	if want := []string{"ALL"}; !reflect.DeepEqual([]string(host.CapDrop), want) {
		t.Errorf("CapDrop = %v, want %v", host.CapDrop, want)
	}
	if want := []string{"no-new-privileges:true"}; !reflect.DeepEqual(host.SecurityOpt, want) {
		t.Errorf("SecurityOpt = %v, want %v", host.SecurityOpt, want)
	}
	if host.AutoRemove {
		t.Error("AutoRemove = true, want false: RunStreaming removes the container itself")
	}
	if host.Privileged {
		t.Error("Privileged = true, want false")
	}
	if len(host.CapAdd) != 0 {
		t.Errorf("CapAdd = %v, want none", host.CapAdd)
	}
	if host.Runtime != "" {
		t.Errorf("Runtime = %q, want Docker's default", host.Runtime)
	}
	if host.Memory != 0 || host.NanoCPUs != 0 {
		t.Errorf("Memory = %d, NanoCPUs = %d, want both unlimited", host.Memory, host.NanoCPUs)
	}
	if !cfg.AttachStdout || !cfg.AttachStderr {
		t.Error("stdout and stderr must be attached")
	}
	if cfg.Tty {
		t.Error("Tty = true, want false so stdout and stderr stay separable")
	}
	if cfg.AttachStdin || cfg.OpenStdin {
		t.Error("stdin must not be attached")
	}
}

func TestContainerConfigMapping(t *testing.T) {
	spec := validSpec()
	spec.User = "4000:4000"
	spec.Runtime = "runsc"
	spec.PidsLimit = 256
	spec.Cpus = 1.5
	spec.Env = map[string]string{"B": "2", "A": "1", "C": "3"}

	cfg, host := containerConfig(spec)

	if cfg.Image != spec.Image {
		t.Errorf("Image = %q, want %q", cfg.Image, spec.Image)
	}
	if cfg.User != "4000:4000" {
		t.Errorf("User = %q, want the spec's user", cfg.User)
	}
	if want := []string{"A=1", "B=2", "C=3"}; !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v sorted by key", cfg.Env, want)
	}
	if !reflect.DeepEqual(cfg.Labels, spec.Labels) {
		t.Errorf("Labels = %v, want %v", cfg.Labels, spec.Labels)
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

func TestContainerConfigCopiesMaps(t *testing.T) {
	spec := validSpec()
	cfg, _ := containerConfig(spec)

	spec.Labels["routini.org"] = "late"
	if _, ok := cfg.Labels["routini.org"]; ok {
		t.Error("mutating the spec's labels changed the container config")
	}
	cfg.Labels["injected"] = "x"
	if _, ok := spec.Labels["injected"]; ok {
		t.Error("mutating the container config changed the spec's labels")
	}
}

func TestContainerConfigEmptyMaps(t *testing.T) {
	cfg, _ := containerConfig(RunSpec{Name: "a", Image: "img", Env: map[string]string{}, Labels: map[string]string{}})
	if cfg.Env != nil {
		t.Errorf("Env = %v, want nil for an empty map", cfg.Env)
	}
	if cfg.Labels != nil {
		t.Errorf("Labels = %v, want nil for an empty map", cfg.Labels)
	}
}

func TestRunSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RunSpec)
		wantErr string
	}{
		{"valid", func(*RunSpec) {}, ""},
		{"no name", func(s *RunSpec) { s.Name = "" }, "container name is missing"},
		{"name with slash", func(s *RunSpec) { s.Name = "../etc" }, "invalid container name"},
		{"name with space", func(s *RunSpec) { s.Name = "a b" }, "invalid container name"},
		{"no image", func(s *RunSpec) { s.Image = "" }, "image reference is missing"},
		{"image with space", func(s *RunSpec) { s.Image = "img; rm -rf /" }, "invalid image reference"},
		{"image too long", func(s *RunSpec) { s.Image = "a" + strings.Repeat("b", maxRefLen) }, "longer than"},
		{"bad user", func(s *RunSpec) { s.User = "root:root:root" }, "invalid user"},
		{"bad network", func(s *RunSpec) { s.Network = "net work" }, "invalid network name"},
		{"bad runtime", func(s *RunSpec) { s.Runtime = "runsc; sh" }, "invalid runtime"},
		{"bad env key", func(s *RunSpec) { s.Env = map[string]string{"1BAD": "x"} }, "invalid env key"},
		{"env value with NUL", func(s *RunSpec) { s.Env = map[string]string{"K": "a\x00b"} }, "contains a NUL"},
		// Multi-line values are normal: the egress CA (ROUTINI_CA_PEM) and prompts.
		{"multi-line env value", func(s *RunSpec) {
			s.Env = map[string]string{"ROUTINI_CA_PEM": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "ROUTINI_PROMPT": "line one\nline two"}
		}, ""},
		{"empty label key", func(s *RunSpec) { s.Labels = map[string]string{"": "x"} }, "label key is empty"},
		{"label key with equals", func(s *RunSpec) { s.Labels = map[string]string{"a=b": "x"} }, "invalid label key"},
		{"label value with NUL", func(s *RunSpec) { s.Labels = map[string]string{"a": "b\x00"} }, "NUL or newline"},
		{"negative cpus", func(s *RunSpec) { s.Cpus = -1 }, "cpus must not be negative"},
		{"negative memory", func(s *RunSpec) { s.MemoryMb = -1 }, "memoryMb must not be negative"},
		{"negative pids", func(s *RunSpec) { s.PidsLimit = -1 }, "pidsLimit must not be negative"},
		{"empty user is allowed", func(s *RunSpec) { s.User = "" }, ""},
		{"empty network is allowed", func(s *RunSpec) { s.Network = "" }, ""},
		{"digest reference", func(s *RunSpec) {
			s.Image = "ghcr.io/nvasion/agent@sha256:" + strings.Repeat("a", 64)
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec()
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

func TestRunSpecValidateKeepsEnvValuesOutOfErrors(t *testing.T) {
	const secret = "sk-super-secret"
	spec := validSpec()
	spec.Env = map[string]string{"1BAD": secret}
	err := spec.validate()
	if err == nil {
		t.Fatal("want an error for an invalid env key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the env value: %v", err)
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("0123456789abcdef0123"); got != "0123456789ab" {
		t.Errorf("shortID = %q, want the first 12 characters", got)
	}
	if got := shortID("short"); got != "short" {
		t.Errorf("shortID = %q, want %q unchanged", got, "short")
	}
}

func TestHasAllLabels(t *testing.T) {
	have := map[string]string{"a": "1", "b": "2"}
	if !hasAllLabels(have, map[string]string{"a": "1"}) {
		t.Error("subset should match")
	}
	if hasAllLabels(have, map[string]string{"a": "1", "c": "3"}) {
		t.Error("missing key should not match")
	}
	if hasAllLabels(have, map[string]string{"a": "9"}) {
		t.Error("different value should not match")
	}
}
