package dockerx

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
)

const (
	bytesPerMiB    = 1024 * 1024
	nanoCPUsPerCPU = 1e9

	// maxRefLen bounds an image reference; the Engine API's own limit is far
	// higher, this only keeps absurd input out of request URLs.
	maxRefLen = 512
)

// Field syntax accepted by this package. Values reach the Engine API inside
// request paths and query strings, so they are validated before being sent
// rather than relying on the daemon to reject them.
var (
	// nameRe is Docker's own container, network and volume name rule.
	nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	// envKeyRe matches the POSIX environment variable names execx also accepts.
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// userRe matches "user", "uid", "user:group" and "uid:gid".
	userRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(:[a-zA-Z0-9_.-]+)?$`)
	// runtimeRe matches an OCI runtime name such as "runc" or "runsc".
	runtimeRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	// refRe matches an image reference: registry, repository, tag and digest
	// characters only, so no shell or URL metacharacters can slip through.
	refRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/@-]*$`)
	// envNameRe matches an environment container or volume name.
	envNameRe = regexp.MustCompile(`^routini-env-[a-z0-9-]{1,80}$`)
	// envNetworkRe matches an environment's sandbox network name.
	envNetworkRe = regexp.MustCompile(`^routini-sb-[A-Za-z0-9-]{1,80}$`)
)

// validate checks every field that is interpolated into an Engine API request
// or into the container's configuration. Error messages name the offending
// field but never echo an environment value, which may hold a credential.
func (s RunSpec) validate() error {
	if err := validateName("container name", s.Name); err != nil {
		return err
	}
	if err := validateRef(s.Image); err != nil {
		return err
	}
	if s.User != "" && !userRe.MatchString(s.User) {
		return fmt.Errorf("dockerx: invalid user %q", s.User)
	}
	if s.Network != "" {
		if err := validateName("network name", s.Network); err != nil {
			return err
		}
	}
	if s.Runtime != "" && !runtimeRe.MatchString(s.Runtime) {
		return fmt.Errorf("dockerx: invalid runtime %q", s.Runtime)
	}
	if err := validateEnv(s.Env); err != nil {
		return err
	}
	if err := validateLabels(s.Labels); err != nil {
		return err
	}
	if s.Cpus < 0 {
		return fmt.Errorf("dockerx: cpus must not be negative (got %v)", s.Cpus)
	}
	if s.MemoryMb < 0 {
		return fmt.Errorf("dockerx: memoryMb must not be negative (got %d)", s.MemoryMb)
	}
	if s.PidsLimit < 0 {
		return fmt.Errorf("dockerx: pidsLimit must not be negative (got %d)", s.PidsLimit)
	}
	return nil
}

func validateName(kind, name string) error {
	return validatePattern(kind, name, nameRe)
}

// validatePattern checks that value is non-empty and matches re, naming the
// field in both error cases without echoing values that might be secrets
// (callers only use this for names, never for env or label values).
func validatePattern(kind, value string, re *regexp.Regexp) error {
	if value == "" {
		return fmt.Errorf("dockerx: %s is missing", kind)
	}
	if !re.MatchString(value) {
		return fmt.Errorf("dockerx: invalid %s %q", kind, value)
	}
	return nil
}

func validateRef(ref string) error {
	if ref == "" {
		return errors.New("dockerx: image reference is missing")
	}
	if len(ref) > maxRefLen {
		return fmt.Errorf("dockerx: image reference is longer than %d bytes", maxRefLen)
	}
	if !refRe.MatchString(ref) {
		return fmt.Errorf("dockerx: invalid image reference %q", ref)
	}
	return nil
}

// validateEnv allows newlines in values: the Engine API carries Env as JSON,
// and agents need multi-line values (ROUTINI_CA_PEM, prompts). Only NUL, which
// cannot appear in a process environment, is refused.
func validateEnv(env map[string]string) error {
	for k, v := range env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("dockerx: invalid env key %q", k)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("dockerx: env value for %q contains a NUL", k)
		}
	}
	return nil
}

func validateLabels(labels map[string]string) error {
	for k, v := range labels {
		if k == "" {
			return errors.New("dockerx: label key is empty")
		}
		if strings.ContainsAny(k, "\x00\n=") {
			return fmt.Errorf("dockerx: invalid label key %q", k)
		}
		if strings.ContainsAny(v, "\x00\n") {
			return fmt.Errorf("dockerx: label value for %q contains a NUL or newline", k)
		}
	}
	return nil
}

// validateEnvLabels applies validateLabels and then requires the two labels
// every environment container and volume must carry: without them,
// RemoveVolume, RemoveEnvContainer and CountEnvContainers could not tell a
// Routini environment apart from an unrelated object on the same host.
func validateEnvLabels(labels map[string]string) error {
	if err := validateLabels(labels); err != nil {
		return err
	}
	if labels[LabelManaged] != "true" {
		return fmt.Errorf("dockerx: labels must include %s=true", LabelManaged)
	}
	if labels[LabelEnvironment] == "" {
		return fmt.Errorf("dockerx: labels must include a non-empty %s", LabelEnvironment)
	}
	return nil
}

// validate checks every field of an EnvSpec before it reaches the Engine
// API, the same way RunSpec.validate does.
func (s EnvSpec) validate() error {
	if err := validatePattern("environment name", s.Name, envNameRe); err != nil {
		return err
	}
	if err := validatePattern("volume name", s.Volume, envNameRe); err != nil {
		return err
	}
	if err := validatePattern("network name", s.Network, envNetworkRe); err != nil {
		return err
	}
	if err := validateRef(s.Image); err != nil {
		return err
	}
	if s.Runtime != "" && !runtimeRe.MatchString(s.Runtime) {
		return fmt.Errorf("dockerx: invalid runtime %q", s.Runtime)
	}
	if err := validateEnv(s.Env); err != nil {
		return err
	}
	if err := validateEnvLabels(s.Labels); err != nil {
		return err
	}
	if s.Cpus < 0 {
		return fmt.Errorf("dockerx: cpus must not be negative (got %v)", s.Cpus)
	}
	if s.MemoryMb < 0 {
		return fmt.Errorf("dockerx: memoryMb must not be negative (got %d)", s.MemoryMb)
	}
	if s.PidsLimit < 0 {
		return fmt.Errorf("dockerx: pidsLimit must not be negative (got %d)", s.PidsLimit)
	}
	return nil
}

// containerConfig maps a validated RunSpec onto the Engine API's create
// payload. It is pure: every hardening default lives here and nowhere else.
func containerConfig(spec RunSpec) (*container.Config, *container.HostConfig) {
	user := spec.User
	if user == "" {
		user = DefaultUser
	}
	pids := spec.PidsLimit
	if pids == 0 {
		pids = DefaultPidsLimit
	}
	cfg := &container.Config{
		Image:        spec.Image,
		User:         user,
		Env:          envSlice(spec.Env),
		Labels:       copyLabels(spec.Labels),
		AttachStdout: true,
		AttachStderr: true,
	}
	host := &container.HostConfig{
		NetworkMode: container.NetworkMode(spec.Network),
		CapDrop:     strslice.StrSlice{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Runtime:     spec.Runtime,
		AutoRemove:  false,
		Resources: container.Resources{
			Memory:    spec.MemoryMb * bytesPerMiB,
			NanoCPUs:  int64(spec.Cpus * nanoCPUsPerCPU),
			PidsLimit: &pids,
		},
	}
	return cfg, host
}

// envContainerConfig maps a validated EnvSpec onto the Engine API's create
// payload. It is pure: every hardening default lives here and nowhere else.
// Unlike containerConfig, the container never runs the workload directly;
// it just idles under tail -f /dev/null so ExecStreaming and ExecTTY can run
// commands inside it on demand.
func envContainerConfig(spec EnvSpec) (*container.Config, *container.HostConfig) {
	pids := spec.PidsLimit
	if pids == 0 {
		pids = DefaultPidsLimit
	}
	init := true
	cfg := &container.Config{
		Image:      spec.Image,
		User:       DefaultUser,
		Entrypoint: strslice.StrSlice{"tail", "-f", "/dev/null"},
		Cmd:        strslice.StrSlice{},
		WorkingDir: workspaceDir,
		Labels:     copyLabels(spec.Labels),
		Env:        envSlice(spec.Env),
	}
	host := &container.HostConfig{
		Init: &init,
		Mounts: []mount.Mount{{
			Type:   mount.TypeVolume,
			Source: spec.Volume,
			Target: workspaceDir,
		}},
		CapDrop:       strslice.StrSlice{"ALL"},
		SecurityOpt:   []string{"no-new-privileges:true"},
		Runtime:       spec.Runtime,
		NetworkMode:   container.NetworkMode(spec.Network),
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
		AutoRemove:    false,
		Resources: container.Resources{
			Memory:    spec.MemoryMb * bytesPerMiB,
			NanoCPUs:  int64(spec.Cpus * nanoCPUsPerCPU),
			PidsLimit: &pids,
		},
	}
	return cfg, host
}

// envSlice renders env as Docker's "KEY=value" list, sorted by key so that a
// given spec always produces the same configuration.
func envSlice(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// copyLabels returns a defensive copy so a caller's map cannot be mutated by,
// or observed through, the created container's configuration.
func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}
