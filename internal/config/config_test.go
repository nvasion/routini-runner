package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSaveLoadPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "routini-runner")
	path := filepath.Join(dir, "config.json")
	c := New()
	c.URL = "https://routini.example.com"
	c.RunnerID = "r1"
	c.Credential = "rrc_secret"
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 700", dst.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{
		`"caFile": null`,
		`"exec": true`,
		`"pty": true`,
		`"agents": false`,
		`"maxConcurrentExec": 8`,
		`"agentImagePrefixes": [`,
		`"ghcr.io/nvasion/"`,
		`"maxConcurrentAgents": 2`,
		`"dockerHost": ""`,
		`"containerRuntime": ""`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config missing %s:\n%s", want, raw)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Credential != "rrc_secret" || got.URL != c.URL || got.RunnerID != "r1" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestNewAgentDefaults(t *testing.T) {
	c := New()
	if c.Capabilities.Agents {
		t.Error("New(): capabilities.agents must stay false")
	}
	if c.MaxConcurrentAgents != DefaultMaxConcurrentAgents {
		t.Errorf("New(): maxConcurrentAgents = %d, want %d", c.MaxConcurrentAgents, DefaultMaxConcurrentAgents)
	}
	if !reflect.DeepEqual(c.AgentImagePrefixes, []string{"ghcr.io/nvasion/"}) {
		t.Errorf("New(): agentImagePrefixes = %#v", c.AgentImagePrefixes)
	}
	if c.DockerHost != "" || c.ContainerRuntime != "" {
		t.Errorf("New(): dockerHost/containerRuntime must default to empty: %q/%q", c.DockerHost, c.ContainerRuntime)
	}
	// The returned slice must not alias shared state between configs.
	c.AgentImagePrefixes[0] = "example.invalid/"
	if got := New().AgentImagePrefixes[0]; got != "ghcr.io/nvasion/" {
		t.Errorf("New(): agentImagePrefixes aliased: %q", got)
	}
}

func TestAgentConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := New()
	c.URL = "https://routini.example.com"
	c.RunnerID = "r1"
	c.Credential = "rrc_secret"
	c.Capabilities.Agents = true
	c.AgentImagePrefixes = []string{"ghcr.io/nvasion/", "registry.example.com/agents/"}
	c.MaxConcurrentAgents = 5
	c.DockerHost = "tcp://127.0.0.1:2375"
	c.ContainerRuntime = RuntimeGvisor
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
}

func TestLoadDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, err := Load(write(`{"url":"https://x.example","runnerId":"r","credential":"rrc_x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Capabilities.Exec || !c.Capabilities.Pty || c.MaxConcurrentExec != 8 {
		t.Errorf("defaults not applied: %+v", c)
	}
	c, err = Load(write(`{"url":"https://x.example","credential":"rrc_x","capabilities":{"exec":true,"pty":false},"maxConcurrentExec":2,"caFile":"/tmp/ca.pem"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Capabilities.Pty || c.MaxConcurrentExec != 2 || c.CAFilePath() != "/tmp/ca.pem" {
		t.Errorf("explicit values not kept: %+v", c)
	}
	for _, bad := range []string{
		`{`,
		`{"url":"","credential":"rrc_x"}`,
		`{"url":"https://x.example","credential":""}`,
		`{"url":"ftp://x.example","credential":"rrc_x"}`,
	} {
		if _, err := Load(write(bad)); err == nil {
			t.Errorf("Load(%s): expected an error", bad)
		}
	}
}

func TestLoadAgentDefaults(t *testing.T) {
	const base = `"url":"https://x.example","credential":"rrc_x"`
	tests := []struct {
		name           string
		json           string
		wantAgents     bool
		wantPrefixes   []string
		wantMaxAgents  int
		wantDockerHost string
		wantRuntime    string
	}{
		{
			name:          "all agent fields missing",
			json:          `{` + base + `}`,
			wantPrefixes:  []string{"ghcr.io/nvasion/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
		{
			name:          "explicit empty prefix list falls back to the default",
			json:          `{` + base + `,"agentImagePrefixes":[]}`,
			wantPrefixes:  []string{"ghcr.io/nvasion/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
		{
			name:          "null prefix list falls back to the default",
			json:          `{` + base + `,"agentImagePrefixes":null}`,
			wantPrefixes:  []string{"ghcr.io/nvasion/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
		{
			name:          "blank prefixes are dropped",
			json:          `{` + base + `,"agentImagePrefixes":["","  ","ghcr.io/other/"]}`,
			wantPrefixes:  []string{"ghcr.io/other/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
		{
			name:           "explicit values are kept",
			json:           `{` + base + `,"capabilities":{"exec":true,"pty":true,"agents":true},"agentImagePrefixes":["registry.example.com/a/"],"maxConcurrentAgents":4,"dockerHost":"tcp://127.0.0.1:2375","containerRuntime":"runsc"}`,
			wantAgents:     true,
			wantPrefixes:   []string{"registry.example.com/a/"},
			wantMaxAgents:  4,
			wantDockerHost: "tcp://127.0.0.1:2375",
			wantRuntime:    RuntimeGvisor,
		},
		{
			name:          "zero maxConcurrentAgents means 2",
			json:          `{` + base + `,"maxConcurrentAgents":0}`,
			wantPrefixes:  []string{"ghcr.io/nvasion/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
		{
			name:          "negative maxConcurrentAgents means 2",
			json:          `{` + base + `,"maxConcurrentAgents":-7}`,
			wantPrefixes:  []string{"ghcr.io/nvasion/"},
			wantMaxAgents: DefaultMaxConcurrentAgents,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.Capabilities.Agents != tt.wantAgents {
				t.Errorf("capabilities.agents = %v, want %v", c.Capabilities.Agents, tt.wantAgents)
			}
			if !reflect.DeepEqual(c.AgentImagePrefixes, tt.wantPrefixes) {
				t.Errorf("agentImagePrefixes = %#v, want %#v", c.AgentImagePrefixes, tt.wantPrefixes)
			}
			if c.MaxConcurrentAgents != tt.wantMaxAgents {
				t.Errorf("maxConcurrentAgents = %d, want %d", c.MaxConcurrentAgents, tt.wantMaxAgents)
			}
			if c.DockerHost != tt.wantDockerHost {
				t.Errorf("dockerHost = %q, want %q", c.DockerHost, tt.wantDockerHost)
			}
			if c.ContainerRuntime != tt.wantRuntime {
				t.Errorf("containerRuntime = %q, want %q", c.ContainerRuntime, tt.wantRuntime)
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv(EnvPath, "")
	if p := ResolvePath(""); p != DefaultPath {
		t.Errorf("got %q", p)
	}
	t.Setenv(EnvPath, "/x/config.json")
	if p := ResolvePath(""); p != "/x/config.json" {
		t.Errorf("got %q", p)
	}
	if p := ResolvePath("/flag.json"); p != "/flag.json" {
		t.Errorf("got %q", p)
	}
}

func TestTLSConfigCAFile(t *testing.T) {
	if _, err := TLSConfig(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected an error for a missing CA file")
	}
	p := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(p, []byte("not a cert"), 0o600)
	if _, err := TLSConfig(p); err == nil {
		t.Error("expected an error for a CA file without certificates")
	}
	cfg, err := TLSConfig("")
	if err != nil || cfg.RootCAs != nil {
		t.Errorf("no CA file should use system roots: %v", err)
	}
}
