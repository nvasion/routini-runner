package main

import (
	"os"
	"strings"
	"testing"

	"github.com/nvasion/routini-runner/internal/config"
)

func TestAgentsSubcommand(t *testing.T) {
	path := writeConfig(t, "https://routini.example.com")

	code, out, _ := runCLI(t, nil, "agents", "status", "--config", path)
	if code != exitOK || !strings.Contains(out, "agents are disabled") {
		t.Fatalf("status: code %d, out %q", code, out)
	}

	code, out, _ = runCLI(t, nil, "agents", "enable", "--config", path)
	if code != exitOK || !strings.Contains(out, "agents enabled") || !strings.Contains(out, "restart") {
		t.Fatalf("enable: code %d, out %q", code, out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Capabilities.Agents || cfg.Credential == "" || !cfg.Capabilities.Exec {
		t.Errorf("after enable: %+v", cfg.Capabilities)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	assertNoSecrets(t, out)

	code, out, _ = runCLI(t, nil, "agents", "enable", "--config", path)
	if code != exitOK || !strings.Contains(out, "already enabled") {
		t.Errorf("enable again: code %d, out %q", code, out)
	}

	code, _, _ = runCLI(t, nil, "agents", "disable", "--config", path)
	if cfg, _ := config.Load(path); code != exitOK || cfg.Capabilities.Agents {
		t.Errorf("disable: code %d, agents %v", code, cfg.Capabilities.Agents)
	}
}

func TestAgentsSubcommandUsage(t *testing.T) {
	path := writeConfig(t, "https://routini.example.com")
	for _, args := range [][]string{
		{"agents"},
		{"agents", "toggle", "--config", path},
		{"agents", "enable", "--config", path, "extra"},
	} {
		if code, _, _ := runCLI(t, nil, args...); code != exitUsage {
			t.Errorf("%v: code %d, want %d", args, code, exitUsage)
		}
	}
	if code, _, _ := runCLI(t, nil, "agents", "status", "--config", path+".missing"); code != exitError {
		t.Errorf("missing config: code %d, want %d", code, exitError)
	}
}
