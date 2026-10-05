package config

import (
	"os"
	"path/filepath"
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
	for _, want := range []string{`"caFile": null`, `"exec": true`, `"pty": true`, `"maxConcurrentExec": 8`} {
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
