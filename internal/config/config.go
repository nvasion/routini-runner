// Package config loads, validates and saves the runner's config.json.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nvasion/routini-runner/internal/urlcheck"
)

// DefaultPath is used when neither --config nor ROUTINI_RUNNER_CONFIG is set.
const DefaultPath = "/etc/routini-runner/config.json"

// EnvPath names the environment variable that overrides DefaultPath.
const EnvPath = "ROUTINI_RUNNER_CONFIG"

// DefaultMaxConcurrentExec is used when maxConcurrentExec is missing or not positive.
const DefaultMaxConcurrentExec = 8

// Capabilities switches runner features on or off.
type Capabilities struct {
	Exec bool `json:"exec"`
	Pty  bool `json:"pty"`
}

// Config is the on-disk runner configuration (PROTOCOL.md section 1).
type Config struct {
	URL               string       `json:"url"`
	RunnerID          string       `json:"runnerId"`
	Credential        string       `json:"credential"`
	CAFile            *string      `json:"caFile"`
	Capabilities      Capabilities `json:"capabilities"`
	MaxConcurrentExec int          `json:"maxConcurrentExec"`
}

// New returns a config with the protocol defaults filled in.
func New() *Config {
	return &Config{
		Capabilities:      Capabilities{Exec: true, Pty: true},
		MaxConcurrentExec: DefaultMaxConcurrentExec,
	}
}

// ResolvePath returns flagPath if set, else $ROUTINI_RUNNER_CONFIG, else DefaultPath.
func ResolvePath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	return DefaultPath
}

// CAFilePath returns the CA file path, or "" when none is configured.
func (c *Config) CAFilePath() string {
	if c.CAFile == nil {
		return ""
	}
	return *c.CAFile
}

// Validate checks the fields the runner needs to connect.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("config: url is missing")
	}
	if _, err := urlcheck.Parse(c.URL); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if strings.TrimSpace(c.Credential) == "" {
		return errors.New("config: credential is missing (enroll the runner first)")
	}
	if c.MaxConcurrentExec < 0 {
		return errors.New("config: maxConcurrentExec must not be negative")
	}
	return nil
}

// Load reads and validates the config at path. Missing fields take the
// protocol defaults (both capabilities on, maxConcurrentExec 8).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := New()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config %s: invalid JSON: %w", path, err)
	}
	if c.MaxConcurrentExec <= 0 {
		c.MaxConcurrentExec = DefaultMaxConcurrentExec
	}
	if c.CAFile != nil && *c.CAFile == "" {
		c.CAFile = nil
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically at mode 0600, creating the parent
// directory at mode 0700 if it does not exist.
func Save(path string, c *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// TLSConfig returns a TLS client config that trusts the system roots plus,
// when caFile is non-empty, the PEM certificates in caFile.
func TLSConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return cfg, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no PEM certificates", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}
