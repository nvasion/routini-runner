// Package updatex lets Routini move this runner to another release
// (PROTOCOL.md section 2.7). The runner runs as an unprivileged user and its
// binary is owned by root, so it cannot replace itself: install.sh installs a
// root-owned helper, scripts/routini-runner-update, plus a sudoers rule that
// lets the runner's user run exactly `routini-runner-update --check` and
// `routini-runner-update vX.Y.Z`. The helper downloads that release, checks
// its sha256 and queues a restart of the service.
package updatex

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HelperPath is where install.sh puts the helper.
const HelperPath = "/usr/local/sbin/routini-runner-update"

// Timeouts for the helper. An update downloads a release, so it gets minutes.
const (
	CheckTimeout = 10 * time.Second
	RunTimeout   = 5 * time.Minute
)

// maxOutput caps the helper output sent back to the server.
const maxOutput = 4096

// Refusals, sent as the result's error.
const (
	ErrDisabled = "updates are not enabled on this runner; reinstall it with install.sh to allow them"
	ErrVersion  = "invalid version (want vX.Y.Z)"
	ErrBusy     = "an update is already running"
)

var tagRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// ValidTag reports whether v is a release tag the helper accepts.
func ValidTag(v string) bool { return tagRe.MatchString(v) }

// Exec runs a command and returns its combined output.
type Exec func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options configures an Updater.
type Options struct {
	Helper  string // "": HelperPath
	Current string // this runner's version, without the leading "v"
	Exec    Exec   // nil: os/exec with stdin from /dev/null
	Logger  *log.Logger
}

// Msg is the runner.update frame.
type Msg struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ResultMsg is the runner.update.result frame: exactly one per runner.update.
type ResultMsg struct {
	Type    string  `json:"type"`
	ID      string  `json:"id"`
	Version string  `json:"version"`
	OK      bool    `json:"ok"`
	Error   *string `json:"error"`
	Output  string  `json:"output"`
}

// Updater runs the helper, one update at a time.
type Updater struct {
	opts Options

	mu      sync.Mutex
	running bool
}

// New returns an Updater.
func New(opts Options) *Updater {
	if opts.Helper == "" {
		opts.Helper = HelperPath
	}
	if opts.Exec == nil {
		opts.Exec = run
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	return &Updater{opts: opts}
}

// Available reports whether this runner can update itself: the helper is
// installed and sudo lets this user run it without a password.
func (u *Updater) Available(ctx context.Context) bool {
	if _, err := os.Stat(u.opts.Helper); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	out, err := u.opts.Exec(ctx, "sudo", "-n", u.opts.Helper, "--check")
	return err == nil && strings.TrimSpace(string(out)) == "ok"
}

// Start handles a runner.update frame. Refusals are answered at once; an
// accepted update runs in the background. Either way send is called exactly
// once. After a successful update the helper restarts the service, so the
// runner reconnects with the new version shortly afterwards.
func (u *Updater) Start(enabled bool, m Msg, send func(any)) {
	refuse := func(msg string) { send(result(m, false, msg, "")) }
	switch {
	case !enabled:
		refuse(ErrDisabled)
		return
	case !ValidTag(m.Version):
		refuse(ErrVersion)
		return
	case m.Version == "v"+u.opts.Current:
		refuse("already running " + m.Version)
		return
	}
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		refuse(ErrBusy)
		return
	}
	u.running = true
	u.mu.Unlock()

	go func() {
		defer func() {
			u.mu.Lock()
			u.running = false
			u.mu.Unlock()
		}()
		u.opts.Logger.Printf("update %s: updating to %s", m.ID, m.Version)
		ctx, cancel := context.WithTimeout(context.Background(), RunTimeout)
		defer cancel()
		out, err := u.opts.Exec(ctx, "sudo", "-n", u.opts.Helper, m.Version)
		tail := lastBytes(out, maxOutput)
		if err != nil {
			u.opts.Logger.Printf("update %s: failed: %v", m.ID, err)
			send(result(m, false, "update to "+m.Version+" failed: "+err.Error(), tail))
			return
		}
		u.opts.Logger.Printf("update %s: installed %s; the service restarts next", m.ID, m.Version)
		send(result(m, true, "", tail))
	}()
}

func result(m Msg, ok bool, errMsg, output string) ResultMsg {
	r := ResultMsg{Type: "runner.update.result", ID: m.ID, Version: m.Version, OK: ok, Output: output}
	if errMsg != "" {
		r.Error = &errMsg
	}
	return r
}

// lastBytes keeps the end of b, which holds the helper's final verdict, as
// valid UTF-8.
func lastBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.ToValidUTF8(string(bytes.TrimSpace(b)), "�")
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil // /dev/null: sudo -n must never prompt
	return cmd.CombinedOutput()
}
