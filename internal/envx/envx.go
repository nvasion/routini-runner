// Package envx runs env.op, env.cancel and env.tty.* (PROTOCOL.md section
// 2.8): long-lived environment containers a user works in interactively,
// sharing the egress design agents use (internal/agentx) but living across
// reconnects instead of being torn down with the task that started them.
//
// It talks to Docker only through the dockerx.Docker interface and to the
// shared routini-egress container only through internal/egressctl.
package envx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/egressctl"
)

// Frame types this package sends.
const (
	TypeOutput    = "env.output"
	TypeDone      = "env.done"
	TypeTTYOpened = "env.tty.opened"
	TypeTTYError  = "env.tty.error"
	TypeTTYData   = "env.tty.data"
	TypeTTYExit   = "env.tty.exit"
)

// Error messages sent in env.done or env.tty.error. None of them ever
// carries an env value or the session (PROTOCOL.md 2.8).
const (
	ErrDisabled = "environments are disabled on this runner"
	// ErrTooMany is sent by OpenTTY once MaxTTYs terminals are already open.
	ErrTooMany = "too many terminals"
	// ErrAlreadyOpen guards against a duplicate terminal id.
	ErrAlreadyOpen = "terminal id is already open"
	// ErrContainerMissing covers both a container that does not exist and
	// one that is not a managed environment container: the two look the
	// same to a caller that must not be able to touch an unrelated
	// container just by guessing its id.
	ErrContainerMissing = "environment container is missing"
	// ErrEgressNotReady is sent by session.open and session.close when no
	// network.ensure has established routini-egress's control URL yet.
	ErrEgressNotReady = "egress network is not ready"
)

// ImageNotAllowedError returns the refusal for an image reference outside
// the configured allow-list. ref is a public image reference, never a secret.
func ImageNotAllowedError(ref string) string {
	return "image not allowed by agentImagePrefixes: " + ref
}

// BusyError returns the refusal sent once MaxEnvironments is reached.
func BusyError(running int) string {
	return fmt.Sprintf("runner busy (%d environments running)", running)
}

// Defaults and limits.
const (
	// DefaultMaxEnvironments mirrors config.DefaultMaxEnvironments; kept
	// local so this package has no import cycle on internal/config and
	// stays testable on its own.
	DefaultMaxEnvironments = 4
	// DefaultTimeoutSec applies when an exec op omits timeoutSec.
	DefaultTimeoutSec = 600
	// MaxTTYs is the maximum number of open environment terminals,
	// independent of ptyx's own 4-terminal PTY limit.
	MaxTTYs = 4
	// ttyChunkSize is the largest env.tty.data payload, before base64.
	ttyChunkSize = 32 * 1024
	// inputQueue bounds how much unwritten env.tty.input is buffered.
	inputQueue = 256
	// drainTimeout bounds how long output is drained after a terminal's
	// shell exits while another process still holds it open.
	drainTimeout = 500 * time.Millisecond
	// quickOpTimeout bounds a Docker or egress control call that is not
	// expected to pull an image. It is a defensive bound, not part of the
	// protocol: no op but exec carries its own timeoutSec.
	quickOpTimeout = 30 * time.Second
	// pullOpTimeout bounds an op that may pull an image.
	pullOpTimeout = 10 * time.Minute
)

// tokenRe bounds an egress session token, which is interpolated into the
// control API's request path, so only characters safe unescaped there are
// accepted (mirrors agentx's own tokenRe).
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)

// OpMsg is the env.op message.
type OpMsg struct {
	Type string          `json:"type"`
	ID   string          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

// CancelMsg is the env.cancel message.
type CancelMsg struct {
	ID string `json:"id"`
}

// OutputMsg is the env.output message. Its framing is exec.output's
// (PROTOCOL.md 2.3).
type OutputMsg struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Stream string `json:"stream"`
	Data   string `json:"data"`
}

// DoneMsg is the env.done message. Exactly one is sent per env.op.
type DoneMsg struct {
	Type     string  `json:"type"`
	ID       string  `json:"id"`
	OK       bool    `json:"ok"`
	Error    *string `json:"error"`
	ExitCode *int    `json:"exitCode"`
	TimedOut bool    `json:"timedOut"`
	Canceled bool    `json:"canceled"`
	Result   any     `json:"result"`
}

// doneOK returns the env.done sent for an op that ran, with result as its
// result payload (nil for an op that has none).
func doneOK(id string, result any) DoneMsg {
	return DoneMsg{Type: TypeDone, ID: id, OK: true, Result: result}
}

// doneErr returns the env.done sent for an op that was refused or failed.
func doneErr(id, msg string) DoneMsg {
	return DoneMsg{Type: TypeDone, ID: id, Error: &msg}
}

// SendFunc delivers one message to the server. It must be safe for
// concurrent use and must not block forever when the connection is gone.
type SendFunc func(v any)

// Options configures a Manager.
type Options struct {
	// Docker is the daemon this Manager runs containers on. Environments
	// are refused when it is nil.
	Docker dockerx.Docker
	// Enabled mirrors the environments capability: it is true only when
	// config asks for agents and the daemon answered a ping (PROTOCOL.md
	// 2.1); environments come bundled with the agents opt-in.
	Enabled bool
	// ImagePrefixes is the image reference allow-list. An empty list allows
	// nothing.
	ImagePrefixes []string
	// MaxEnvironments caps parallel environment containers; default
	// DefaultMaxEnvironments.
	MaxEnvironments int
	// Runtime is the OCI runtime for environment containers; "" means
	// Docker's default.
	Runtime string
	// EgressSecret is shared with the egress container and authenticates
	// every control API call. internal/conn generates one secret per runner
	// process and passes the same value to agentx and envx, so EnsureEgress
	// never sees the two packages disagree about it and recreate
	// routini-egress out from under one another.
	EgressSecret string
	// HTTPClient talks to the egress control API; nil means a loopback
	// client with a timeout and no redirects.
	HTTPClient *http.Client
	Logger     *log.Logger
}

// Manager tracks running environment exec ops, open terminals and the egress
// sessions this runner has opened.
type Manager struct {
	opts    Options
	enabled bool
	// secret is the egress secret shared with agentx and the routini-egress
	// container; see Options.EgressSecret. It is never logged.
	secret string

	mu sync.Mutex
	// controlURL is routini-egress's control URL, learned the last time
	// network.ensure ran. session.open and session.close need it but are
	// not given it directly by the protocol.
	controlURL string
	execs      map[string]*execJob
	ttys       map[string]*ttySession
	// tokens is the set of egress session tokens opened through
	// session.open and not yet closed, so Disconnect can close them all.
	tokens map[string]struct{}

	wg sync.WaitGroup
}

// New returns a Manager.
func New(opts Options) *Manager {
	if opts.MaxEnvironments <= 0 {
		opts.MaxEnvironments = DefaultMaxEnvironments
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = egressctl.DefaultHTTPClient()
	}
	return &Manager{
		opts: opts,
		// A Manager without a daemon refuses every op rather than panicking
		// on the first call.
		enabled: opts.Enabled && opts.Docker != nil,
		secret:  opts.EgressSecret,
		execs:   make(map[string]*execJob),
		ttys:    make(map[string]*ttySession),
		tokens:  make(map[string]struct{}),
	}
}

// Op handles env.op. It runs in its own goroutine and always reports exactly
// one env.done through send, including for a refusal.
func (m *Manager) Op(msg OpMsg, send SendFunc) {
	if send == nil {
		m.logf("env.op without a send function ignored")
		return
	}
	if msg.ID == "" {
		m.logf("env.op without id ignored")
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.runOp(msg, send)
	}()
}

// Op names this package understands.
const (
	opVolumeEnsure    = "volume.ensure"
	opVolumeRemove    = "volume.remove"
	opNetworkEnsure   = "network.ensure"
	opSessionOpen     = "session.open"
	opSessionClose    = "session.close"
	opContainerStart  = "container.start"
	opContainerRemove = "container.remove"
	opContainerState  = "container.state"
	opExec            = "exec"
	opPull            = "pull"
)

func (m *Manager) runOp(msg OpMsg, send SendFunc) {
	if !m.enabled {
		send(doneErr(msg.ID, ErrDisabled))
		return
	}
	switch msg.Op {
	case opVolumeEnsure:
		m.volumeEnsure(msg, send)
	case opVolumeRemove:
		m.volumeRemove(msg, send)
	case opNetworkEnsure:
		m.networkEnsure(msg, send)
	case opSessionOpen:
		m.sessionOpen(msg, send)
	case opSessionClose:
		m.sessionClose(msg, send)
	case opContainerStart:
		m.containerStart(msg, send)
	case opContainerRemove:
		m.containerRemove(msg, send)
	case opContainerState:
		m.containerState(msg, send)
	case opExec:
		m.runExec(msg, send)
	case opPull:
		m.pull(msg, send)
	default:
		send(doneErr(msg.ID, "unknown op"))
	}
}

// decodeArgs decodes an op's args into v. The error never echoes raw (which
// may carry env values or a session), only the op's name.
func decodeArgs(raw json.RawMessage, v any, op string) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid %s args", op)
	}
	return nil
}

// allowedImage reports whether ref starts with one of prefixes. An empty
// allow-list allows nothing, and a blank prefix is ignored because it would
// match every reference.
func allowedImage(ref string, prefixes []string) bool {
	if ref == "" {
		return false
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

// envLabels returns labels with the managed label the runner matches on
// forced on, the same defensive rule agentx applies to agent containers: a
// container this package could not find again by label would leak it.
func envLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[dockerx.LabelManaged] = "true"
	return out
}

// sessionToken parses the token out of an opaque session body, the same way
// agentx.EgressSpec does. The error never echoes the body.
func sessionToken(session json.RawMessage) (string, error) {
	var s struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(session, &s); err != nil {
		return "", errors.New("session is not an object")
	}
	return s.Token, nil
}

func (m *Manager) setControlURL(url string) {
	m.mu.Lock()
	m.controlURL = url
	m.mu.Unlock()
}

func (m *Manager) getControlURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.controlURL
}

func (m *Manager) rememberToken(token string) {
	m.mu.Lock()
	m.tokens[token] = struct{}{}
	m.mu.Unlock()
}

func (m *Manager) forgetToken(token string) {
	m.mu.Lock()
	delete(m.tokens, token)
	m.mu.Unlock()
}

func (m *Manager) tokenSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.tokens))
	for t := range m.tokens {
		out = append(out, t)
	}
	return out
}

// newControlClient builds an egressctl.Client from the control URL learned
// through the last network.ensure. It fails with ErrEgressNotReady when none
// has run yet.
func (m *Manager) newControlClient() (*egressctl.Client, error) {
	url := m.getControlURL()
	if url == "" {
		return nil, errors.New(ErrEgressNotReady)
	}
	return egressctl.New(url, m.secret, m.opts.HTTPClient)
}

// Running returns the number of environment containers running now. A
// Docker error counts as 0, the same way a disabled Manager does: this
// number only ever feeds host facts, which must never block or fail the
// connection over a transient daemon hiccup.
func (m *Manager) Running() int {
	if !m.enabled {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	n, err := m.opts.Docker.CountEnvContainers(ctx)
	if err != nil {
		m.logf("environments: count running containers: %v", err)
		return 0
	}
	return n
}

// Disconnect cancels every running exec op, closes every open terminal and
// closes every egress session this Manager opened, without reporting
// anything more for them (their results can no longer be delivered). It is
// used when the control connection drops. Environment containers and
// volumes are left running: they are long-lived state, and the server
// reopens their egress session on the next connection.
func (m *Manager) Disconnect() {
	execs := m.execSnapshot()
	if len(execs) > 0 {
		m.logf("environments: canceling %d running exec op(s)", len(execs))
	}
	for _, j := range execs {
		j.silent.Store(true)
		j.stop(stopCanceled)
	}

	ttys := m.ttySnapshot()
	for _, s := range ttys {
		s.silent.Store(true)
		_ = s.tty.Close()
	}

	tokens := m.tokenSnapshot()
	if len(tokens) > 0 {
		m.logf("environments: closing %d egress session(s)", len(tokens))
	}
	for _, token := range tokens {
		m.closeTokenBestEffort(token)
	}
}

// closeTokenBestEffort closes one egress session on a fresh context. Its
// outcome is only logged: Disconnect's job is to drop the real credentials
// from the proxy's memory, not to report anything to a connection that is
// already gone.
func (m *Manager) closeTokenBestEffort(token string) {
	defer m.forgetToken(token)
	ctrl, err := m.newControlClient()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	if _, err := ctrl.CloseSession(ctx, token); err != nil {
		m.logf("environments: close egress session: %v", err)
	}
}

// Wait waits up to d for every running op and terminal to finish and reports
// whether they did.
func (m *Manager) Wait(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// logf writes one line to the Manager's logger. Nothing passed to it may be
// a session, a token or an environment value.
func (m *Manager) logf(format string, args ...any) {
	m.opts.Logger.Printf(format, args...)
}
