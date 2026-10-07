// Package agentx runs agent.start tasks (PROTOCOL.md section 2.6): one
// container per task, on an internal Docker network whose only way out is the
// shared routini-egress proxy, with line-by-line output streaming, timeouts,
// cancellation and a concurrency cap.
//
// It mirrors internal/execx, which does the same job for shell commands, and
// talks to Docker only through the dockerx.Docker interface.
package agentx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/nvasion/routini-runner/internal/enroll"
)

// Frame types this package sends.
const (
	TypeOutput = "agent.output"
	TypeExit   = "agent.exit"
)

// Error messages sent in agent.exit when a task never ran (PROTOCOL.md 2.6
// step 1). None of them ever carries a secret value.
const (
	ErrDisabled      = "agents are disabled on this runner"
	ErrInvalidEnvKey = "invalid env key"
	ErrShuttingDown  = "runner is shutting down"
	// ErrInvalidID is not a protocol refusal but a plain failure: the task id
	// is part of the container name the Engine API is asked to create.
	ErrInvalidID = "invalid agent id"
	// ErrInvalidToken is reported when the egress session has no usable
	// token. The token itself is never echoed: it is the agent's proxy
	// password.
	ErrInvalidToken = "invalid egress session token"
)

// ImageNotAllowedError returns the refusal for an image reference outside
// the configured allow-list. ref is a public image reference, never a secret.
func ImageNotAllowedError(ref string) string {
	return "image not allowed by agentImagePrefixes: " + ref
}

// BusyError returns the refusal sent once maxConcurrentAgents is reached.
func BusyError(running int) string {
	return fmt.Sprintf("runner busy (%d agents running)", running)
}

// Container naming and lifecycle constants.
const (
	// ContainerPrefix is prepended to the task id to name the container.
	ContainerPrefix = "routini-agent-"
	// StopGrace is how long a stopped container gets to exit before it is
	// killed (PROTOCOL.md 2.6 step 6).
	StopGrace = 10 * time.Second
	// DefaultMaxConcurrent caps parallel agent containers when Options
	// leaves MaxConcurrent at zero.
	DefaultMaxConcurrent = 2
	// DefaultTimeoutSec applies when agent.start omits timeoutSec. There is
	// no maximum: PROTOCOL.md 2.6 leaves agent time to the customer.
	DefaultTimeoutSec = 3600
	// egressSecretBytes is the length of the secret the runner shares with
	// the egress container, before hex encoding.
	egressSecretBytes = 32
	// maxErrorLen bounds an error message put in agent.exit.
	maxErrorLen = 200
	// cleanupTimeout bounds step 7, which runs on a fresh context.
	cleanupTimeout = 30 * time.Second
	// stopSlack is added to StopGrace to bound the Docker stop call itself.
	stopSlack = 20 * time.Second
)

// Environment the runner injects into every agent container (PROTOCOL.md 2.6
// step 4). The proxy user is a fixed name; the password is the session token.
const (
	envCAPEM           = "ROUTINI_CA_PEM"
	envGitProxyAuth    = "GIT_HTTP_PROXY_AUTHMETHOD"
	gitProxyAuthMethod = "basic"
	proxyUser          = "routini"
)

var (
	// proxyEnvKeys all carry the egress proxy URL, and noProxyEnvKeys are
	// emptied so that nothing can bypass the proxy.
	proxyEnvKeys   = []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"}
	noProxyEnvKeys = []string{"NO_PROXY", "no_proxy"}
	// injectedEnvCount is what agentEnv adds on top of the task's own
	// environment: the proxy URLs, the emptied no-proxy keys, the git proxy
	// auth method and the CA.
	injectedEnvCount = len(proxyEnvKeys) + len(noProxyEnvKeys) + 2
)

// Field syntax accepted by this package.
var (
	// envKeyRe is the POSIX environment variable name rule exec also uses
	// (PROTOCOL.md 2.3 and 2.6).
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// idRe keeps the task id safe inside a Docker container name, which
	// Docker itself limits to [a-zA-Z0-9][a-zA-Z0-9_.-]*.
	idRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	// tokenRe bounds the egress session token, which is interpolated into
	// the control API's request path and into the agent's proxy URL, so only
	// characters safe unescaped in both are accepted.
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)
)

// EgressSpec is the egress object of an agent.start frame.
type EgressSpec struct {
	Image   string `json:"image"`
	Network string `json:"network"`
	// Session is passed to the egress proxy untouched. It holds the real
	// credentials, so it is never logged and never reaches the agent
	// container.
	Session json.RawMessage `json:"session"`
	// Token is the session token parsed out of Session. It is not read from
	// the frame directly.
	Token string `json:"-"`
}

// UnmarshalJSON decodes the egress object and parses the session token out of
// the opaque session body. The error never echoes the body.
func (e *EgressSpec) UnmarshalJSON(data []byte) error {
	// A distinct type avoids recursing into this method.
	type plain EgressSpec
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return errors.New("agentx: egress is not an object")
	}
	*e = EgressSpec(p)
	if len(e.Session) == 0 {
		return nil
	}
	var s struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(e.Session, &s); err != nil {
		return errors.New("agentx: egress session is not an object")
	}
	e.Token = s.Token
	return nil
}

// StartMsg is the agent.start message.
type StartMsg struct {
	ID         string            `json:"id"`
	Image      string            `json:"image"`
	Pull       string            `json:"pull"`
	User       string            `json:"user"`
	Cpus       float64           `json:"cpus"`
	MemoryMb   int64             `json:"memoryMb"`
	PidsLimit  int64             `json:"pidsLimit"`
	TimeoutSec *int              `json:"timeoutSec"`
	Env        map[string]string `json:"env"`
	Labels     map[string]string `json:"labels"`
	Egress     EgressSpec        `json:"egress"`
}

// CancelMsg is the agent.cancel message.
type CancelMsg struct {
	ID string `json:"id"`
}

// OutputMsg is the agent.output message. Its framing is exec.output's
// (PROTOCOL.md 2.3).
type OutputMsg struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Stream string `json:"stream"`
	Data   string `json:"data"`
}

// EgressStats are the session counters the egress proxy reports when the
// session is closed.
type EgressStats = egressctl.Stats

// ExitMsg is the agent.exit message. Exactly one is sent per agent.start.
type ExitMsg struct {
	Type     string       `json:"type"`
	ID       string       `json:"id"`
	ExitCode *int         `json:"exitCode"`
	TimedOut bool         `json:"timedOut"`
	Canceled bool         `json:"canceled"`
	Error    *string      `json:"error"`
	Egress   *EgressStats `json:"egress"`
}

// ErrorExit returns the agent.exit sent for a task that never ran.
func ErrorExit(id, msg string) ExitMsg {
	return ExitMsg{Type: TypeExit, ID: id, Error: &msg}
}

// SendFunc delivers one message to the server. It must be safe for concurrent
// use and must not block forever when the connection is gone.
type SendFunc func(v any)

// Options configures a Manager.
type Options struct {
	// Docker is the daemon this Manager runs containers on. Agents are
	// refused when it is nil.
	Docker dockerx.Docker
	// Enabled mirrors the agents capability: it is true only when config
	// asks for agents and the daemon answered a ping (PROTOCOL.md 2.1).
	Enabled bool
	// ImagePrefixes is the image reference allow-list. An empty list allows
	// nothing.
	ImagePrefixes []string
	// MaxConcurrent caps parallel agent containers; default
	// DefaultMaxConcurrent.
	MaxConcurrent int
	// Runtime is the OCI runtime for agent containers; "" means Docker's
	// default.
	Runtime string
	// EgressSecret is shared with the egress container and authenticates
	// every control API call. It is the same secret internal/conn passes to
	// envx, so EnsureEgress never sees the two packages disagree about it and
	// recreate routini-egress out from under one another. Empty means a
	// Manager generates its own, for callers (and tests) that do not share
	// one across packages.
	EgressSecret string
	// HTTPClient talks to the egress control API; nil means a loopback
	// client with a timeout and no redirects.
	HTTPClient *http.Client
	Logger     *log.Logger
}

// Manager tracks the running agent tasks.
type Manager struct {
	opts    Options
	enabled bool
	// secret is shared with the egress container and authenticates every
	// control API call. It is generated once per Manager and never logged.
	secret string

	mu     sync.Mutex
	jobs   map[string]*job
	closed bool
	wg     sync.WaitGroup
}

// New returns a Manager. It fails only when the host cannot provide the
// random bytes of the egress secret.
func New(opts Options) (*Manager, error) {
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultMaxConcurrent
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = egressctl.DefaultHTTPClient()
	}
	secret := opts.EgressSecret
	if secret == "" {
		s, err := newSecret()
		if err != nil {
			return nil, err
		}
		secret = s
	}
	return &Manager{
		opts: opts,
		// A Manager without a daemon refuses every task rather than
		// panicking on the first call.
		enabled: opts.Enabled && opts.Docker != nil,
		secret:  secret,
		jobs:    make(map[string]*job),
	}, nil
}

// newSecret returns the hex-encoded egress secret.
func newSecret() (string, error) {
	b := make([]byte, egressSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentx: generate egress secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

type stopReason int

const (
	notStopped stopReason = iota
	stopCanceled
	stopTimedOut
)

// job is one running agent task.
type job struct {
	id   string
	name string
	send SendFunc

	mu       sync.Mutex
	abort    context.CancelFunc
	reason   stopReason
	finished bool
}

// setAbort records the cancel function of the run context, applying a stop
// that was requested while the task was still starting.
func (j *job) setAbort(cancel context.CancelFunc) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.abort = cancel
	if j.reason != notStopped {
		j.abort()
	}
}

// cancelRun unblocks the run, which makes dockerx tear the container down.
func (j *job) cancelRun() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.abort != nil {
		j.abort()
	}
}

// setReason records why the task is being stopped. It reports whether this
// call is the one that has to do the stopping: the first reason wins, and a
// finished task is never stopped.
func (j *job) setReason(r stopReason) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.finished || j.reason != notStopped {
		return false
	}
	j.reason = r
	return true
}

// finish closes the task to further stops and returns why it ended.
func (j *job) finish() stopReason {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.finished = true
	return j.reason
}

// Running returns the number of agent tasks running now.
func (m *Manager) Running() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs)
}

// Start handles agent.start. Every outcome, including a refusal, is reported
// through send: zero or more agent.output messages and exactly one
// agent.exit.
func (m *Manager) Start(msg StartMsg, send SendFunc) {
	if send == nil {
		m.logf("agent.start without a send function ignored")
		return
	}
	if msg.ID == "" {
		m.logf("agent.start without id ignored")
		return
	}
	// Step 1, in the order of PROTOCOL.md 2.6. The image allow-list is
	// checked before anything is reserved or created.
	if !m.enabled {
		send(ErrorExit(msg.ID, ErrDisabled))
		return
	}
	for _, ref := range []string{msg.Image, msg.Egress.Image} {
		if !allowedImage(ref, m.opts.ImagePrefixes) {
			send(ErrorExit(msg.ID, ImageNotAllowedError(ref)))
			return
		}
	}
	j, refusal := m.reserve(msg, send)
	if j == nil {
		// An empty refusal means a duplicate id, which is ignored: the
		// running task will send the one agent.exit for it.
		if refusal != "" {
			send(ErrorExit(msg.ID, refusal))
		}
		return
	}
	m.logf("agent %s: starting image %s on network %s", j.id, msg.Image, msg.Egress.Network)
	go m.run(j, msg)
}

// reserve runs the remaining step-1 checks and, when they all pass, registers
// the task. It returns a nil job with the refusal message when one applies,
// and a nil job with an empty message for a duplicate id.
func (m *Manager) reserve(msg StartMsg, send SendFunc) (*job, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrShuttingDown
	}
	if _, dup := m.jobs[msg.ID]; dup {
		m.logf("agent %s: already running; duplicate agent.start ignored", msg.ID)
		return nil, ""
	}
	if n := len(m.jobs); n >= m.opts.MaxConcurrent {
		return nil, BusyError(n)
	}
	for k := range msg.Env {
		if !envKeyRe.MatchString(k) {
			return nil, ErrInvalidEnvKey
		}
	}
	// The id and the token are interpolated into a container name and into
	// the control API's request path, so they are checked before the task
	// creates anything.
	if !idRe.MatchString(msg.ID) {
		return nil, ErrInvalidID
	}
	if !tokenRe.MatchString(msg.Egress.Token) {
		return nil, ErrInvalidToken
	}
	j := &job{id: msg.ID, name: ContainerPrefix + msg.ID, send: send}
	m.jobs[msg.ID] = j
	m.wg.Add(1)
	return j, ""
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

// run drives steps 2 to 7 for one task and sends its single agent.exit.
func (m *Manager) run(j *job, msg StartMsg) {
	defer m.wg.Done()
	started := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j.setAbort(cancel)

	timer := time.AfterFunc(timeoutFor(msg.TimeoutSec), func() { m.stop(j, stopTimedOut) })
	defer timer.Stop()

	code, stats, err := m.lifecycle(ctx, j, msg)

	reason := j.finish()
	m.forget(j.id)

	exit := ExitMsg{Type: TypeExit, ID: j.id, Egress: stats}
	switch reason {
	case stopTimedOut:
		// A stopped container was killed, so it has no exit code to report
		// and the stop is not an error (PROTOCOL.md 2.6).
		exit.TimedOut = true
	case stopCanceled:
		exit.Canceled = true
	default:
		exit.ExitCode = code
		if err != nil {
			exit.ExitCode = nil
			exit.Error = ptr(enroll.OneLine(err.Error(), maxErrorLen))
		}
	}
	if err != nil {
		m.logf("agent %s: %v", j.id, err)
	}
	m.logf("agent %s: finished exit=%s timedOut=%v canceled=%v in %s",
		j.id, codeString(exit.ExitCode), exit.TimedOut, exit.Canceled,
		time.Since(started).Round(time.Millisecond))
	j.send(exit)
}

func codeString(code *int) string {
	if code == nil {
		return "none"
	}
	return fmt.Sprint(*code)
}

// timeoutFor returns the task's wall-clock limit.
func timeoutFor(sec *int) time.Duration {
	s := DefaultTimeoutSec
	if sec != nil && *sec > 0 {
		s = *sec
	}
	return time.Duration(s) * time.Second
}

// lifecycle runs steps 2 to 5 and, once a session has been opened, always
// closes it (step 7) on the way out.
func (m *Manager) lifecycle(ctx context.Context, j *job, msg StartMsg) (code *int, stats *EgressStats, err error) {
	d := m.opts.Docker
	eg := msg.Egress

	// Step 2: the shared egress proxy and this task's internal network.
	if err := d.EnsureImage(ctx, eg.Image, dockerx.PullMissing); err != nil {
		return nil, nil, fmt.Errorf("ensure egress image: %w", err)
	}
	controlURL, err := d.EnsureEgress(ctx, eg.Image, m.secret)
	if err != nil {
		return nil, nil, fmt.Errorf("ensure egress container: %w", err)
	}
	if err := d.EnsureNetwork(ctx, eg.Network, managedLabels()); err != nil {
		return nil, nil, fmt.Errorf("ensure egress network: %w", err)
	}
	if err := d.ConnectNetwork(ctx, eg.Network, dockerx.EgressContainerName, dockerx.EgressContainerName); err != nil {
		return nil, nil, fmt.Errorf("connect egress container to network: %w", err)
	}

	// Step 3: the egress session. From here on step 7 always closes it, so
	// the real credentials never outlive the task inside the proxy.
	ctrl, err := egressctl.New(controlURL, m.secret, m.opts.HTTPClient)
	if err != nil {
		return nil, nil, err
	}
	if err := ctrl.OpenSession(ctx, eg.Token, eg.Session); err != nil {
		return nil, nil, err
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer ccancel()
		s, cerr := ctrl.CloseSession(cctx, eg.Token)
		if cerr != nil {
			// agent.exit.egress stays null; the task's own outcome is what
			// gets reported.
			m.logf("agent %s: %v", j.id, cerr)
			return
		}
		stats = s
	}()
	pem, err := ctrl.CA(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Steps 4 and 5: the agent image and the container itself.
	if err := d.EnsureImage(ctx, msg.Image, msg.Pull); err != nil {
		return nil, nil, fmt.Errorf("ensure agent image: %w", err)
	}
	spec := dockerx.RunSpec{
		Name:      j.name,
		Image:     msg.Image,
		User:      msg.User,
		Network:   eg.Network,
		Runtime:   m.opts.Runtime,
		Env:       agentEnv(msg.Env, eg.Token, pem),
		Labels:    agentLabels(msg.Labels),
		Cpus:      msg.Cpus,
		MemoryMb:  msg.MemoryMb,
		PidsLimit: msg.PidsLimit,
	}
	code, err = d.RunStreaming(ctx, spec, func(stream, line string) {
		j.send(OutputMsg{Type: TypeOutput, ID: j.id, Stream: stream, Data: line})
	})
	if err != nil {
		return nil, nil, fmt.Errorf("run agent container: %w", err)
	}
	return code, nil, nil
}

// agentEnv returns env with the proxy settings of step 4 merged on top. The
// session's bindings, which hold the real credentials, never appear here:
// only the session token, which the proxy maps to them in its own memory.
func agentEnv(env map[string]string, token, caPEM string) map[string]string {
	out := make(map[string]string, len(env)+injectedEnvCount)
	for k, v := range env {
		out[k] = v
	}
	proxyURL := "http://" + proxyUser + ":" + token + "@" +
		dockerx.EgressContainerName + ":" + dockerx.EgressProxyPort.Port()
	for _, k := range proxyEnvKeys {
		out[k] = proxyURL
	}
	for _, k := range noProxyEnvKeys {
		out[k] = ""
	}
	out[envGitProxyAuth] = gitProxyAuthMethod
	out[envCAPEM] = caPEM
	return out
}

// agentLabels returns the task's labels as given, with the managed label the
// runner matches on when it cleans up forced on: a task whose container could
// not be found again would leak it.
func agentLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[dockerx.LabelManaged] = "true"
	return out
}

// managedLabels are the labels put on objects this package creates.
func managedLabels() map[string]string {
	return map[string]string{dockerx.LabelManaged: "true"}
}

// Cancel handles agent.cancel. Unknown ids are ignored. It returns without
// waiting for Docker, so the caller's read loop is never blocked.
func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	j := m.jobs[id]
	m.mu.Unlock()
	if j == nil {
		return
	}
	m.logf("agent %s: cancel requested", id)
	m.goTracked(func() { m.stop(j, stopCanceled) })
}

// CancelAll stops every running agent task, which reports each one as
// canceled, and then kills whatever managed container is left behind. It is
// used when the control connection drops: the results can no longer be
// delivered, and closing the sessions drops the real credentials from the
// egress proxy's memory. It returns without waiting for Docker; use Wait to
// block until the tasks are gone.
func (m *Manager) CancelAll() {
	jobs := m.snapshot()
	if len(jobs) == 0 && !m.enabled {
		return
	}
	m.logf("agents: canceling %d running task(s)", len(jobs))
	m.goTracked(func() {
		var wg sync.WaitGroup
		for _, j := range jobs {
			wg.Add(1)
			go func(j *job) {
				defer wg.Done()
				m.stop(j, stopCanceled)
			}(j)
		}
		wg.Wait()
		m.killLeftovers()
	})
}

// Shutdown refuses new tasks and cancels the running ones; their agent.exit
// is still sent while the connection is up.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.CancelAll()
}

// Wait waits up to d for all tasks and their clean-up to finish and reports
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

// stop records why the task ends and asks Docker to stop its container with
// StopGrace (step 6). It blocks until Docker answers.
func (m *Manager) stop(j *job, r stopReason) {
	if !j.setReason(r) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), StopGrace+stopSlack)
	defer cancel()
	if err := m.opts.Docker.Stop(ctx, j.name, StopGrace); err != nil {
		m.logf("agent %s: stop container: %v", j.id, err)
	}
	// Stop only reaches a container that exists, so the run context is
	// canceled as well: that interrupts a step still in flight, such as an
	// image pull, and lets dockerx tear down whatever it created. The
	// session is still closed afterwards, on a context of its own.
	j.cancelRun()
}

// killLeftovers removes containers this runner created that no task owns any
// more, for instance after a crash. The shared egress container carries the
// same label and is removed too; EnsureEgress recreates it for the next task
// and its CA survives in the CA volume.
func (m *Manager) killLeftovers() {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := m.opts.Docker.KillByLabels(ctx, managedLabels()); err != nil {
		m.logf("agents: kill leftover containers: %v", err)
	}
}

// goTracked runs fn in a goroutine that Wait accounts for.
func (m *Manager) goTracked(fn func()) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		fn()
	}()
}

func (m *Manager) forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, id)
}

func (m *Manager) snapshot() []*job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j)
	}
	return out
}

// logf writes one line to the Manager's logger. Nothing passed to it may be
// a session, a token or an environment value.
func (m *Manager) logf(format string, args ...any) {
	m.opts.Logger.Printf(format, args...)
}

func ptr[T any](v T) *T { return &v }
