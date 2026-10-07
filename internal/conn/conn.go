// Package conn runs the runner's control connection (PROTOCOL.md section 2):
// dial, hello/welcome, the read loop and dispatch, liveness, facts and
// reconnect backoff.
package conn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nvasion/routini-runner/internal/agentx"
	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/enroll"
	"github.com/nvasion/routini-runner/internal/envx"
	"github.com/nvasion/routini-runner/internal/execx"
	"github.com/nvasion/routini-runner/internal/facts"
	"github.com/nvasion/routini-runner/internal/ptyx"
	"github.com/nvasion/routini-runner/internal/updatex"
	"github.com/nvasion/routini-runner/internal/urlcheck"
	"github.com/nvasion/routini-runner/internal/version"
)

func ptr[T any](v T) *T { return &v }

// Protocol is the protocol version this runner speaks.
const Protocol = 1

// ConnectPath is the control-connection endpoint, relative to the base URL.
const ConnectPath = "/api/runner/connect"

// CloseReplaced is the close code the server uses when another connection
// with the same credential replaced this one.
const CloseReplaced = 4000

// DockerPingTimeout bounds the startup probe of the local Docker daemon.
// Agents stay unavailable when it does not answer in time.
const DockerPingTimeout = 5 * time.Second

// Sentinel causes of a FatalError.
var (
	ErrUnauthorized        = errors.New("the server rejected the runner credential (401): it is unknown or revoked; re-enroll the runner")
	ErrUnsupportedProtocol = errors.New("the server does not support this runner's protocol version (426): upgrade routini-runner")
	ErrRevoked             = errors.New("runner was removed from Routini")
)

// FatalError ends Run without retrying; the CLI exits with code 78 (EX_CONFIG).
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

// IsFatal reports whether err is a FatalError.
func IsFatal(err error) bool {
	var fe *FatalError
	return errors.As(err, &fe)
}

// Options configures a Runner. Zero values take the protocol defaults.
type Options struct {
	Config *config.Config
	Logger *log.Logger

	Backoff       Backoff
	ReadTimeout   time.Duration // no frame or ping for this long: reconnect (60s)
	WriteTimeout  time.Duration // per-frame write deadline (10s)
	FactsInterval time.Duration // periodic facts (60s)
	KillGrace     time.Duration // exec SIGTERM to SIGKILL (5s)
	HangupGrace   time.Duration // pty SIGHUP to SIGKILL (2s)

	Lookup   urlcheck.Lookup    // DNS for the plaintext URL rule; nil: system resolver
	Facts    func() facts.Facts // nil: facts.Collect
	Hostname string             // "": os.Hostname

	// Docker replaces the client New would build from Config.DockerHost. It
	// is only used when Config.Capabilities.Agents is true, and is pinged
	// like any other; tests inject a fake daemon through it.
	Docker dockerx.Docker

	// UpdateHelper and UpdateExec replace the update helper's path and the
	// way it is run (sudo); tests inject both.
	UpdateHelper string
	UpdateExec   updatex.Exec
}

// Runner holds the state that outlives individual connections.
type Runner struct {
	opts   Options
	cfg    *config.Config
	log    *log.Logger
	base   *url.URL
	dialer *websocket.Dialer
	execs  *execx.Manager
	ptys   *ptyx.Manager
	agents *agentx.Manager
	envs   *envx.Manager
	docker dockerInfo

	updater *updatex.Updater
	updates bool // the update helper answered at startup
}

// dockerInfo is the outcome of the startup Docker probe. Agents are served
// only when it succeeded (PROTOCOL.md section 2.1).
type dockerInfo struct {
	available bool
	version   string
	err       string // why the probe failed, for facts.agents.error
}

// maxProbeError caps the Docker probe error reported in facts.
const maxProbeError = 300

// New validates opts and returns a Runner.
func New(opts Options) (*Runner, error) {
	if opts.Config == nil {
		return nil, errors.New("conn: no config")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	if opts.Backoff == (Backoff{}) {
		opts.Backoff = DefaultBackoff()
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 60 * time.Second
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 10 * time.Second
	}
	if opts.FactsInterval <= 0 {
		opts.FactsInterval = 60 * time.Second
	}
	if opts.KillGrace <= 0 {
		opts.KillGrace = execx.DefaultKillGrace
	}
	if opts.HangupGrace <= 0 {
		opts.HangupGrace = ptyx.DefaultHangupGrace
	}
	if opts.Lookup == nil {
		opts.Lookup = urlcheck.DefaultLookup
	}
	if opts.Facts == nil {
		opts.Facts = facts.Collect
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	base, err := urlcheck.Parse(opts.Config.URL)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := config.TLSConfig(opts.Config.CAFilePath())
	if err != nil {
		return nil, err
	}
	dialer := &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		TLSClientConfig:  tlsCfg,
		Proxy:            http.ProxyFromEnvironment,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  64 * 1024,
	}
	if urlcheck.IsPlaintext(base) {
		dialer.Proxy = nil
		dialer.NetDialContext = urlcheck.GuardedDialContext(&net.Dialer{Timeout: 15 * time.Second}, opts.Lookup)
	}
	cfg := opts.Config
	// Agents need the local Docker daemon. A daemon that does not answer
	// leaves exec and pty untouched: the runner just does not offer agents.
	docker, client := probeDocker(cfg, opts.Docker, opts.Logger)
	// One egress secret per runner process, shared by agentx and envx: both
	// talk to the same routini-egress container, and EnsureEgress recreates
	// it whenever the secret it sees changes, so the two packages must never
	// disagree about it (PROTOCOL.md 2.6 and 2.8).
	egressSecret, err := newEgressSecret()
	if err != nil {
		return nil, err
	}
	agents, err := agentx.New(agentx.Options{
		Docker:        client,
		Enabled:       docker.available,
		ImagePrefixes: cfg.AgentImagePrefixes,
		MaxConcurrent: cfg.MaxConcurrentAgents,
		Runtime:       cfg.ContainerRuntime,
		EgressSecret:  egressSecret,
		Logger:        opts.Logger,
	})
	if err != nil {
		return nil, err
	}
	// Environments come bundled with the agents opt-in and share agentx's
	// Enabled condition exactly (PROTOCOL.md 2.1): both need
	// capabilities.agents and a Docker daemon that answered the startup
	// ping.
	envs := envx.New(envx.Options{
		Docker:          client,
		Enabled:         docker.available,
		ImagePrefixes:   cfg.AgentImagePrefixes,
		MaxEnvironments: cfg.MaxEnvironments,
		Runtime:         cfg.ContainerRuntime,
		EgressSecret:    egressSecret,
		Logger:          opts.Logger,
	})
	// Self-update needs the root-owned helper and its sudo rule (install.sh).
	// Without them (containers, older installs) the runner just does not
	// offer "update".
	updater := updatex.New(updatex.Options{
		Helper: opts.UpdateHelper, Current: version.Version, Exec: opts.UpdateExec, Logger: opts.Logger,
	})
	updates := updater.Available(context.Background())
	if updates {
		opts.Logger.Printf("updates from Routini are enabled")
	}
	return &Runner{
		opts:   opts,
		cfg:    cfg,
		log:    opts.Logger,
		base:   base,
		dialer: dialer,
		execs: execx.NewManager(execx.Options{
			Enabled: cfg.Capabilities.Exec, Max: cfg.MaxConcurrentExec,
			KillGrace: opts.KillGrace, Logger: opts.Logger,
		}),
		ptys: ptyx.NewManager(ptyx.Options{
			Enabled: cfg.Capabilities.Pty, HangupGrace: opts.HangupGrace, Logger: opts.Logger,
		}),
		agents:  agents,
		envs:    envs,
		docker:  docker,
		updater: updater,
		updates: updates,
	}, nil
}

// egressSecretBytes is the length of the secret internal/conn shares with
// agentx, envx and the egress container, before hex encoding.
const egressSecretBytes = 32

// newEgressSecret returns the hex-encoded egress secret generated once per
// runner process.
func newEgressSecret() (string, error) {
	b := make([]byte, egressSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("conn: generate egress secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// probeDocker decides whether this runner serves agents at all: it needs the
// config flag and a daemon that answers. Any failure is reported as a single
// warning and leaves agents unavailable, which is not fatal because exec and
// pty do not depend on Docker.
func probeDocker(cfg *config.Config, injected dockerx.Docker, logger *log.Logger) (dockerInfo, dockerx.Docker) {
	if !cfg.Capabilities.Agents {
		return dockerInfo{}, nil
	}
	client, ver, err := dialDocker(cfg, injected)
	if err != nil {
		logger.Printf("agents are enabled in the config but Docker is unavailable: %v", err)
		msg := err.Error()
		if len(msg) > maxProbeError {
			msg = msg[:maxProbeError]
		}
		return dockerInfo{err: strings.ToValidUTF8(msg, "�")}, nil
	}
	logger.Printf("agents enabled: docker %s, up to %d running at a time", ver, cfg.MaxConcurrentAgents)
	return dockerInfo{available: true, version: ver}, client
}

// dialDocker takes the injected client or builds one from the config, then
// pings it once to learn the daemon's version.
func dialDocker(cfg *config.Config, injected dockerx.Docker) (dockerx.Docker, string, error) {
	client := injected
	if client == nil {
		c, err := dockerx.New(cfg.DockerHost)
		if err != nil {
			return nil, "", err
		}
		client = c
	}
	ctx, cancel := context.WithTimeout(context.Background(), DockerPingTimeout)
	defer cancel()
	version, err := client.Ping(ctx)
	if err != nil {
		return nil, "", err
	}
	return client, version, nil
}

// Run keeps the control connection up until ctx is canceled (it then shuts
// down gracefully and returns nil) or a fatal condition occurs (it returns a
// *FatalError).
func (r *Runner) Run(ctx context.Context) error {
	attempt := 0
	for {
		res := r.session(ctx)
		if res.fatal != nil {
			return &FatalError{Err: res.fatal}
		}
		if ctx.Err() != nil {
			return nil
		}
		replaced := res.closeCode == CloseReplaced
		if res.connected && !replaced && time.Since(res.connectedAt) >= r.opts.Backoff.ResetAfter {
			attempt = 0
		}
		delay := r.opts.Backoff.Delay(attempt, nil)
		if attempt < 32 {
			attempt++
		}
		switch {
		case replaced:
			r.log.Printf("another connection with this runner's credential replaced this one (close 4000); waiting %s before reconnecting", delay.Round(time.Millisecond))
		case res.err != nil:
			r.log.Printf("connection lost: %v; reconnecting in %s", res.err, delay.Round(time.Millisecond))
		default:
			r.log.Printf("connection closed; reconnecting in %s", delay.Round(time.Millisecond))
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

type result struct {
	connected   bool
	connectedAt time.Time
	closeCode   int
	err         error
	fatal       error
}

// wsConn serialises every write (data and control frames) with one mutex,
// as gorilla/websocket allows only one concurrent writer.
type wsConn struct {
	ws           *websocket.Conn
	writeTimeout time.Duration

	mu     sync.Mutex
	closed bool
}

var errConnClosed = errors.New("connection closed")

func (c *wsConn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errConnClosed
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	if err := c.ws.WriteMessage(websocket.TextMessage, b); err != nil {
		c.closed = true
		_ = c.ws.Close() // unblock the read loop
		return err
	}
	return nil
}

func (c *wsConn) writeControl(mt int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return websocket.ErrCloseSent
	}
	return c.ws.WriteControl(mt, data, time.Now().Add(c.writeTimeout))
}

// closeWith sends a close frame; no data frames are written after it.
func (c *wsConn) closeWith(code int, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(c.writeTimeout))
}

type helloMsg struct {
	Type         string      `json:"type"`
	Protocol     int         `json:"protocol"`
	Version      string      `json:"version"`
	Hostname     string      `json:"hostname"`
	OS           string      `json:"os"`
	Arch         string      `json:"arch"`
	Capabilities []string    `json:"capabilities"`
	Facts        facts.Facts `json:"facts"`
}

type factsMsg struct {
	Type  string      `json:"type"`
	Facts facts.Facts `json:"facts"`
}

type welcomeMsg struct {
	RunnerID string `json:"runnerId"`
	Name     string `json:"name"`
}

// capabilities lists the features this runner will actually serve. "agents"
// and "environments" both need the config flag and a Docker daemon that
// answered the startup ping (PROTOCOL.md section 2.1): environments come
// bundled with the agents opt-in, they do not have a config flag of their
// own.
func (r *Runner) capabilities() []string {
	caps := []string{}
	if r.cfg.Capabilities.Exec {
		caps = append(caps, "exec")
	}
	if r.cfg.Capabilities.Pty {
		caps = append(caps, "pty")
	}
	if r.cfg.Capabilities.Agents && r.docker.available {
		caps = append(caps, "agents", "environments")
	}
	if r.updates {
		caps = append(caps, "update")
	}
	return caps
}

// hostFacts collects the host facts and adds the docker object, which only
// the connection can fill in (PROTOCOL.md section 2.2).
func (r *Runner) hostFacts() facts.Facts {
	f := r.opts.Facts()
	if r.docker.available {
		f.Docker = &facts.Docker{
			Available:           true,
			Version:             r.docker.version,
			AgentsRunning:       r.agents.Running(),
			MaxAgents:           r.cfg.MaxConcurrentAgents,
			EnvironmentsRunning: r.envs.Running(),
			MaxEnvironments:     r.cfg.MaxEnvironments,
		}
	}
	f.Agents = &facts.Agents{Configured: r.cfg.Capabilities.Agents}
	if r.cfg.Capabilities.Agents && !r.docker.available {
		f.Agents.Error = r.docker.err
	}
	return f
}

// session runs one connection from dial to close.
func (r *Runner) session(ctx context.Context) result {
	// The plaintext rule is re-checked on every dial: DNS may have changed.
	if _, err := urlcheck.CheckWith(ctx, r.cfg.URL, r.opts.Lookup); err != nil {
		if urlcheck.IsRuleError(err) {
			return result{fatal: err}
		}
		return result{err: err}
	}
	wsURL := urlcheck.WSURL(r.base, ConnectPath)
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+r.cfg.Credential)
	hdr.Set("Routini-Runner-Protocol", fmt.Sprint(Protocol))

	ws, resp, err := r.dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				return result{fatal: ErrUnauthorized}
			case http.StatusUpgradeRequired:
				return result{fatal: ErrUnsupportedProtocol}
			}
			detail := enroll.OneLine(string(body), 200)
			if detail != "" {
				return result{err: fmt.Errorf("connect: server answered %s: %s", resp.Status, detail)}
			}
			return result{err: fmt.Errorf("connect: server answered %s", resp.Status)}
		}
		if urlcheck.IsRuleError(err) {
			return result{fatal: err}
		}
		return result{err: fmt.Errorf("connect: %w", err)}
	}

	res := result{connected: true, connectedAt: time.Now()}
	c := &wsConn{ws: ws, writeTimeout: r.opts.WriteTimeout}
	r.log.Printf("connected to %s; waiting for welcome", r.base.Host)

	var sendErrOnce sync.Once
	send := func(v any) {
		if err := c.send(v); err != nil {
			sendErrOnce.Do(func() { r.log.Printf("send failed: %v", err) })
		}
	}

	done := make(chan struct{}) // closed when the read loop has ended
	gracefulDone := make(chan struct{})
	go func() {
		defer close(gracefulDone)
		select {
		case <-ctx.Done():
			r.gracefulClose(c, done)
		case <-done:
		}
	}()

	hello := helloMsg{
		Type:         "hello",
		Protocol:     Protocol,
		Version:      version.Version,
		Hostname:     r.opts.Hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Capabilities: r.capabilities(),
		Facts:        r.hostFacts(),
	}
	if err := c.send(hello); err != nil {
		res.err = fmt.Errorf("send hello: %w", err)
	} else {
		res.closeCode, res.err, res.fatal = r.readLoop(c, send, done)
	}
	close(done)

	if res.fatal == nil && ctx.Err() != nil {
		<-gracefulDone
		_ = ws.Close()
		return res
	}
	// The connection dropped (or the runner was revoked): results can no
	// longer be delivered, so stop everything without reporting. Canceling
	// the agents also closes their egress sessions, which drops the real
	// credentials from the proxy's memory (PROTOCOL.md section 2.6).
	r.execs.AbortAll()
	r.ptys.AbortAll()
	r.agents.CancelAll()
	r.envs.Disconnect()
	if res.fatal != nil {
		c.closeWith(websocket.CloseNormalClosure, "")
	}
	_ = ws.Close()
	<-gracefulDone
	return res
}

// gracefulClose runs on SIGINT/SIGTERM: cancel running commands and agent
// tasks (their exec.exit and agent.exit are still sent), close terminals,
// then close the socket with 1000.
func (r *Runner) gracefulClose(c *wsConn, readDone <-chan struct{}) {
	r.log.Printf("shutting down: canceling running commands and agent tasks, and closing terminals")
	r.execs.Shutdown()
	r.ptys.Shutdown()
	// Agents are stopped too: waiting for them lets each one send its
	// agent.exit and close its egress session while the socket is still up.
	r.agents.Shutdown()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); r.execs.Wait(r.opts.KillGrace + time.Second) }()
	go func() { defer wg.Done(); r.ptys.Wait(r.opts.HangupGrace + time.Second) }()
	go func() { defer wg.Done(); r.agents.Wait(agentx.StopGrace + time.Second) }()
	wg.Wait()
	r.execs.AbortAll()
	r.ptys.AbortAll()
	c.closeWith(websocket.CloseNormalClosure, "runner shutting down")
	// Give the server a moment to echo the close frame, then drop the socket.
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
	}
	_ = c.ws.Close()
}

// readLoop reads frames until the connection ends. It returns the close code
// (if the peer sent one), the error that ended the loop, and a fatal error
// for conditions that must stop the runner.
func (r *Runner) readLoop(c *wsConn, send func(any), done <-chan struct{}) (closeCode int, err error, fatal error) {
	ws := c.ws
	ws.SetReadLimit(16 << 20)
	extend := func() { _ = ws.SetReadDeadline(time.Now().Add(r.opts.ReadTimeout)) }
	extend()
	ws.SetPingHandler(func(data string) error {
		extend()
		err := c.writeControl(websocket.PongMessage, []byte(data))
		if err == nil || err == websocket.ErrCloseSent {
			return nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		return err
	})
	ws.SetPongHandler(func(string) error { extend(); return nil })
	ws.SetCloseHandler(func(code int, _ string) error {
		// Echo the close frame under the write lock (gorilla's default
		// handler would write outside it).
		msg := []byte{}
		if code != websocket.CloseNoStatusReceived {
			msg = websocket.FormatCloseMessage(code, "")
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed {
			c.closed = true
			_ = ws.WriteControl(websocket.CloseMessage, msg, time.Now().Add(c.writeTimeout))
		}
		return nil
	})

	st := &dispatchState{send: send, done: done}
	for {
		mt, data, rerr := ws.ReadMessage()
		if rerr != nil {
			var ce *websocket.CloseError
			if errors.As(rerr, &ce) {
				closeCode = ce.Code
			}
			return closeCode, rerr, nil
		}
		extend()
		if mt != websocket.TextMessage {
			continue
		}
		if f := r.dispatch(st, data); f != nil {
			return 0, nil, f
		}
	}
}

type dispatchState struct {
	welcomed bool
	send     func(any)
	done     <-chan struct{}
}

type envelope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (r *Runner) dispatch(st *dispatchState, data []byte) error {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.Type == "" {
		if err == nil {
			err = errors.New("missing type")
		}
		r.log.Printf("ignoring malformed frame: %v", err)
		return nil
	}

	if !st.welcomed {
		if env.Type != "welcome" {
			r.log.Printf("ignoring %q received before welcome", env.Type)
			return nil
		}
		var w welcomeMsg
		if err := json.Unmarshal(data, &w); err != nil {
			r.log.Printf("ignoring malformed welcome: %v", err)
			return nil
		}
		st.welcomed = true
		r.log.Printf("welcome: runner %q (%s)", w.Name, w.RunnerID)
		go r.factsLoop(st.send, st.done)
		return nil
	}

	switch env.Type {
	case "exec.start":
		var m execx.StartMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed exec.start: %v", err)
			if env.ID != "" {
				st.send(execx.ErrorExit(env.ID, "invalid exec.start message"))
			}
			return nil
		}
		r.execs.Start(m, st.send)
	case "exec.cancel":
		r.execs.Cancel(env.ID)
	case "agent.start":
		var m agentx.StartMsg
		if err := json.Unmarshal(data, &m); err != nil {
			// The frame carries the egress session, so only the id is logged.
			r.log.Printf("ignoring malformed agent.start %q", env.ID)
			if env.ID != "" {
				st.send(agentx.ErrorExit(env.ID, "invalid agent.start message"))
			}
			return nil
		}
		r.agents.Start(m, st.send)
	case "agent.cancel":
		r.agents.Cancel(env.ID)
	case "env.op":
		var m envx.OpMsg
		if err := json.Unmarshal(data, &m); err != nil {
			// The frame may carry a session or env values, so only the id
			// is logged.
			r.log.Printf("ignoring malformed env.op %q", env.ID)
			if env.ID != "" {
				st.send(envx.DoneMsg{Type: envx.TypeDone, ID: env.ID, Error: ptr("invalid env.op message")})
			}
			return nil
		}
		r.envs.Op(m, st.send)
	case "env.cancel":
		r.envs.Cancel(env.ID)
	case "env.tty.open":
		var m envx.TTYOpenMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed env.tty.open: %v", err)
			if env.ID != "" {
				st.send(envx.TTYErrorMsg{Type: envx.TypeTTYError, ID: env.ID, Message: "invalid env.tty.open message"})
			}
			return nil
		}
		r.envs.OpenTTY(m, st.send)
	case "env.tty.input":
		var m envx.TTYInputMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed env.tty.input: %v", err)
			return nil
		}
		r.envs.TTYInput(m)
	case "env.tty.resize":
		var m envx.TTYResizeMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed env.tty.resize: %v", err)
			return nil
		}
		r.envs.TTYResize(m)
	case "env.tty.close":
		r.envs.TTYClose(env.ID)
	case "runner.update":
		var m updatex.Msg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed runner.update: %v", err)
			if env.ID != "" {
				st.send(updatex.ResultMsg{Type: "runner.update.result", ID: env.ID, Error: ptr("invalid runner.update message")})
			}
			return nil
		}
		r.updater.Start(r.updates, m, st.send)
	case "pty.open":
		var m ptyx.OpenMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed pty.open: %v", err)
			if env.ID != "" {
				st.send(ptyx.ErrorReply(env.ID, "invalid pty.open message"))
			}
			return nil
		}
		r.ptys.Open(m, st.send)
	case "pty.input":
		var m ptyx.InputMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed pty.input: %v", err)
			return nil
		}
		r.ptys.Input(m)
	case "pty.resize":
		var m ptyx.ResizeMsg
		if err := json.Unmarshal(data, &m); err != nil {
			r.log.Printf("ignoring malformed pty.resize: %v", err)
			return nil
		}
		r.ptys.Resize(m)
	case "pty.close":
		r.ptys.Close(env.ID)
	case "revoked":
		return ErrRevoked // logged by the caller as "runner was removed from Routini"
	case "welcome":
		// Duplicate welcome: nothing to do.
	default:
		// Unknown types are ignored so either side can add new ones.
	}
	return nil
}

func (r *Runner) factsLoop(send func(any), done <-chan struct{}) {
	t := time.NewTicker(r.opts.FactsInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			send(factsMsg{Type: "facts", Facts: r.hostFacts()})
		}
	}
}
