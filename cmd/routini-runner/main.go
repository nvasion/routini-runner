// Command routini-runner is the Routini runner agent: it dials out to a
// Routini server over WebSocket and runs commands and terminals on its
// behalf. See PROTOCOL.md for the wire contract.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nvasion/routini-runner/internal/config"
	"github.com/nvasion/routini-runner/internal/conn"
	"github.com/nvasion/routini-runner/internal/enroll"
	"github.com/nvasion/routini-runner/internal/facts"
	"github.com/nvasion/routini-runner/internal/urlcheck"
	"github.com/nvasion/routini-runner/internal/version"
)

// Exit codes.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitConfig = 78 // EX_CONFIG: do not restart (systemd RestartPreventExitStatus=78)
)

// Environment variables read by `up`.
const (
	envURL   = "ROUTINI_RUNNER_URL"
	envToken = "ROUTINI_RUNNER_TOKEN"
	envName  = "ROUTINI_RUNNER_NAME"
)

const usage = `routini-runner %s - runs commands and terminals for Routini on this server

Usage:
  routini-runner enroll --url URL --token rre_... [--name NAME] [--config PATH] [--ca-file PATH] [--force]
  routini-runner run [--config PATH]
  routini-runner up [--config PATH]
  routini-runner facts
  routini-runner version

Commands:
  enroll   exchange a single-use enrollment token for a runner credential and write the config
  run      connect to Routini and serve until SIGINT/SIGTERM
  up       for containers: enroll from $ROUTINI_RUNNER_URL / $ROUTINI_RUNNER_TOKEN
           (optional $ROUTINI_RUNNER_NAME) if no config exists yet, then run
  facts    print the host facts sent to Routini, as JSON
  version  print the version

The config path defaults to $ROUTINI_RUNNER_CONFIG, else /etc/routini-runner/config.json.
`

// connHook lets tests adjust connection options (backoff, timeouts).
var connHook func(*conn.Options)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

type cli struct {
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	log    *log.Logger
}

func realMain(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	c := &cli{stdout: stdout, stderr: stderr, getenv: getenv, log: newLogger(stderr)}
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version.Version)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "enroll":
		return c.cmdEnroll(rest)
	case "run":
		return c.cmdRun(rest)
	case "up":
		return c.cmdUp(rest)
	case "facts":
		return c.cmdFacts(rest)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "routini-runner %s\n", version.Version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version.Version)
		return exitOK
	default:
		fmt.Fprintf(stderr, "routini-runner: unknown command %q\n\n", cmd)
		fmt.Fprintf(stderr, usage, version.Version)
		return exitUsage
	}
}

// tsWriter prefixes each log line with an RFC 3339 UTC timestamp.
type tsWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (t *tsWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + string(p)
	if _, err := io.WriteString(t.w, line); err != nil {
		return 0, err
	}
	return len(p), nil
}

func newLogger(w io.Writer) *log.Logger {
	return log.New(&tsWriter{w: w}, "", 0)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func (c *cli) newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(c.stderr)
	return flags
}

func (c *cli) cmdEnroll(args []string) int {
	flags := c.newFlags("enroll")
	url := flags.String("url", "", "Routini base URL, e.g. https://routini.example.com")
	token := flags.String("token", "", "enrollment token (rre_...)")
	name := flags.String("name", "", "runner name (default: the token's name, else the hostname)")
	cfgPath := flags.String("config", "", "config path (default $ROUTINI_RUNNER_CONFIG or "+config.DefaultPath+")")
	caFile := flags.String("ca-file", "", "PEM file with extra CA certificates to trust")
	force := flags.Bool("force", false, "replace an existing config")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(c.stderr, "enroll: unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return exitUsage
	}
	if *url == "" || *token == "" {
		fmt.Fprintln(c.stderr, "enroll: --url and --token are required")
		return exitUsage
	}
	path := config.ResolvePath(*cfgPath)
	if !*force && fileExists(path) {
		c.log.Printf("enroll: %s already exists; this runner is already enrolled (use --force to replace it)", path)
		return exitError
	}
	ctx, cancel := signalContext()
	defer cancel()
	return c.enroll(ctx, *url, *token, *name, *caFile, path)
}

func (c *cli) enroll(ctx context.Context, rawURL, token, name, caFile, path string) int {
	base, err := urlcheck.Check(ctx, rawURL)
	if err != nil {
		c.log.Printf("enroll: %v", err)
		if urlcheck.IsRuleError(err) {
			return exitConfig
		}
		return exitError
	}
	var caPtr *string
	if caFile != "" {
		abs, err := filepath.Abs(caFile)
		if err != nil {
			c.log.Printf("enroll: --ca-file: %v", err)
			return exitConfig
		}
		caPtr = &abs
	}
	tlsCfg, err := config.TLSConfig(caFile)
	if err != nil {
		c.log.Printf("enroll: %v", err)
		return exitConfig
	}
	hostname, _ := os.Hostname()
	client := enroll.NewHTTPClient(base, tlsCfg, nil)
	resp, err := enroll.Enroll(ctx, client, base, enroll.Request{
		Token:    strings.TrimSpace(token),
		Name:     name,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  version.Version,
	})
	if err != nil {
		c.log.Printf("enroll: %v", err)
		if errors.Is(err, enroll.ErrTokenRejected) || urlcheck.IsRuleError(err) {
			return exitConfig
		}
		return exitError
	}
	cfg := config.New()
	cfg.URL = base.String()
	cfg.RunnerID = resp.RunnerID
	cfg.Credential = resp.Credential
	cfg.CAFile = caPtr
	if err := config.Save(path, cfg); err != nil {
		c.log.Printf("enroll: %v", err)
		return exitError
	}
	org := ""
	if resp.Org != "" {
		org = " in org " + resp.Org
	}
	c.log.Printf("enrolled as %q (runner %s)%s; config written to %s", resp.Name, resp.RunnerID, org, path)
	return exitOK
}

func (c *cli) cmdRun(args []string) int {
	flags := c.newFlags("run")
	cfgPath := flags.String("config", "", "config path (default $ROUTINI_RUNNER_CONFIG or "+config.DefaultPath+")")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	ctx, cancel := signalContext()
	defer cancel()
	return c.run(ctx, config.ResolvePath(*cfgPath))
}

func (c *cli) run(ctx context.Context, path string) int {
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			c.log.Printf("no config at %s: enroll this runner first with `routini-runner enroll`", path)
		} else {
			c.log.Printf("%v", err)
		}
		return exitConfig
	}
	opts := conn.Options{Config: cfg, Logger: c.log}
	if connHook != nil {
		connHook(&opts)
	}
	r, err := conn.New(opts)
	if err != nil {
		c.log.Printf("%v", err)
		return exitConfig
	}
	c.log.Printf("routini-runner %s starting (protocol %d, runner %s)", version.Version, conn.Protocol, cfg.RunnerID)
	if err := r.Run(ctx); err != nil {
		code := exitError
		if conn.IsFatal(err) {
			code = exitConfig
		}
		c.log.Printf("%v; exiting with code %d", err, code)
		return code
	}
	c.log.Printf("stopped")
	return exitOK
}

func (c *cli) cmdUp(args []string) int {
	flags := c.newFlags("up")
	cfgPath := flags.String("config", "", "config path (default $ROUTINI_RUNNER_CONFIG or "+config.DefaultPath+")")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	path := config.ResolvePath(*cfgPath)
	ctx, cancel := signalContext()
	defer cancel()
	if !fileExists(path) {
		url, token := c.getenv(envURL), c.getenv(envToken)
		if url == "" || token == "" {
			c.log.Printf("no config at %s: set %s and %s to enroll this runner", path, envURL, envToken)
			return exitConfig
		}
		if code := c.enroll(ctx, url, token, c.getenv(envName), "", path); code != exitOK {
			return code
		}
	}
	return c.run(ctx, path)
}

func (c *cli) cmdFacts(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(c.stderr, "facts: takes no arguments")
		return exitUsage
	}
	b, err := json.MarshalIndent(facts.Collect(), "", "  ")
	if err != nil {
		c.log.Printf("facts: %v", err)
		return exitError
	}
	fmt.Fprintln(c.stdout, string(b))
	return exitOK
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
