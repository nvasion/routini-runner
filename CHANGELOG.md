# Changelog

All notable changes to `routini-runner` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0

### Added

- **Environments.** A new `environments` capability (bundled with the
  `agents` opt-in) and `env.op`, `env.cancel`, `env.tty.open`,
  `env.tty.input`, `env.tty.resize`, `env.tty.close`, `env.output`,
  `env.done`, `env.tty.opened`, `env.tty.error`, `env.tty.data` and
  `env.tty.exit` frames (PROTOCOL.md section 2.8). `internal/envx` runs each
  `env.op` in its own goroutine and always answers with exactly one
  `env.done`: `volume.ensure`/`volume.remove`, `network.ensure` (which
  shares the `routini-egress` proxy agents use), `session.open`/
  `session.close`, `container.start`/`container.remove`/`container.state`,
  `exec` (streaming `env.output` line by line, killable by `env.cancel` or a
  timeout) and `pull`. Up to 4 environment terminals can be open at once,
  independent of the PTY limit. Unlike agent tasks, a dropped control
  connection cancels running `exec` ops, closes terminals and closes egress
  sessions, but leaves environment containers and volumes running: they are
  long-lived state the server reconnects to.
- `facts.docker.environmentsRunning` now reports the real count of running
  environment containers instead of a placeholder zero.

### Changed

- The egress control client (`internal/agentx/control.go`) moved to its own
  package, `internal/egressctl`, shared by agents and environments.
- `internal/conn` now generates one egress secret per runner process and
  hands the same value to both `internal/agentx` and the new
  `internal/envx`, so `EnsureEgress` never sees them disagree and recreate
  `routini-egress` out from under one another.
- `dockerx.Docker` gained `InspectVolume`, which `container.start` uses to
  confirm a volume carries the same `routini.environment` label as the
  container before mounting it.

## 0.3.0

### Added

- **Updates from the Routini console.** A new `update` capability and
  `runner.update` / `runner.update.result` frames (PROTOCOL.md section 2.7).
  - `install.sh` installs a root-owned helper,
    `/usr/local/sbin/routini-runner-update`.
  - It also adds a sudoers rule that lets the runner's user run only
    `routini-runner-update --check` and `routini-runner-update vX.Y.Z`.
  - The helper downloads and sha256-verifies that release, installs it, and
    schedules a restart.
  - Opt out with `install.sh --no-remote-update`.
- **`routini-runner-update --enable-agents` / `--disable-agents`.** Root on
  the host can switch agents (docker group plus `capabilities.agents`) without
  re-running the installer. Routini cannot trigger this.
- **`routini-runner agents enable|disable|status`.** Edits
  `capabilities.agents` in the config and keeps the file's owner and mode.
- **`facts.agents`.** `{ configured, error }` tells the console why a host
  does not run agents: not configured, or Docker refused (e.g. a permission
  error on the socket).

### Changed

- Release archives now include `routini-runner-update`.

## 0.2.0

### Added

- **Agents capability (opt-in).** The runner can run Routini agents as
  containers on the local Docker daemon. It is advertised to the server as the
  `agents` capability only when `capabilities.agents` is `true` in
  `config.json` **and** the local Docker daemon answered a ping at startup;
  host facts gain a `docker` object (`available`, `version`, `agentsRunning`,
  `maxAgents`) when the daemon is reachable. Agent containers run unprivileged
  (`1000:1000` by default) with all capabilities dropped,
  `no-new-privileges`, and CPU, memory and PID limits; outbound traffic goes
  through the managed `routini-egress` container on an internal bridge
  network.
- **Agent frames** `agent.start`, `agent.cancel`, `agent.output` and
  `agent.exit` (PROTOCOL.md section 2.6). Each `agent.start` is answered by
  exactly one `agent.exit`; the egress session that holds the real
  credentials is opened on the local proxy before the container starts and
  always closed afterwards, and the agent container only ever sees the
  session token and the proxy's CA. Dropping the control connection cancels
  every running agent task and closes its session.
- New config fields: `agentImagePrefixes` (default `["ghcr.io/nvasion/"]`,
  the only image references the runner will pull or run),
  `maxConcurrentAgents` (default 2), `dockerHost` (default
  `unix:///var/run/docker.sock`, overridden by `$DOCKER_HOST`) and
  `containerRuntime` (default: Docker's own runtime; `"runsc"` selects
  gVisor).
- `scripts/install.sh` gains `--enable-agents`, which writes
  `capabilities.agents: true` into `config.json` and adds the
  `routini-runner` system user to the `docker` group. Membership of the
  `docker` group is **root-equivalent** on the host, so the installer prints a
  warning and the flag is never implied.
- `README.md` gains a "Running agents on this server" section: requirements,
  the root-equivalence warning, how to enable and disable the capability, and
  the new config fields.

### Changed

- The agents capability is off by default; without `--enable-agents` (or
  `capabilities.agents` in `config.json`) the runner behaves exactly as in
  0.1.0. Command execution and interactive terminals are unchanged.

## 0.1.0

### Added

- First release: outbound-only WebSocket runner for Routini with command
  execution (`exec`) and interactive terminals (`pty`), single-use enrollment
  tokens, host facts, `scripts/install.sh` for systemd and multi-arch
  container images on `ghcr.io/nvasion/routini-runner`.
