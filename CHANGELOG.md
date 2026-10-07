# Changelog

All notable changes to `routini-runner` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

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
