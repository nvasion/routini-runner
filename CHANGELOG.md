# Changelog

All notable changes to `routini-runner` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0

### Added

- **Agents capability (opt-in).** The runner can run Routini agents as
  containers on the local Docker daemon. It is advertised to the server as the
  `agents` capability only when `capabilities.agents` is `true` in
  `config.json` **and** the local Docker daemon answered a ping at startup;
  host facts gain a `docker` object (`available`, `version`) when the daemon is
  reachable. Agent containers run unprivileged (`1000:1000` by default) with
  all capabilities dropped, `no-new-privileges`, and CPU, memory and PID
  limits; outbound traffic goes through the managed `routini-egress` container
  on an internal bridge network.
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
