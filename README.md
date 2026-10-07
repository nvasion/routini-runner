# routini-runner

`routini-runner` is a small agent that runs on your Linux server and lets
[Routini](https://routini.tynhub.com) run commands and open interactive
terminals there. It connects **out** to your Routini server over a WebSocket
and never listens on a port.

The wire protocol is specified in [PROTOCOL.md](PROTOCOL.md); release notes are
in [CHANGELOG.md](CHANGELOG.md).

## Security model

- **Outbound only.** The runner dials `wss://<your Routini>/api/runner/connect`.
  Your firewall needs outbound HTTPS to the Routini URL and nothing else.
- **TLS is verified** against the system roots, plus an optional CA file
  (`--ca-file`). Plain `http://` / `ws://` is accepted only when the host is
  `localhost`, a loopback or private IP (10/8, 172.16/12, 192.168/16, 127/8,
  ::1, fc00::/7, fe80::/10), or a name that resolves only to such addresses
  (for example a Docker service name like `http://server:3001`). The check is
  repeated on every connection, against the address actually dialed.
- **One secret.** Enrollment exchanges a single-use `rre_` token for a runner
  credential (`rrc_...`). The credential is stored in the config file at mode
  0600 (directory 0700) and is sent only as a Bearer token to the configured
  URL. Neither the token nor the credential is ever logged. Redirects are not
  followed.
- **Commands run as the runner's own OS user** (`routini-runner` when installed
  with `install.sh`), not as root. To allow privileged commands, add sudo
  rules for that user yourself. The systemd unit does not set
  `NoNewPrivileges`, so sudo keeps working.
- **You can switch features off** per server in the config file:
  `"capabilities": {"exec": true, "pty": false}` disables interactive
  terminals; `"exec": false` disables commands. `maxConcurrentExec` caps
  parallel commands (default 8).
- **Agents are off by default.** Running Routini agents in local Docker
  containers has to be switched on deliberately, because it makes the runner's
  user root-equivalent on the host. See
  [Running agents on this server](#running-agents-on-this-server).
- **Removal is final.** If an admin removes the runner in Routini, or its
  credential is rejected, the runner exits with code 78 and systemd does not
  restart it.

## Install (systemd)

On the server, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/nvasion/routini-runner/main/scripts/install.sh \
  | sudo sh -s -- --url https://routini.example.com --token rre_... [--name web-01] [--version v0.2.0] [--enable-agents]
```

The installer:

1. detects the architecture (amd64 or arm64);
2. downloads `routini-runner_<version>_linux_<arch>.tar.gz` and
   `sha256sums.txt` from the GitHub release (the latest one unless
   `--version` is given) and verifies the checksum;
3. installs the binary to `/usr/local/bin/routini-runner`;
4. creates the system user `routini-runner` (home `/var/lib/routini-runner`);
5. enrolls as that user, writing `/etc/routini-runner/config.json`
   (the directory is owned by `routini-runner`, mode 0700);
6. with `--enable-agents`: sets `capabilities.agents` to `true` in that config
   and adds `routini-runner` to the `docker` group, after printing the
   root-equivalence warning (see
   [Running agents on this server](#running-agents-on-this-server));
7. installs the update helper `/usr/local/sbin/routini-runner-update` and,
   unless `--no-remote-update` is given, the sudoers rule that lets Routini
   update this runner (see [Updating](#updating));
8. installs `routini-runner.service` and runs `systemctl enable --now`.

Running it again upgrades the binary and restarts the service; if the config
already exists, enrollment is skipped and `--url`/`--token` are not needed.

### Updating

From v0.3.0 on, Routini can update a runner from its console (Fleet → the
host → **Update runner**). The button runs the root-owned helper
`/usr/local/sbin/routini-runner-update` through sudo. The sudoers rule in
`/etc/sudoers.d/routini-runner` allows the runner's user exactly two
commands:

```
routini-runner-update --check
routini-runner-update vX.Y.Z
```

The helper accepts nothing else from that user. It downloads the release,
checks its sha256 against the release's `sha256sums.txt`, installs it and
restarts the service. To opt out, delete the sudoers file, or re-run
`install.sh --no-remote-update`. Upgrading by re-running `install.sh` always
works.

Runners installed before v0.3.0 have no helper. Re-run `install.sh` once on
such a host; after that, updates can come from the console.

Logs: `journalctl -u routini-runner -f`.

## Docker

```sh
docker run -d --init --name routini-runner \
  -e ROUTINI_RUNNER_URL=https://routini.example.com \
  -e ROUTINI_RUNNER_TOKEN=rre_... \
  -e ROUTINI_RUNNER_NAME=docker-01 \
  -v routini-runner:/home/routini-runner/.config/routini-runner \
  ghcr.io/nvasion/routini-runner:latest
```

Release images are published for linux/amd64 and linux/arm64 as
`ghcr.io/nvasion/routini-runner` with tags `X.Y.Z`, `X.Y` and `latest`. To
build one yourself: `docker build -t routini/runner:dev .`

The image runs `routini-runner up` as user `routini-runner` (uid 10001). On
first start it enrolls with the environment variables and writes
`/home/routini-runner/.config/routini-runner/config.json`; mount a volume
there to keep the enrollment across container re-creation (the token is
single-use). `--init` is recommended so that orphaned background processes
started by commands are reaped.

## Running agents on this server

Routini can run **agents** (for example `routini-agent-claude`) as containers
on this server's own Docker daemon instead of on Routini's infrastructure.
This is **off by default** and has to be switched on per server.

### Requirements

- **Docker 24 or newer**, running locally, reachable at
  `unix:///var/run/docker.sock` (or at `dockerHost` / `$DOCKER_HOST`). The
  runner only advertises the `agents` capability when `capabilities.agents` is
  `true` *and* the daemon answered a ping at startup, so a missing or stopped
  daemon is not fatal — agents are simply not offered.
- **Outbound HTTPS** from this server to:
  - `ghcr.io` (and `pkg-containers.githubusercontent.com`) to pull agent
    images;
  - the **model hosts** the agent talks to (for example
    `api.anthropic.com`);
  - the **repository hosts** the agent clones from (for example
    `github.com`).

  No inbound ports are opened: the runner still only dials out.
- Enough room for the agents: each one gets its own container with CPU, memory
  and PID limits, and at most `maxConcurrentAgents` run at a time.

### Warning: the docker group is root-equivalent

> **Putting the runner's user in the `docker` group makes it root on this
> host.** Anyone who can talk to the Docker socket can start a container that
> mounts `/` and write anywhere as root — the `docker` group is therefore
> *root-equivalent*, and the usual user/sudo boundaries do not contain it.

Enable agents only on a host you are willing to hand over to the agents that
run there — ideally a dedicated VM that holds no other secrets. Agent
containers themselves run unprivileged (`1000:1000` by default) with all
Linux capabilities dropped, `no-new-privileges`, and on an internal network
whose egress goes through Routini's managed proxy container; the
root-equivalence applies to the *runner's* access to the daemon, not to the
agents.

### Enabling agents

Either at install time:

```sh
curl -fsSL https://raw.githubusercontent.com/nvasion/routini-runner/main/scripts/install.sh \
  | sudo sh -s -- --url https://routini.example.com --token rre_... --enable-agents
```

or on an already-installed runner, by editing
`/etc/routini-runner/config.json`:

```json
{
  "capabilities": { "exec": true, "pty": true, "agents": true }
}
```

```sh
sudo usermod -aG docker routini-runner   # once, if not done by the installer
sudo systemctl restart routini-runner
```

The capability is read at startup, so the restart is required. The runner
probes the daemon once while starting and logs either `agents enabled: docker
<version>` or a single warning that Docker is unavailable; only in the first
case does it offer `agents` and `environments` to Routini and report the
daemon in the `docker` object of its facts (`available`, `version`,
`agentsRunning`, `maxAgents`, `environmentsRunning`, `maxEnvironments`).

On a host that already runs v0.3.0 or newer, root can also switch agents on
without re-running the installer:

```sh
sudo routini-runner-update --enable-agents
```

This adds `routini-runner` to the `docker` group, sets `capabilities.agents`
and restarts the service. Routini itself can never do this, because the
`docker` group is root-equivalent; the helper only does it for root on the
host. The console shows this command for hosts that cannot run agents yet.

### Disabling agents

`sudo routini-runner-update --disable-agents` undoes the above. By hand: set
`"agents": false` under `capabilities` (or remove the key) and restart:

```sh
sudo systemctl restart routini-runner
```

To also drop the root-equivalent access, remove the group membership:

```sh
sudo gpasswd -d routini-runner docker
sudo systemctl restart routini-runner
```

Running agents are stopped when the runner shuts down; disabling the
capability only prevents new ones.

### Agent settings

All of these live in `config.json` next to `capabilities`:

| Field | Default | Meaning |
| --- | --- | --- |
| `agentImagePrefixes` | `["ghcr.io/nvasion/"]` | Image references the runner is allowed to pull and run. A request for an image that does not start with one of these prefixes is rejected. |
| `maxConcurrentAgents` | `2` | Cap on agents running at the same time. Any value that is not positive means 2. |
| `containerRuntime` | `""` (Docker's own runtime) | Set to `"runsc"` to run agents under [gVisor](https://gvisor.dev/) for kernel-level isolation. The runtime must already be registered with Docker. |
| `dockerHost` | `""` (`unix:///var/run/docker.sock`) | Docker endpoint to use. `$DOCKER_HOST` overrides it. |

### Environments on this server

**Environments** (long-lived, interactive containers a user works in — shell,
file edits, exec) come bundled with the agents opt-in above: there is no
separate capability flag. Once `capabilities.agents` is `true` and Docker
answered its startup ping, the runner advertises both `agents` and
`environments`, and the same egress, sandboxing and `agentImagePrefixes`
rules apply to environment containers as to agents.

Each environment's data volume **lives on this host** — it is not copied
anywhere else — so removing the runner or its Docker data removes that data
too. `maxEnvironments` (default `4`, next to `maxConcurrentAgents` in
`config.json`) caps how many environment containers run at the same time;
any value that is not positive means 4.

## Configuration

`/etc/routini-runner/config.json` (or `--config PATH`, or
`$ROUTINI_RUNNER_CONFIG`):

```json
{
  "url": "https://routini.example.com",
  "runnerId": "uuid",
  "credential": "rrc_...",
  "caFile": null,
  "capabilities": { "exec": true, "pty": true, "agents": false },
  "maxConcurrentExec": 8,
  "agentImagePrefixes": ["ghcr.io/nvasion/"],
  "maxConcurrentAgents": 2,
  "maxEnvironments": 4,
  "dockerHost": "",
  "containerRuntime": ""
}
```

Missing fields take the defaults above; see
[Running agents on this server](#running-agents-on-this-server) for the agent
settings.

## CLI

```
routini-runner enroll --url URL --token rre_... [--name NAME] [--config PATH] [--ca-file PATH] [--force]
routini-runner run    [--config PATH]
routini-runner up     [--config PATH]
routini-runner facts
routini-runner version
```

- `enroll` exchanges the token for a credential and writes the config. It
  refuses to overwrite an existing config unless `--force` is given.
- `run` connects and serves until SIGINT/SIGTERM. On a signal it cancels
  running commands, closes terminals, closes the connection with code 1000 and
  exits 0. It reconnects with exponential backoff (1 s to 60 s, ±20% jitter).
- `up` (containers): if the config file is missing, enrolls from
  `ROUTINI_RUNNER_URL`, `ROUTINI_RUNNER_TOKEN` and optional
  `ROUTINI_RUNNER_NAME`, then runs.
- `facts` prints the host facts the runner reports (for debugging).

Exit codes: `0` normal stop, `1` error, `2` usage, `78` configuration problem
that a restart cannot fix (no config, credential rejected (401), protocol
unsupported (426), runner removed, enrollment token rejected, plain http to a
public address).

Logs go to stderr, one line per event, with a UTC timestamp.

## How commands and terminals run

- Commands: `/bin/sh -c <command>` in a new process group, stdin `/dev/null`,
  the runner's environment plus the requested `env`, working directory `cwd`
  or the runner user's home. Output is streamed line by line. Timeout and
  cancel send SIGTERM to the group, then SIGKILL after 5 s. Default timeout
  600 s, maximum 86400 s. If the connection drops, running commands are killed.
- Terminals: `$SHELL -l` (or `/bin/bash -l`, `/bin/sh -l`) in a
  pseudo-terminal with `TERM=xterm-256color` and `LANG=C.UTF-8`, at most 4 at
  a time. Closing a terminal sends SIGHUP to the shell's process group, then
  SIGKILL after 2 s.

## Building

Requires Go 1.22 and Linux.

```sh
go vet ./...
go test -race ./...
sh scripts/install_test.sh   # tests the installer helpers, changes nothing
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o routini-runner ./cmd/routini-runner
```

Set the version with
`-ldflags "-X github.com/nvasion/routini-runner/internal/version.Version=0.2.0"`.
Tagging `vX.Y.Z` builds static linux/amd64 and linux/arm64 binaries and
attaches them, with `sha256sums.txt`, to the GitHub release, then pushes the
multi-arch container image to GHCR.

## License

Apache License 2.0. See [LICENSE](LICENSE).
