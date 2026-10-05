# routini-runner

`routini-runner` is a small agent that runs on your Linux server and lets
[Routini](https://routini.tynhub.com) run commands and open interactive
terminals there. It connects **out** to your Routini server over a WebSocket
and never listens on a port.

The wire protocol is specified in [PROTOCOL.md](PROTOCOL.md).

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
- **Removal is final.** If an admin removes the runner in Routini, or its
  credential is rejected, the runner exits with code 78 and systemd does not
  restart it.

## Install (systemd)

On the server, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/nvasion/routini-runner/main/scripts/install.sh \
  | sudo sh -s -- --url https://routini.example.com --token rre_... [--name web-01] [--version v0.1.0]
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
6. installs `routini-runner.service` and runs `systemctl enable --now`.

Running it again upgrades the binary and restarts the service; if the config
already exists, enrollment is skipped and `--url`/`--token` are not needed.

Logs: `journalctl -u routini-runner -f`.

## Docker

```sh
docker build -t routini/runner:dev .
docker run -d --init --name routini-runner \
  -e ROUTINI_RUNNER_URL=https://routini.example.com \
  -e ROUTINI_RUNNER_TOKEN=rre_... \
  -e ROUTINI_RUNNER_NAME=docker-01 \
  -v routini-runner:/home/routini-runner/.config/routini-runner \
  routini/runner:dev
```

The image runs `routini-runner up` as user `routini-runner` (uid 10001). On
first start it enrolls with the environment variables and writes
`/home/routini-runner/.config/routini-runner/config.json`; mount a volume
there to keep the enrollment across container re-creation (the token is
single-use). `--init` is recommended so that orphaned background processes
started by commands are reaped.

## Configuration

`/etc/routini-runner/config.json` (or `--config PATH`, or
`$ROUTINI_RUNNER_CONFIG`):

```json
{
  "url": "https://routini.example.com",
  "runnerId": "uuid",
  "credential": "rrc_...",
  "caFile": null,
  "capabilities": { "exec": true, "pty": true },
  "maxConcurrentExec": 8
}
```

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
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o routini-runner ./cmd/routini-runner
```

Set the version with
`-ldflags "-X github.com/nvasion/routini-runner/internal/version.Version=0.1.0"`.
Tagging `vX.Y.Z` builds static linux/amd64 and linux/arm64 binaries and
attaches them, with `sha256sums.txt`, to the GitHub release.

## License

Apache License 2.0. See [LICENSE](LICENSE).
