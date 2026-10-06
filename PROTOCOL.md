# Routini runner protocol, version 1

This document is the contract between `routini-runner`, the binary running on your server, and a Routini server, which has a runner gateway in its API. If the two implementations disagree, this document is right.

## Principles

- **The runner only dials out.** It never listens on a port. Your firewall needs outbound HTTPS to the Routini URL and nothing else.
- **TLS is verified** against the system roots, or a CA file you pass with `--ca-file`. Plain `http://` and `ws://` work only for URLs on loopback or private addresses (development and labs).
- **The runner holds one secret,** the runner credential. It is stored at mode 0600 and sent only as a Bearer token to the configured URL.
- **Commands run as the runner's own OS user** (`routini-runner` when installed with `install.sh`). To grant privileges, add sudo rules for that user yourself.

## 1. Enrollment (HTTPS, once)

An admin creates an enrollment token in the console. It is single-use, expires after 1 hour, and starts with `rre_`.

```
routini-runner enroll --url https://routini.example.com --token rre_xxx [--name web-01] [--config /etc/routini-runner/config.json]
```

The runner sends:

```http
POST {url}/api/runner/enroll
Content-Type: application/json

{ "token": "rre_xxx", "name": "web-01", "hostname": "web-01.prod", "os": "linux", "arch": "amd64", "version": "0.1.0" }
```

`name` is optional. Without it, the server uses the name given to the enrollment token, or else the hostname.

On success the server answers `201`:

```json
{ "runnerId": "uuid", "credential": "rrc_xxx", "hostId": "uuid", "name": "web-01", "org": "acme" }
```

Errors:

- `401 {"error": "..."}`: the token is unknown, expired or already used.
- `400`: the body is invalid.

The runner writes its config file at mode 0600, creating the parent directory at 0700:

```json
{ "url": "https://routini.example.com", "runnerId": "uuid", "credential": "rrc_xxx", "caFile": null,
  "capabilities": { "exec": true, "pty": true, "agents": false }, "maxConcurrentExec": 8 }
```

Admins can edit `capabilities` and `maxConcurrentExec` by hand. For example, `"pty": false` turns off interactive terminals on that server.

`capabilities.agents` enables containerised agent tasks (section 2.6). Enrollment writes it as `false`, because it needs a local Docker daemon. Setting it to `true` is not enough on its own: the runner advertises `agents` only when **both** `capabilities.agents` is `true` in `config.json` **and** the local Docker daemon answered a ping at startup. If the ping fails, the runner starts normally, does not advertise `agents`, and refuses `agent.start`.

Optional keys that only affect agents:

- `agentImagePrefixes`: image references the runner is willing to run. Missing or empty means `["ghcr.io/nvasion/"]`.
- `maxConcurrentAgents`: default 2. Any value that is not positive means 2.
- `dockerHost`: default `""`, meaning `unix:///var/run/docker.sock`. The `DOCKER_HOST` environment variable overrides it.
- `containerRuntime`: default `""`, meaning Docker's default runtime. `"runsc"` selects gVisor.

## 2. Control connection (WebSocket)

```http
GET {url → ws(s)}/api/runner/connect
Authorization: Bearer rrc_xxx
Routini-Runner-Protocol: 1
```

Responses before the upgrade:

- `401`: the credential is unknown or revoked. The runner exits with code **78** (EX_CONFIG) and does not retry.
- `426`: the protocol version is unsupported. The runner exits with code 78.
- Any other failure: the runner reconnects with exponential backoff, starting at 1 s and capped at 60 s, with ±20% jitter. The backoff resets after a connection stays up for 60 s.

All messages are **JSON text frames**, one object each, with a `type` field. Unknown types are ignored, so either side can add types without breaking the other. Field names are camelCase.

**Liveness:**

- The server sends WebSocket **pings** every 20 s, and the runner answers with pongs (most WebSocket libraries do this automatically).
- If the runner receives no frame or ping for 60 s, it treats the connection as dead and reconnects.
- If the server receives no pong for 60 s, it closes the connection.

### 2.1 Handshake

The runner sends `hello` immediately after the connection opens:

```json
{ "type": "hello", "protocol": 1, "version": "0.1.0", "hostname": "web-01.prod", "os": "linux", "arch": "amd64",
  "capabilities": ["exec", "pty", "agents"], "facts": { ...see 2.2 } }
```

`capabilities` lists only the features the runner will actually serve. `"agents"` appears only when `capabilities.agents` is `true` in `config.json` **and** the local Docker daemon answered a ping at startup; a runner with agents enabled in config but no reachable Docker daemon sends `["exec", "pty"]`.

The server replies with `welcome`:

```json
{ "type": "welcome", "runnerId": "uuid", "name": "web-01" }
```

The runner must not act on any other server frame until it has received `welcome`.

### 2.2 Facts

The runner sends facts in `hello`, then every **60 s** as `{"type": "facts", "facts": {...}}`. They come from `/proc`, `statfs("/")` and `uname`. Every field is optional; the runner omits any it cannot read.

```json
{
  "kernel": "Linux 6.8.0-45-generic",
  "osPretty": "Ubuntu 24.04.1 LTS",
  "uptimeSec": 123456,
  "load1": 0.42, "load5": 0.30, "load15": 0.25,
  "cpus": 4,
  "memTotalMb": 7972, "memUsedPct": 41,
  "diskTotalGb": 78.6, "diskUsedPct": 63,
  "addresses": ["10.0.0.11", "fd00::11"],
  "docker": { "available": true, "version": "27.3.1" }
}
```

- `memUsedPct` is `(MemTotal - MemAvailable) / MemTotal`.
- `diskUsedPct` covers `/` and excludes reserved blocks: `(total - free) / (total - free + avail)`, which is the same as `df`.
- `addresses` lists non-loopback interface addresses.
- `docker` reports the local Docker daemon: `version` is what its ping returned. The whole object is omitted when Docker is unreachable.

### 2.3 Exec: run a command

The server starts a command:

```json
{ "type": "exec.start", "id": "task-uuid", "command": "df -h / | tail -1", "env": { "FOO": "bar" }, "cwd": null, "timeoutSec": 600 }
```

How the runner executes it:

- **Shell:** `/bin/sh -c <command>`, in a **new process group**, with stdin set to `/dev/null`.
- **Environment:** the runner's own environment, plus `env` merged on top. `env` keys must match `^[A-Za-z_][A-Za-z0-9_]*$`; otherwise the runner rejects the command.
- **Working directory:** `cwd` if given, otherwise the runner user's home directory.

The runner streams output as it arrives, one frame per **line**, as UTF-8 text:

```json
{ "type": "exec.output", "id": "task-uuid", "stream": "stdout", "data": "/dev/sda1  79G  50G  26G  66% /" }
```

- Lines are split on `\n`, and a trailing `\r` is stripped.
- Invalid UTF-8 is replaced with U+FFFD.
- A line longer than 16 KiB is split into 16 KiB pieces.
- An unterminated final line is flushed at exit.

When the process ends, the runner sends exactly one `exec.exit`:

```json
{ "type": "exec.exit", "id": "task-uuid", "exitCode": 0, "timedOut": false, "canceled": false, "error": null }
```

- `exitCode` is `null` when the process was killed by a signal, or never started.
- `error` is a short message when the command never ran: `"exec is disabled on this runner"`, `"runner busy (8 commands running)"`, `"invalid env key"`, or a spawn failure.

To cancel, the server sends:

```json
{ "type": "exec.cancel", "id": "task-uuid" }
```

On cancel or timeout, the runner sends SIGTERM to the process group, waits 5 s, then sends SIGKILL to the group. It then reports `canceled: true` or `timedOut: true`.

The runner accepts at most `maxConcurrentExec` commands at a time (default 8). Any extra `exec.start` is answered at once with an `exec.exit` carrying the busy error.

**If the control connection drops,** the runner cancels every running exec. It does this because their results can no longer be delivered, and the server fails those steps anyway. The runner does not re-send output after reconnecting.

### 2.4 PTY: interactive terminal

The server opens a terminal:

```json
{ "type": "pty.open", "id": "session-uuid", "cols": 120, "rows": 32 }
```

The runner starts a login shell in a pseudo-terminal:

- **Shell:** `$SHELL -l`, or `/bin/bash -l`, or `/bin/sh -l`, whichever exists first.
- **Environment:** `TERM=xterm-256color`, `LANG=C.UTF-8`, and the working directory is the runner user's home.

It then replies with one of:

```json
{ "type": "pty.opened", "id": "session-uuid" }
{ "type": "pty.error", "id": "session-uuid", "message": "terminals are disabled on this runner" }
```

Data uses **base64**, because terminal output is not guaranteed to be UTF-8.

From runner to server: `{ "type": "pty.data", "id": "...", "b64": "..." }`. The runner sends chunks of up to 32 KiB as they are read.

From server to runner:

- `{ "type": "pty.input", "id": "...", "b64": "..." }`
- `{ "type": "pty.resize", "id": "...", "cols": 100, "rows": 30 }`
- `{ "type": "pty.close", "id": "..." }`. The runner hangs up the shell's process group (SIGHUP, then SIGKILL after 2 s).

When the shell exits for any reason, the runner sends `{ "type": "pty.exit", "id": "...", "exitCode": 0 }`. That ends the session; frames for that id after this point are ignored.

Each runner allows at most 4 open terminals; a fifth `pty.open` gets `pty.error` "too many terminals". When the control connection drops, all terminals close.

### 2.5 Server-initiated close

```json
{ "type": "revoked" }
```

The server sends this, then closes the connection, when an admin removes the runner. The runner deletes nothing, logs `runner was removed from Routini`, and exits with code 78.

The server may also close the connection with WebSocket close code `4000` (another connection with the same credential replaced this one). The runner must then wait a full backoff interval before reconnecting, so two copies of the same runner do not keep displacing each other.

### 2.6 Agents

An agent task runs a container image instead of a shell command, on an internal Docker network with no route to the internet. Its only way out is `routini-egress`, a local proxy that terminates TLS for the hosts the server allowed and injects the real credentials. The runner serves agent tasks only when it advertised the `agents` capability (2.1).

The server starts an agent:

```json
{ "type": "agent.start", "id": "task-uuid", "image": "ghcr.io/nvasion/routini-agent-claude:0.3.0", "pull": "missing",
  "user": "1000:1000", "cpus": 2, "memoryMb": 4096, "pidsLimit": 512, "timeoutSec": 1800,
  "env": { "ROUTINI_PROMPT": "...", "ANTHROPIC_API_KEY": "routini-brokered-credential" },
  "labels": { "routini.managed": "true", "routini.org": "...", "routini.run": "...", "routini.step": "0" },
  "egress": {
    "image": "ghcr.io/nvasion/routini-egress:0.3.0",
    "network": "routini-sb-<org id>",
    "session": {
      "token": "...",
      "orgId": "...",
      "label": "run 12 step 1",
      "allowedHosts": ["..."],
      "bindings": [ { "host": "api.anthropic.com", "header": "x-api-key", "format": "raw", "secret": "..." } ],
      "expiresAt": "..."
    }
  } }
```

- `pull` is `"missing"` (pull only when the image is absent) or `"always"`.
- `user` defaults to `1000:1000` and `pidsLimit` to 512. `cpus` becomes a CPU quota, `memoryMb` a memory limit in MiB.
- `labels` are set on the agent container as given. `routini.managed=true` and `routini.run` are the ones the runner matches on later, so the server always sends them.
- `egress.network` is the per-org internal network. The runner creates it if it does not exist.
- `egress.session` is passed through to the egress proxy untouched (see step 3).

To cancel, the server sends:

```json
{ "type": "agent.cancel", "id": "task-uuid" }
```

The runner streams container output one frame per **line**, with exactly the framing of `exec.output` (2.3): lines split on `\n`, a trailing `\r` stripped, invalid UTF-8 replaced with U+FFFD, lines longer than 16 KiB split into 16 KiB pieces, and an unterminated final line flushed at exit. `stream` is `"stdout"` or `"stderr"`.

```json
{ "type": "agent.output", "id": "task-uuid", "stream": "stdout", "data": "one line" }
```

Every `agent.start` is answered by exactly one `agent.exit`:

```json
{ "type": "agent.exit", "id": "task-uuid", "exitCode": 0, "timedOut": false, "canceled": false, "error": null,
  "egress": { "requests": 41, "intercepted": 12, "blocked": ["evil.example"] } }
```

- `exitCode` is `null` when the container never ran, was killed, or anything failed.
- `error` is `null` on a clean run, otherwise a short message.
- `egress` holds the session's counters, or `null` when they could not be read.

The runner's steps, in order:

1. **Refusals.** Each one is answered at once with a single `agent.exit` carrying `exitCode: null` and this `error`, and nothing is created:
   - `"agents are disabled on this runner"`, when `agents` was not advertised.
   - `"image not allowed by agentImagePrefixes: <ref>"`, where `<ref>` is the rejected reference. Checked for both the agent image and the egress image.
   - `"runner busy (N agents running)"`, where `N` is the number already running, once `maxConcurrentAgents` is reached.
2. **Egress.** Ensure the egress image and the `routini-egress` container, ensure the internal network `egress.network`, and connect `routini-egress` to it with the alias `routini-egress`. One `routini-egress` container serves every task on the host; it is reused, not recreated per task.
3. **Session.** `PUT <control>/sessions/<token>` with the session JSON as the body and `Authorization: Bearer <secret>`, then `GET <control>/ca`, which returns `{"pem": "..."}`. `<control>` is the loopback URL of `routini-egress`, and `<secret>` is the egress secret known only to the runner and that container.
4. **Environment.** On top of `env`, the agent container gets:
   - `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy` and `http_proxy` = `http://routini:<token>@routini-egress:3128`
   - `NO_PROXY=""` and `no_proxy=""`, so nothing bypasses the proxy
   - `GIT_HTTP_PROXY_AUTHMETHOD=basic`
   - `ROUTINI_CA_PEM=<pem>`, the PEM from step 3
5. **Run.** Ensure the agent image, honouring `pull`, then run it on the internal network, streaming `agent.output` as described above.
6. **Stop.** On `timeoutSec` elapsing or on `agent.cancel`, stop the container with a 10 s grace, then kill it. The exit reports `timedOut: true` or `canceled: true`.
7. **Clean up.** Always `DELETE <control>/sessions/<token>` and report the stats it returns in `agent.exit.egress`, which is `null` when that call failed. The container is always removed, on every path.

Any failure at any step produces one `agent.exit` with `exitCode: null` and a short `error`, after the clean-up of step 7.

**If the control connection drops,** the runner kills all agent containers (the ones labelled `routini.managed=true` plus `routini.run`) and closes their sessions, for the same reason exec tasks are cancelled: their results can no longer be delivered. `routini-egress` stays up, because it is shared and holds the CA.

**Secrets.** Real credentials appear only in `egress.session.bindings`. The runner hands them to the local egress proxy over loopback, where they live in memory only, for the life of the session. They are never written to disk, never logged, and never visible inside the agent container: there, `ANTHROPIC_API_KEY` is the placeholder `routini-brokered-credential`, and the proxy swaps in the real value for allowed hosts according to the bindings.

## 3. Versioning

`Routini-Runner-Protocol` is an integer. The server answers `426` for versions it does not support. New message types and new optional fields do not change the version; a change to existing semantics does.
