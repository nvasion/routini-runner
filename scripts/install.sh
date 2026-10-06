#!/bin/sh
# Install routini-runner as a systemd service.
#
#   curl -fsSL https://raw.githubusercontent.com/nvasion/routini-runner/main/scripts/install.sh \
#     | sudo sh -s -- --url https://routini.example.com --token rre_... [--name web-01] [--version v0.2.0]
#
# Re-running is safe: the binary is replaced (upgraded) and, when
# /etc/routini-runner/config.json already exists, enrollment is skipped.
#
# --enable-agents opts this host into running Routini agents in local Docker
# containers. See the "Running agents on this server" section of README.md:
# it puts the runner's user in the docker group, which is root-equivalent.
set -eu

REPO="nvasion/routini-runner"
BIN_DIR="/usr/local/bin"
BIN="$BIN_DIR/routini-runner"
RUNNER_USER="routini-runner"
RUNNER_HOME="/var/lib/routini-runner"
CONFIG_DIR="/etc/routini-runner"
CONFIG="$CONFIG_DIR/config.json"
UNIT="/etc/systemd/system/routini-runner.service"

DOCKER_GROUP="docker"
# Agent containers need Docker 24 or newer (see README.md).
MIN_DOCKER_MAJOR=24

URL=""
TOKEN=""
NAME=""
VERSION=""
ENABLE_AGENTS=0

say() { printf 'routini-runner install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
# shquote prints $1 as a single-quoted shell word.
shquote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

usage() {
	cat >&2 <<EOF
Usage: install.sh --url URL --token rre_... [--name NAME] [--version vX.Y.Z]
                  [--enable-agents]

  --url            Routini base URL (https://..., or http:// on a private network)
  --token          single-use enrollment token from the Routini console
  --name           runner name (default: the token's name, else the hostname)
  --version        release tag to install (default: the latest release)
  --enable-agents  let Routini run agents in local Docker containers: sets
                   capabilities.agents in the config and adds the
                   $RUNNER_USER user to the $DOCKER_GROUP group, which is
                   ROOT-EQUIVALENT on this host

--url and --token are only needed for the first install; later runs upgrade
the binary and keep the existing enrollment.
EOF
	exit 2
}

need_value() {
	[ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
}

# config_enable_agents CONFIG [OWNER]
#
# Sets capabilities.agents to true in the JSON config at CONFIG, leaving every
# other field untouched, and rewrites the file atomically at mode 0600 (owned
# by OWNER when given). The config holds the runner credential, so nothing
# read from it is ever printed. Returns non-zero (with a message) on failure.
config_enable_agents() {
	_cfg="$1"
	_owner="${2:-}"
	[ -f "$_cfg" ] || { say "error: $_cfg does not exist"; return 1; }
	_dir="$(dirname "$_cfg")"
	_tmp="$(mktemp "$_dir/.config-agents-XXXXXX")" || {
		say "error: could not create a temporary file in $_dir"
		return 1
	}
	# Read the config twice: the first pass finds the capabilities object and
	# whether it already has an "agents" key, the second pass rewrites it.
	if ! awk '
		function indent(s) { match(s, /^[ \t]*/); return substr(s, 1, RLENGTH) }
		BEGIN { entry = "\"agents\": true" }
		NR == FNR {
			if ($0 ~ /"/) root_keys++
			if (in_caps) {
				if ($0 ~ /"agents"[ \t]*:/) has_agents = 1
				if ($0 ~ /"/) caps_entries++
				if ($0 ~ /\}/) in_caps = 0
			} else if ($0 ~ /"capabilities"[ \t]*:/) {
				has_caps = 1
				if ($0 ~ /\}/) { if ($0 ~ /"agents"[ \t]*:/) has_agents = 1 }
				else in_caps = 1
			}
			next
		}
		!out_caps && $0 ~ /"capabilities"[ \t]*:/ {
			if ($0 ~ /\}/) {
				if (has_agents) sub(/"agents"[ \t]*:[ \t]*[^,}]*/, entry)
				else if ($0 ~ /\{[ \t]*\}/) sub(/\{[ \t]*\}/, "{" entry "}")
				else sub(/[ \t]*\}/, ", " entry "}")
				print
				next
			}
			out_caps = 1
			print
			if (!has_agents) print indent($0) "  " entry (caps_entries > 0 ? "," : "")
			next
		}
		out_caps {
			if ($0 ~ /"agents"[ \t]*:/) sub(/"agents"[ \t]*:[ \t]*[^,}]*/, entry)
			if ($0 ~ /\}/) out_caps = 0
			print
			next
		}
		{
			print
			if (!has_caps && !added && $0 ~ /^[ \t]*\{[ \t]*$/) {
				added = 1
				print "  \"capabilities\": { " entry " }" (root_keys > 0 ? "," : "")
			}
		}
	' "$_cfg" "$_cfg" >"$_tmp"; then
		rm -f "$_tmp"
		say "error: could not rewrite $_cfg"
		return 1
	fi
	# Refuse to install a rewrite that did not do what it claims.
	if ! grep -q '"agents"[[:space:]]*:[[:space:]]*true' "$_tmp"; then
		rm -f "$_tmp"
		say "error: could not set capabilities.agents in $_cfg"
		return 1
	fi
	chmod 0600 "$_tmp" || { rm -f "$_tmp"; return 1; }
	if [ -n "$_owner" ]; then
		chown "$_owner:$_owner" "$_tmp" || { rm -f "$_tmp"; return 1; }
	fi
	mv -f "$_tmp" "$_cfg" || { rm -f "$_tmp"; say "error: could not replace $_cfg"; return 1; }
	return 0
}

# add_to_group USER GROUP: makes USER a member of GROUP (idempotent).
add_to_group() {
	_user="$1"
	_group="$2"
	if id -nG "$_user" 2>/dev/null | tr ' ' '\n' | grep -qx "$_group"; then
		say "$_user is already in the $_group group"
		return 0
	fi
	if command -v usermod >/dev/null 2>&1; then
		usermod -aG "$_group" "$_user" || return 1
	elif command -v gpasswd >/dev/null 2>&1; then
		gpasswd -a "$_user" "$_group" >/dev/null || return 1
	elif command -v adduser >/dev/null 2>&1; then
		adduser "$_user" "$_group" >/dev/null || return 1 # busybox form
	else
		say "error: none of usermod, gpasswd or adduser is available"
		return 1
	fi
	say "added $_user to the $_group group"
	return 0
}

# docker_major prints the major version of the installed Docker CLI, or nothing.
docker_major() {
	command -v docker >/dev/null 2>&1 || return 0
	docker --version 2>/dev/null |
		sed -n 's/^Docker version \([0-9][0-9]*\)\..*/\1/p' | head -n 1
}

# warn_docker_version warns when Docker is missing or older than MIN_DOCKER_MAJOR.
warn_docker_version() {
	if ! command -v docker >/dev/null 2>&1; then
		say "warning: docker was not found on this host. Install Docker $MIN_DOCKER_MAJOR"
		say "         or newer; until the daemon answers, the runner starts normally"
		say "         but does not advertise the agents capability."
		return 0
	fi
	_major="$(docker_major)"
	if [ -z "$_major" ]; then
		say "warning: could not determine the Docker version; $MIN_DOCKER_MAJOR or newer is required"
	elif [ "$_major" -lt "$MIN_DOCKER_MAJOR" ]; then
		say "warning: Docker $_major is older than the required $MIN_DOCKER_MAJOR; please upgrade"
	fi
}

# warn_docker_group prints the root-equivalence warning for the docker group.
warn_docker_group() {
	say "WARNING: membership of the '$DOCKER_GROUP' group is ROOT-EQUIVALENT on this"
	say "         host: anyone who can talk to the Docker socket can start a"
	say "         container that mounts / and thereby become root. By enabling"
	say "         agents you accept that the '$RUNNER_USER' user is effectively"
	say "         root on this machine. Only do this on a host you are willing to"
	say "         hand over to Routini agents; prefer a dedicated VM."
}

# When ROUTINI_INSTALL_SH_LIB is set, install.sh only defines the helpers above
# and changes nothing on the host. scripts/install_test.sh uses this.
if [ -n "${ROUTINI_INSTALL_SH_LIB:-}" ]; then
	return 0 2>/dev/null || exit 0
fi

while [ $# -gt 0 ]; do
	case "$1" in
	--url) need_value "$@"; URL="$2"; shift 2 ;;
	--url=*) URL="${1#*=}"; shift ;;
	--token) need_value "$@"; TOKEN="$2"; shift 2 ;;
	--token=*) TOKEN="${1#*=}"; shift ;;
	--name) need_value "$@"; NAME="$2"; shift 2 ;;
	--name=*) NAME="${1#*=}"; shift ;;
	--version) need_value "$@"; VERSION="$2"; shift 2 ;;
	--version=*) VERSION="${1#*=}"; shift ;;
	--enable-agents) ENABLE_AGENTS=1; shift ;;
	-h | --help) usage ;;
	*) say "unknown argument: $1"; usage ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (pipe to 'sudo sh -s -- ...')"
[ "$(uname -s)" = "Linux" ] || die "routini-runner supports Linux only"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

if [ ! -f "$CONFIG" ] && { [ -z "$URL" ] || [ -z "$TOKEN" ]; }; then
	say "this server is not enrolled yet: --url and --token are required"
	usage
fi

# 1. Architecture.
case "$(uname -m)" in
x86_64 | amd64) ARCH="amd64" ;;
aarch64 | arm64) ARCH="arm64" ;;
*) die "unsupported architecture: $(uname -m) (amd64 and arm64 are supported)" ;;
esac

# Downloads with curl, or wget as a fallback.
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
	fetch_stdout() { curl -fsSL --retry 3 "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
	fetch_stdout() { wget -q -O - "$1"; }
else
	die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	die "sha256sum or shasum is required"
fi

# 2. Download and verify the release.
if [ -z "$VERSION" ]; then
	VERSION="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "$VERSION" ] || die "could not determine the latest release; pass --version vX.Y.Z"
fi
case "$VERSION" in
v*) TAG="$VERSION" ;;
*) TAG="v$VERSION" ;;
esac
FILE_VERSION="${TAG#v}"
TARBALL="routini-runner_${FILE_VERSION}_linux_${ARCH}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$TAG"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $TARBALL ($TAG)"
fetch "$BASE_URL/$TARBALL" "$TMP/$TARBALL" || die "download failed: $BASE_URL/$TARBALL"
fetch "$BASE_URL/sha256sums.txt" "$TMP/sha256sums.txt" || die "download failed: $BASE_URL/sha256sums.txt"

EXPECTED="$(awk -v f="$TARBALL" '$2 == f || $2 == "*" f {print $1}' "$TMP/sha256sums.txt" | head -n 1)"
[ -n "$EXPECTED" ] || die "$TARBALL is not listed in sha256sums.txt"
ACTUAL="$(sha256 "$TMP/$TARBALL")"
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for $TARBALL (expected $EXPECTED, got $ACTUAL)"
say "checksum verified"

# 3. Install the binary.
tar -xzf "$TMP/$TARBALL" -C "$TMP" routini-runner || die "could not extract routini-runner from $TARBALL"
mkdir -p "$BIN_DIR"
install -m 0755 "$TMP/routini-runner" "$BIN.new"
mv -f "$BIN.new" "$BIN"
say "installed $("$BIN" version) to $BIN"

# 4. System user.
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
	LOGIN_SHELL="/bin/sh"
	[ -x /bin/bash ] && LOGIN_SHELL="/bin/bash"
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --create-home --home-dir "$RUNNER_HOME" \
			--shell "$LOGIN_SHELL" --comment "Routini runner" "$RUNNER_USER"
	elif command -v adduser >/dev/null 2>&1; then
		adduser --system --group --home "$RUNNER_HOME" --shell "$LOGIN_SHELL" "$RUNNER_USER"
	else
		die "useradd or adduser is required to create the $RUNNER_USER user"
	fi
	say "created system user $RUNNER_USER (home $RUNNER_HOME)"
fi

# 5. Enroll (once).
if [ -f "$CONFIG" ]; then
	say "$CONFIG exists: already enrolled, skipping enrollment"
else
	mkdir -p "$CONFIG_DIR"
	chown "$RUNNER_USER:$RUNNER_USER" "$CONFIG_DIR"
	chmod 0700 "$CONFIG_DIR"
	set -- enroll --url "$URL" --token "$TOKEN" --config "$CONFIG"
	[ -n "$NAME" ] && set -- "$@" --name "$NAME"
	say "enrolling with $URL"
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$RUNNER_USER" -- "$BIN" "$@" || die "enrollment failed"
	else
		CMD="$(shquote "$BIN")"
		for arg in "$@"; do CMD="$CMD $(shquote "$arg")"; done
		su -s /bin/sh -c "$CMD" "$RUNNER_USER" || die "enrollment failed"
	fi
fi

# 5b. Agents capability (opt-in).
if [ "$ENABLE_AGENTS" -eq 1 ]; then
	warn_docker_group
	warn_docker_version
	config_enable_agents "$CONFIG" "$RUNNER_USER" ||
		die "could not enable agents; set \"agents\": true under \"capabilities\" in $CONFIG yourself"
	say "set capabilities.agents in $CONFIG"
	add_to_group "$RUNNER_USER" "$DOCKER_GROUP" ||
		say "warning: could not add $RUNNER_USER to the $DOCKER_GROUP group. Install Docker, then run: usermod -aG $DOCKER_GROUP $RUNNER_USER && systemctl restart routini-runner"
fi

# 6. systemd unit.
cat >"$UNIT" <<'EOF'
[Unit]
Description=Routini runner (runs commands and terminals for Routini)
Documentation=https://github.com/nvasion/routini-runner
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=routini-runner
Group=routini-runner
ExecStart=/usr/local/bin/routini-runner run --config /etc/routini-runner/config.json
Restart=on-failure
RestartSec=5
# 78 (EX_CONFIG): bad credential, unsupported protocol or runner removed.
# Restarting cannot fix these, so do not loop.
RestartPreventExitStatus=78
# On stop, signal only the runner: it cancels running commands (SIGTERM,
# then SIGKILL after 5 s) and closes terminals itself before exiting.
KillMode=mixed
TimeoutStopSec=20

# Hardening is deliberately minimal: the runner exists to run arbitrary admin
# commands, which may use sudo. NoNewPrivileges is therefore NOT set (it
# would break sudo), and the file system is not made read-only.
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"

systemctl daemon-reload
if systemctl is-active --quiet routini-runner; then
	systemctl enable routini-runner >/dev/null 2>&1 || true
	systemctl restart routini-runner
	say "restarted routini-runner with the new binary"
else
	systemctl enable --now routini-runner
	say "started routini-runner"
fi
say "done. Logs: journalctl -u routini-runner -f"
say "to let Routini run privileged commands, add sudo rules for the '$RUNNER_USER' user yourself"
if [ "$ENABLE_AGENTS" -eq 1 ]; then
	say "agents are enabled on this host. To switch them off again, set"
	say "\"agents\": false under \"capabilities\" in $CONFIG, run"
	say "'gpasswd -d $RUNNER_USER $DOCKER_GROUP' and restart the service."
else
	say "agents are not enabled. Re-run with --enable-agents to allow them"
	say "(see \"Running agents on this server\" in the README)."
fi
