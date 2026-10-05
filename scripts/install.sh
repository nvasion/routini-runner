#!/bin/sh
# Install routini-runner as a systemd service.
#
#   curl -fsSL https://raw.githubusercontent.com/nvasion/routini-runner/main/scripts/install.sh \
#     | sudo sh -s -- --url https://routini.example.com --token rre_... [--name web-01] [--version v0.1.0]
#
# Re-running is safe: the binary is replaced (upgraded) and, when
# /etc/routini-runner/config.json already exists, enrollment is skipped.
set -eu

REPO="nvasion/routini-runner"
BIN_DIR="/usr/local/bin"
BIN="$BIN_DIR/routini-runner"
RUNNER_USER="routini-runner"
RUNNER_HOME="/var/lib/routini-runner"
CONFIG_DIR="/etc/routini-runner"
CONFIG="$CONFIG_DIR/config.json"
UNIT="/etc/systemd/system/routini-runner.service"

URL=""
TOKEN=""
NAME=""
VERSION=""

say() { printf 'routini-runner install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
# shquote prints $1 as a single-quoted shell word.
shquote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

usage() {
	cat >&2 <<EOF
Usage: install.sh --url URL --token rre_... [--name NAME] [--version vX.Y.Z]

  --url      Routini base URL (https://..., or http:// on a private network)
  --token    single-use enrollment token from the Routini console
  --name     runner name (default: the token's name, else the hostname)
  --version  release tag to install (default: the latest release)

--url and --token are only needed for the first install; later runs upgrade
the binary and keep the existing enrollment.
EOF
	exit 2
}

need_value() {
	[ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
}

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
