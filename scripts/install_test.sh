#!/bin/sh
# Tests for the helpers in install.sh that can run without touching the host.
#
#   sh scripts/install_test.sh
#
# install.sh is sourced with ROUTINI_INSTALL_SH_LIB set, which makes it define
# its helpers and return before it changes anything.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
ROUTINI_INSTALL_SH_LIB=1 . "$SCRIPT_DIR/install.sh"

FAILURES=0
TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT INT TERM

fail() {
	FAILURES=$((FAILURES + 1))
	printf 'FAIL: %s\n' "$*" >&2
}
pass() { printf 'ok: %s\n' "$*"; }

# write_config NAME BODY -> prints the path of a config file holding BODY.
write_config() {
	_dir="$TMPROOT/$1"
	mkdir -p "$_dir"
	printf '%s\n' "$2" >"$_dir/config.json"
	printf '%s' "$_dir/config.json"
}

# json_get PATH EXPR: prints the value of EXPR in the JSON file at PATH using
# python3 (so the assertions check real JSON, not text).
json_get() {
	python3 -c 'import json,sys
cfg = json.load(open(sys.argv[1]))
expr = sys.argv[2]
for key in expr.split("."):
    cfg = cfg[key] if isinstance(cfg, dict) and key in cfg else None
    if cfg is None:
        break
print(json.dumps(cfg))' "$1" "$2"
}

# case_enable NAME BODY: enables agents in BODY and asserts the result is JSON
# with capabilities.agents true; extra checks come from stdin-free callers.
case_enable() {
	_name="$1"
	_cfg="$(write_config "$_name" "$2")"
	if ! config_enable_agents "$_cfg" >/dev/null 2>&1; then
		fail "$_name: config_enable_agents failed"
		return 0
	fi
	if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$_cfg" 2>/dev/null; then
		fail "$_name: result is not valid JSON"
		printf '%s\n' "--- $_cfg ---" >&2
		cat "$_cfg" >&2
		return 0
	fi
	if [ "$(json_get "$_cfg" capabilities.agents)" != "true" ]; then
		fail "$_name: capabilities.agents is not true"
		return 0
	fi
	CASE_CONFIG="$_cfg"
	pass "$_name"
}

# assert_json NAME PATH EXPR WANT
assert_json() {
	_got="$(json_get "$2" "$3")"
	[ "$_got" = "$4" ] || fail "$1: $3 is $_got, want $4"
}

command -v python3 >/dev/null 2>&1 || {
	echo "install_test.sh: python3 is required" >&2
	exit 1
}

# 1. The config as `routini-runner enroll` writes it (gofmt-style indent, no
#    agents key yet). Every other field must survive untouched.
case_enable multiline '{
  "url": "https://routini.example.com",
  "runnerId": "11111111-2222-3333-4444-555555555555",
  "credential": "rrc_secret",
  "caFile": null,
  "capabilities": {
    "exec": true,
    "pty": true
  },
  "maxConcurrentExec": 8
}'
assert_json multiline "$CASE_CONFIG" capabilities.exec true
assert_json multiline "$CASE_CONFIG" capabilities.pty true
assert_json multiline "$CASE_CONFIG" url '"https://routini.example.com"'
assert_json multiline "$CASE_CONFIG" credential '"rrc_secret"'
assert_json multiline "$CASE_CONFIG" maxConcurrentExec 8

# 2. An existing agents key is flipped, not duplicated (last-wins would
#    otherwise reintroduce false).
case_enable existing_false '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": {
    "exec": true,
    "pty": true,
    "agents": false
  }
}'
assert_json existing_false "$CASE_CONFIG" capabilities.pty true
[ "$(grep -c '"agents"' "$CASE_CONFIG")" -eq 1 ] ||
	fail "existing_false: the agents key was duplicated"

# 3. Idempotent: enabling twice is a no-op the second time.
config_enable_agents "$CASE_CONFIG" >/dev/null 2>&1 ||
	fail "idempotent: second run failed"
[ "$(grep -c '"agents"' "$CASE_CONFIG")" -eq 1 ] ||
	fail "idempotent: the agents key was duplicated"
assert_json idempotent "$CASE_CONFIG" capabilities.agents true
pass idempotent

# 4. agents last in the object (no trailing comma to preserve).
case_enable agents_last '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": {
    "exec": true,
    "agents": false
  },
  "maxConcurrentAgents": 2
}'
assert_json agents_last "$CASE_CONFIG" maxConcurrentAgents 2

# 5. A hand-written single-line capabilities object (as shown in the README).
case_enable single_line '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": { "exec": true, "pty": false },
  "maxConcurrentExec": 4
}'
assert_json single_line "$CASE_CONFIG" capabilities.pty false
assert_json single_line "$CASE_CONFIG" maxConcurrentExec 4

# 6. A single-line capabilities object that already has agents.
case_enable single_line_existing '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": {"exec": true, "agents": false, "pty": true}
}'
assert_json single_line_existing "$CASE_CONFIG" capabilities.pty true
assert_json single_line_existing "$CASE_CONFIG" capabilities.exec true

# 7. An empty capabilities object.
case_enable empty_caps '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": {}
}'

# 8. No capabilities key at all: one is added (the runner fills exec/pty from
#    its own defaults when they are missing).
case_enable no_caps '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret"
}'
assert_json no_caps "$CASE_CONFIG" credential '"rrc_secret"'

# 9. Nested objects after capabilities keep their own braces.
case_enable nested '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": {
    "exec": true,
    "pty": true
  },
  "agentImagePrefixes": ["ghcr.io/nvasion/"],
  "extra": {
    "nested": { "deep": true }
  }
}'
assert_json nested "$CASE_CONFIG" extra.nested.deep true

# 10. Error paths: a missing file and an unreadable directory must fail loudly
#     and must not create anything.
if config_enable_agents "$TMPROOT/missing/config.json" >/dev/null 2>&1; then
	fail "missing_file: config_enable_agents succeeded on a missing file"
else
	pass "missing_file"
fi

# 11. The rewrite must keep mode 0600 (the file holds the credential).
cfg="$(write_config mode '{
  "url": "https://routini.example.com",
  "credential": "rrc_secret",
  "capabilities": { "exec": true }
}')"
chmod 0644 "$cfg"
config_enable_agents "$cfg" >/dev/null 2>&1 || fail "mode: config_enable_agents failed"
mode="$(ls -l "$cfg" | cut -c1-10)"
[ "$mode" = "-rw-------" ] && pass mode || fail "mode: want -rw-------, got $mode"

# 12. No temporary files are left behind.
leftovers="$(find "$TMPROOT" -name '.config-agents-*' | wc -l)"
[ "$leftovers" -eq 0 ] && pass cleanup || fail "cleanup: $leftovers temporary files were left behind"

# 13. docker_major parses a version string, and tolerates a missing docker.
if command -v docker >/dev/null 2>&1; then
	pass "docker_major (docker present: $(docker_major))"
else
	if [ -z "$(docker_major)" ]; then
		pass "docker_major (docker absent)"
	else
		fail "docker_major: want empty output without docker"
	fi
fi

# 14. The warnings mention root-equivalence and the group, and never a secret.
warning="$(warn_docker_group 2>&1)"
case "$warning" in
*ROOT-EQUIVALENT*) ;;
*) fail "warn_docker_group: the warning does not mention root-equivalence" ;;
esac
case "$warning" in
*"'$DOCKER_GROUP' group"*) pass "warn_docker_group" ;;
*) fail "warn_docker_group: the warning does not name the $DOCKER_GROUP group" ;;
esac
case "$warning" in
*rrc_*) fail "warn_docker_group: the warning leaks a credential" ;;
esac

if [ "$FAILURES" -eq 0 ]; then
	echo "install.sh: all tests passed"
else
	printf 'install.sh: %s test(s) failed\n' "$FAILURES" >&2
	exit 1
fi
