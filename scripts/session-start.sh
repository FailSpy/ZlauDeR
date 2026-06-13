#!/usr/bin/env bash
# zlauder SessionStart hook (plugin entry point).
#
# Resolves the zlauder-proxy/zlauder-hooks binaries, then hands off to the real
# control plane `zlauder-hooks session-start`, which ensures this project's proxy
# is running and prints the SessionStart hook JSON Claude Code consumes.
#
# stdout MUST stay valid hook JSON: it is passed through from zlauder-hooks
# UNCHANGED. All diagnostics go to stderr.
#
# The one thing this plugin cannot do is set ANTHROPIC_BASE_URL directly (Claude
# Code only honors "agent"/"subagentStatusLine" from a plugin settings.json). So
# `zlauder-hooks session-start` AUTO-ENABLES a never-seen project by writing the
# route into .claude/settings.local.json (gitignored) and launching the proxy; Claude
# Code applies a route written mid-session only unreliably, so masking activates
# reliably after a ONE-TIME RESTART (every session after reads it at startup). The hook
# gates every side effect on whether THIS session is actually routed through the proxy
# (it never announces masking for a session that isn't).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Pass --port ONLY when $ZLAUDER_PORT is set (the per-project EPHEMERAL port baked into
# settings.local.json, which Claude Code exports into this session's env). The hook uses it
# as the session's ROUTED port for the route gate — NOT a bind directive: the proxy binds an
# OS-assigned ephemeral port (or a static [proxy] port) and ignores an inherited ZLAUDER_PORT.
# When unset (a never-routed first session), the hook resolves the proxy from the project-keyed
# rendezvous.
PORT_ARGS=()
if [ -n "${ZLAUDER_PORT:-}" ]; then
  PORT_ARGS=(--port "$ZLAUDER_PORT")
fi
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"

warn() { printf '%s\n' "$*" >&2; }

# Resolve the config: project zlauder.toml if present, else the bundled default.
config_path() {
  local proj="${CLAUDE_PROJECT_DIR:-}"
  if [ -n "$proj" ] && [ -f "$proj/zlauder.toml" ]; then
    printf '%s\n' "$proj/zlauder.toml"
  elif [ -n "$PLUGIN_ROOT" ] && [ -f "$PLUGIN_ROOT/zlauder.toml" ]; then
    printf '%s\n' "$PLUGIN_ROOT/zlauder.toml"
  fi
}

# Resolve (and, on first run, build) the binaries; this also prepends their dir
# to PATH so the hooks call below and session-start's default --proxy-bin resolve.
if ! zlauder_resolve_bins; then
  warn "ZlauDeR: proxy not started this session."
  exit 1
fi

CFG="$(config_path)"

# Hand off to the real control plane and emit its hook JSON byte-for-byte. zlauder-hooks
# owns the routing decision now: it checks whether THIS session's ANTHROPIC_BASE_URL is
# actually pointed at the proxy and, only then, launches/recycles it and announces that
# masking is active — otherwise it auto-enables a never-seen project, nudges (on stderr)
# a configured-but-not-yet-routed one to restart once to activate masking, or stays a
# silent no-op. (The UserPromptSubmit intake gate blocks that unrouted session's prompts
# until the restart, so nothing sends unmasked.) Single source of truth, no shell guard.
set +e
if [ -n "$CFG" ]; then
  "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" session-start --config "$CFG"
else
  "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" session-start
fi
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  warn "ZlauDeR: zlauder-hooks session-start exited $rc."
  exit "$rc"
fi

exit 0
