---
description: Explicitly route this project's Claude Code through the ZlauDeR masking proxy (writes .claude/settings.local.json, seeds practical zlauder.toml). Usually automatic; a one-time Claude Code restart reliably activates it.
allowed-tools: Bash(bash:*)
---

Script output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/enable.sh"`

This is the per-project **routing** setup, and in most cases you don't need to run it:
the plugin AUTO-ENABLES routing the first time it sees a project (it writes the route on
the first session; a one-time restart then reliably activates masking). Run `/zlauder:enable` to do
that explicitly — e.g. to turn routing back on after `/zlauder:disable`, or to refresh a
stale status-line path. It writes this project's **`.claude/settings.local.json`**
(which the plugin keeps out of git via a `.claude/.gitignore`, so the machine-specific
`http://127.0.0.1:<port>` is never committed) with `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT`
and a `🛡` status line — wrapping any
line you already had as `🛡 … │ {your line}` (the original is saved and restored on
`/zlauder:disable`) — and seeds a practical starter `zlauder.toml` if absent. The
exhaustive reference is `zlauder.toml.example`. Hide the `🛡` segment with
`env.ZLAUDER_STATUSLINE=off`.

Report the result above, then make the activation model clear: Claude Code snapshots
`ANTHROPIC_BASE_URL` at startup, so the route just written applies to THIS session only
unreliably — **a one-time restart of Claude Code is the sure way to activate masking** (the
status line shows `⟳ ZlauDeR: restart to mask` until it's live). Every session after this one
reads the route at startup and routes reliably. Until masking is live, outbound text still
reaches the model unmasked (real PII, not tokens) — this is only about what the provider
sees; the user always sees their own plaintext.

This command controls **routing** (whether traffic goes through the proxy at all, set once
and then effectively permanent). The everyday control is **masking** — on/off, profile,
categories — which is live and managed with `/zlauder:privacy`; flipping masking off leaves
routing in place (transparent pass-through) and can never strand the session. Confirm both
with `/zlauder:privacy` (or `/zlauder:privacy status`). Before UNINSTALLING the plugin, the
user should run `/zlauder:disable --all` so no project is left pointing at a proxy that's gone.
