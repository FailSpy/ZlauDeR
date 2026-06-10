---
description: Stop routing this project through the ZlauDeR proxy (reverts .claude/settings.local.json). Takes effect on your next message, no restart in the common case. `--all` sweeps every project — run it before uninstalling.
argument-hint: "[--all]"
allowed-tools: Bash(bash:*)
---

Reverting the ZlauDeR routing for this project. The script below removes the
`env.ANTHROPIC_BASE_URL` and `env.ZLAUDER_PORT` keys that enabling added to this project's
`.claude/settings.local.json` (and drops the `env` object if it becomes empty; older installs
that wrote the committed `.claude/settings.json` are cleaned up there too), and undoes the
status-line takeover: if enabling wrapped a status line you already had, your original is
**restored verbatim** from the sidecar it saved (`.claude/zlauder-statusline.json`); if you had
none, the ZlauDeR `🛡` line is simply removed. A `statusLine` you set by hand *after* enabling
is left untouched. It leaves all other settings — and the seeded `zlauder.toml` — in place, and
leaves the running proxy alone: it only stops Claude Code from routing through it. It also
records this project as **opted out**, so the plugin won't auto-re-enable it; run
`/zlauder:enable` to turn routing back on.

**`/zlauder:disable --all`** sweeps EVERY project ZlauDeR has plumbed (not just this one) and
clears their routing. Run it **before uninstalling the plugin**, so no project is left pointing
at a proxy that's gone — a dead `ANTHROPIC_BASE_URL` makes Claude Code hang for minutes and then
fail. (Note: a project reopened *after* the plugin is fully gone can't self-heal, since the
binaries are gone too — hence the pre-uninstall sweep.)

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/disable.sh" "$ARGUMENTS"`

Read the script output above, then:

- If it reverted the routing, confirm to the user that this project's
  `.claude/settings.local.json` no longer points at the ZlauDeR proxy. It takes effect on their
  **next message** — Claude Code re-reads the route live, so traffic then goes straight to
  Anthropic with no masking (no full restart needed in the common case; if it is still routing
  after a message or two, a restart forces it).
- If it reported that nothing was wired (no ZlauDeR `env` block found), say so plainly — there
  was nothing to revert.
- For `--all`: relay how many projects were swept and whether all succeeded. Only tell the user
  it is **safe to uninstall** if the sweep reported no failures.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim
and do not claim the change succeeded.
