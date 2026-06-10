//! Shared on-disk session state for zlauder.
//!
//! `zlauder-proxy` and `zlauder-hooks` both need to agree on, per project, the
//! proxy's port, its admin key (the `x-zlauder-key` for the audit/control
//! endpoints), the token salt, and its pid. This crate is the single owner of
//! that file format and its location so the two binaries can't drift.
//!
//! ## Per-project isolation
//!
//! Each project gets its own proxy on a project-derived port ([`derive_port`]),
//! hence its own key, salt, store, and config. State files are keyed by port
//! (`proxy-<port>.json`), so two `claude` windows in the same project share one
//! file (and one proxy), while different projects never collide.
//!
//! ## Who writes it
//!
//! Two writers, by design:
//! - `session-start` writes a **reservation** ([`reserve_port`], `pid == 0`, empty
//!   key) on a project's first launch, so it durably owns its port *before* its
//!   proxy has bound — otherwise two colliding projects could each bake the same
//!   port into their `settings.json` and end up sharing one proxy.
//! - The **bound proxy** then overwrites with the live record (real control token,
//!   salt, pid) after it binds, so the file always matches the live proxy even if
//!   two sessions race to launch (the loser fails to bind and never writes).
//!
//! The hooks reuse the *salt* across a restart (keeps tokens — and the prompt-cache
//! prefix — stable) but only when the record is owned by the same project.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Lowest port used by the per-project derivation.
pub const PORT_BASE: u16 = 18000;
/// Number of ports in the derivation window (`PORT_BASE..PORT_BASE+PORT_SPAN`).
pub const PORT_SPAN: u16 = 2000;

/// Per-build identity baked in by `build.rs` (git short SHA, `-dirty` if the tree
/// had uncommitted changes, or `"unknown"` without git). Both binaries embed it;
/// the proxy reports it on `/healthz` and the SessionStart hook compares it against
/// its own to detect — and recycle — a long-lived proxy left over from an older
/// build (e.g. after a plugin update).
pub const BUILD_ID: &str = match option_env!("ZLAUDER_BUILD") {
    Some(s) => s,
    None => "unknown",
};

/// On-disk record describing one running (or last-known) per-project proxy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyState {
    pub port: u16,
    /// Hex of the proxy's **control token** — a random secret distinct from the
    /// AES session key. Required (via `x-zlauder-key`) to call the reveal/config
    /// control endpoints, so they are not a trivial oracle for a tool-driven
    /// `curl`. It is NOT the encryption key: reading this file grants control-plane
    /// access (disable/reload/reveal-via-proxy) but not offline decryption of the
    /// transcript. Empty for a reservation record (no proxy bound yet).
    pub admin_key: String,
    /// Hex of the token salt; reused across proxy restarts on this port so tokens
    /// (and the prompt-cache prefix) stay stable mid-session.
    #[serde(default)]
    pub salt: String,
    pub base_url: String,
    /// PID of the live proxy, or `0` for a pre-launch reservation (no proxy yet).
    pub pid: u32,
    /// Absolute project root this proxy serves (so a port collision between two
    /// different projects is detectable).
    #[serde(default)]
    pub project_root: String,
}

/// The user-scope config path: `$ZLAUDER_USER_CONFIG`, else
/// `$XDG_CONFIG_HOME/zlauder/config.toml`, else `$HOME/.config/zlauder/config.toml`.
/// Shared by the proxy (layer loading) and the hooks CLI (`--scope user` edits) so
/// they agree on the location.
pub fn user_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ZLAUDER_USER_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        // Windows fallback when HOME is unset (Claude Code launched from cmd/PowerShell
        // may not export HOME to Git Bash): %APPDATA% is the roaming config root, so the
        // path becomes %APPDATA%\zlauder\config.toml.
        .or_else(windows_appdata)
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("zlauder").join("config.toml")
}

/// Deterministically map a (canonical) project root to a port in the derivation
/// window. Same path → same port (so repeat sessions and sibling windows share a
/// proxy); different paths → almost-always different ports. Collisions are rare
/// and resolved at first-launch time by probing upward.
pub fn derive_port(project_root: &str) -> u16 {
    let h = blake3::hash(project_root.as_bytes());
    let b = h.as_bytes();
    let n = u16::from_le_bytes([b[0], b[1]]);
    PORT_BASE + (n % PORT_SPAN)
}

/// Root directory for zlauder state files (created `0700` on Unix).
///
/// `ZLAUDER_STATE_DIR` wins; else `$XDG_RUNTIME_DIR/zlauder`; else (Windows)
/// `%LOCALAPPDATA%\zlauder`; else a temp dir.
///
/// NOTE: `set_mode` is a no-op on Windows (see below), so the `0700` is not enforced
/// there — the state file holds the proxy's admin key + salt. We therefore prefer a
/// per-user dir (`%LOCALAPPDATA%`) over the shared, cleanup-prone temp dir on Windows;
/// hardening file ACLs further is out of scope.
pub fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("ZLAUDER_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("zlauder")))
        .or_else(windows_localappdata_zlauder)
        .unwrap_or_else(|| std::env::temp_dir().join("zlauder"));
    std::fs::create_dir_all(&base).with_context(|| format!("creating state dir {base:?}"))?;
    set_mode(&base, 0o700);
    Ok(base)
}

/// `%LOCALAPPDATA%\zlauder` on Windows (a per-user, non-volatile dir), else `None`.
#[cfg(windows)]
fn windows_localappdata_zlauder() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("zlauder"))
}
#[cfg(not(windows))]
fn windows_localappdata_zlauder() -> Option<PathBuf> {
    None
}

/// `%APPDATA%` (the roaming config root) on Windows, else `None`. Used as a config-path
/// fallback when neither `XDG_CONFIG_HOME` nor `HOME` is set.
#[cfg(windows)]
fn windows_appdata() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}
#[cfg(not(windows))]
fn windows_appdata() -> Option<PathBuf> {
    None
}

/// Path to the state file for `port` (`<state_dir>/proxy-<port>.json`).
pub fn state_path(port: u16) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("proxy-{port}.json")))
}

/// Read the state file for `port`.
pub fn read_state(port: u16) -> Result<ProxyState> {
    let path = state_path(port)?;
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Read the state file for `port`, returning `None` if it doesn't exist or is
/// unparseable (rather than erroring).
pub fn read_state_opt(port: u16) -> Option<ProxyState> {
    read_state(port).ok()
}

/// Is `pid` (probably) a live process? Unix (Linux AND macOS) uses POSIX `kill(pid, 0)`;
/// Windows asks the OS process table; any other platform conservatively assumes alive
/// (never steal a port we can't prove is dead).
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // kill(pid, 0) sends no signal but runs the kernel's existence + permission
        // checks: 0 => the process is alive; errno EPERM => it exists but isn't ours
        // (still alive); ESRCH => it's gone. Portable across Linux and macOS, unlike a
        // `/proc` probe — without this, macOS hit the conservative "always alive" arm,
        // so a crashed proxy's stale record was never reclaimable and pinned its port.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        let pid_s = pid.to_string();
        let Ok(out) = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
        else {
            return true;
        };
        if !out.status.success() {
            return true;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .any(|line| {
                line.split(',')
                    .nth(1)
                    .map(|field| field.trim_matches('"') == pid_s)
                    .unwrap_or(false)
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

/// The project that currently owns `port`, if any. A *reservation* (`pid == 0`)
/// stands until cleared. A *live-proxy* record only counts while its pid is alive —
/// a crashed proxy's stale record is reclaimable, so a dead proxy can't pin a port
/// forever (review finding C3).
fn port_owner(port: u16) -> Option<String> {
    let st = read_state_opt(port)?;
    if st.project_root.is_empty() {
        return None;
    }
    if st.pid != 0 && !pid_alive(st.pid) {
        return None; // stale live-proxy record → reclaimable
    }
    Some(st.project_root)
}

/// Resolve the port a project should use: its [`derive_port`] value, probed upward
/// past any port currently owned by a *different* project (live proxy or standing
/// reservation). Read-only — used by the observer commands (`statusline`, `config`,
/// `reveal`) when no port was baked into `settings.json`. The `session-start`
/// launcher uses [`reserve_port`] instead, which also claims the port atomically.
pub fn pick_port(project_root: &str) -> u16 {
    let start = derive_port(project_root);
    for off in 0..PORT_SPAN {
        let p = PORT_BASE + ((start - PORT_BASE + off) % PORT_SPAN);
        match port_owner(p) {
            Some(owner) if owner != project_root => continue,
            _ => return p,
        }
    }
    start
}

/// Atomically reserve and return the port for `project_root` (used by `session-start` /
/// auto-plumb on a project's first launch). Thin wrapper over [`reserve_port_created`] that
/// drops the "did this call create it" flag.
pub fn reserve_port(project_root: &str) -> Result<u16> {
    reserve_port_created(project_root).map(|(port, _created)| port)
}

/// Like [`reserve_port`], but also returns whether THIS call CREATED the reservation
/// (`true`) versus returning a port already owned by this project (`false` — a standing
/// reservation, a live proxy, or one a concurrent same-project launch just created). The
/// caller can then clean up ONLY its own freshly-created reservation on a later failure,
/// never one a sibling launch is relying on.
///
/// Probes like [`pick_port`], but for a free slot it writes a reservation record via
/// `O_CREAT|O_EXCL`, so two concurrent first-launches can't claim the same port (one loses
/// the create race and keeps probing). A port already owned by this project (reservation or
/// live proxy) is returned as-is — re-launching is idempotent. The reservation makes the
/// port visible to *other* projects' `pick_port`/`reserve_port` before this project's proxy
/// has bound, which is what prevents two colliding projects from baking the same port
/// (review finding F1/HIGH).
pub fn reserve_port_created(project_root: &str) -> Result<(u16, bool)> {
    let start = derive_port(project_root);
    for off in 0..PORT_SPAN {
        let p = PORT_BASE + ((start - PORT_BASE + off) % PORT_SPAN);
        match port_owner(p) {
            Some(owner) if owner != project_root => continue, // someone else's
            Some(_) => return Ok((p, false)),                 // already ours — we did NOT create it
            None => {
                if try_reserve(p, project_root)? {
                    return Ok((p, true)); // WE created this reservation
                }
                // Lost the create race. Re-check ownership: if a concurrent launch
                // for THIS project just claimed it, it's ours — return it (so two
                // same-project launches converge on ONE port, not p and p+1). If a
                // different project won, keep probing.
                match port_owner(p) {
                    Some(owner) if owner == project_root => return Ok((p, false)),
                    _ => continue,
                }
            }
        }
    }
    Ok((start, false))
}

/// Atomically reserve `port` iff no state file exists yet. Returns `false` if the
/// file already exists (lost the race / occupied).
///
/// The reservation is published by `hard_link`ing a fully-written temp file over the
/// target path: `hard_link` is atomic and EXCLUSIVE (fails `AlreadyExists` if the
/// path exists), and because the temp is complete before the link, a concurrent
/// reader never observes an empty/torn reservation.
fn try_reserve(port: u16, project_root: &str) -> Result<bool> {
    let path = state_path(port)?;
    let st = ProxyState {
        port,
        admin_key: String::new(),
        salt: String::new(),
        base_url: format!("http://127.0.0.1:{port}"),
        pid: 0,
        project_root: project_root.to_string(),
    };
    let tmp = temp_sibling(&path);
    std::fs::write(&tmp, serde_json::to_vec_pretty(&st)?)
        .with_context(|| format!("writing reservation temp {tmp:?}"))?;
    set_mode(&tmp, 0o600);
    let result = match std::fs::hard_link(&tmp, &path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reserving {path:?}"))),
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Write `state` to its port's state file (`0600`), atomically (temp file in the
/// same dir, then `rename` over the target). The atomicity matters: the proxy
/// overwrites its own reservation on bind, and a plain truncate-rewrite would let a
/// concurrent reader briefly see the file as empty/absent → a port looking "free"
/// mid-write → a racing `reserve_port` skipping it (review finding).
pub fn write_state(state: &ProxyState) -> Result<()> {
    let path = state_path(state.port)?;
    let tmp = temp_sibling(&path);
    std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("writing {tmp:?}"))?;
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {tmp:?} -> {path:?}"))?;
    Ok(())
}

/// A process-unique temp path next to `path` (same directory → same filesystem, so
/// `rename`/`hard_link` onto `path` are atomic).
fn temp_sibling(path: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    dir.join(format!(".{name}.tmp.{}", std::process::id()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

// No-op on non-Unix (Windows): there is no portable `chmod`, so state files are not
// permission-restricted there. The proxy state file holds the admin key + salt, so on
// Windows we instead place the state dir under a per-user location (`%LOCALAPPDATA%`,
// see `state_dir`) rather than a world-readable temp dir; tightening NTFS ACLs is out of
// scope.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

// ---------------------------------------------------------------------------
// Plumbed-projects registry (persistent — per-project auto-enable state)
// ---------------------------------------------------------------------------

/// Per-project auto-enable state, persisted in the user-config dir (NOT the volatile runtime
/// state dir), so it survives reboots. SessionStart consults it to avoid re-plumbing a
/// project the user opted out of, and `/zlauder:disable --all` uses it to sweep every
/// plumbed project's routing before an uninstall.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlumbState {
    /// zlauder auto-plumbed (or the user enabled) routing for this project.
    Plumbed,
    /// The user ran `/zlauder:disable` here — never auto-plumb it again.
    Optout,
}

/// One project's registry record. Stored ONE FILE PER PROJECT (named by a hash of the root)
/// rather than a single shared map: concurrent updates to DIFFERENT projects then never
/// contend — each writes its own file via the atomic temp+rename — so there is no
/// lost-update race (e.g. one session's auto-plumb clobbering another's opt-out), with no
/// interprocess lock. A same-project race is idempotent (both write the same value). The
/// `root` is stored so the sweep can recover the path from the hashed filename and so a
/// (astronomically unlikely) hash collision is detectable.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryEntry {
    root: String,
    state: PlumbState,
}

/// Directory holding the plumbed-projects registry (one JSON file per project):
/// `<user-config-dir>/plumbed/`.
pub fn registry_dir() -> PathBuf {
    user_config_path().with_file_name("plumbed")
}

fn registry_entry_path(project_root: &str) -> PathBuf {
    registry_dir().join(format!(
        "{}.json",
        blake3::hash(project_root.as_bytes()).to_hex()
    ))
}

/// The recorded auto-enable state for `project_root` (a canonical path), or `None` if
/// zlauder has never plumbed or seen it.
pub fn registry_get(project_root: &str) -> Option<PlumbState> {
    let entry: RegistryEntry = std::fs::read(registry_entry_path(project_root))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())?;
    // Trust the entry only if its stored root matches (guards a hash collision).
    (entry.root == project_root).then_some(entry.state)
}

/// Record `state` for `project_root`, replacing any prior entry (atomic temp+rename). Enable
/// => `Plumbed` (clears a prior opt-out); disable => `Optout`.
pub fn registry_set(project_root: &str, state: PlumbState) -> Result<()> {
    let dir = registry_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {dir:?}"))?;
    let path = registry_entry_path(project_root);
    let entry = RegistryEntry {
        root: project_root.to_string(),
        state,
    };
    let tmp = temp_sibling(&path);
    std::fs::write(&tmp, serde_json::to_vec_pretty(&entry)?)
        .with_context(|| format!("writing {tmp:?}"))?;
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {tmp:?} -> {path:?}"))?;
    Ok(())
}

/// Remove `project_root` from the registry entirely (the disable sweep calls this once a
/// project's routing has been stripped). A missing entry is not an error.
pub fn registry_remove(project_root: &str) -> Result<()> {
    match std::fs::remove_file(registry_entry_path(project_root)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing registry entry"),
    }
}

/// Every project root currently in the `Plumbed` state (used by `/zlauder:disable --all`).
pub fn registry_plumbed_roots() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(registry_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        // Only the final per-project files (`<hash>.json`); skip an in-flight or crash-left
        // temp sibling (`.<hash>.json.tmp.<pid>`, whose extension is the pid, not "json"),
        // which could otherwise be parsed as a duplicate/stale entry by the disable sweep.
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|p| {
            let entry: RegistryEntry = serde_json::from_slice(&std::fs::read(&p).ok()?).ok()?;
            // Same collision/tamper guard `registry_get` applies on the read path: trust the
            // entry only if its filename is `blake3(root).json`, so the sweep never acts on a
            // mismatched or wrong-named (duplicated/hand-copied) record — it disables exactly the
            // projects that were legitimately recorded here, not whatever a stray file claims.
            let expected = format!("{}.json", blake3::hash(entry.root.as_bytes()).to_hex());
            (p.file_name().and_then(|n| n.to_str()) == Some(expected.as_str())).then_some(entry)
        })
        .filter(|e| e.state == PlumbState::Plumbed)
        .map(|e| e.root)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // `ZLAUDER_STATE_DIR` is process-global; serialize tests that mutate it so
    // parallel test threads don't clobber each other's state dir.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn derive_port_is_deterministic_and_in_range() {
        let a = derive_port("/home/me/projects/alpha");
        let b = derive_port("/home/me/projects/alpha");
        let c = derive_port("/home/me/projects/beta");
        assert_eq!(a, b, "same path => same port");
        assert!((PORT_BASE..PORT_BASE + PORT_SPAN).contains(&a));
        assert!((PORT_BASE..PORT_BASE + PORT_SPAN).contains(&c));
        // Not a hard guarantee, but these two distinct paths must not collide or
        // the isolation premise is silently broken for the test fixtures.
        assert_ne!(a, c, "distinct paths collided in-range");
    }

    #[test]
    fn state_round_trips() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-test-{}", std::process::id()));
        // SAFETY: single-threaded test; sets a process-local override only.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };
        let st = ProxyState {
            port: 18042,
            admin_key: "ab".repeat(32),
            salt: "cd".repeat(16),
            base_url: "https://api.anthropic.com".into(),
            pid: 4242,
            project_root: "/home/me/projects/alpha".into(),
        };
        write_state(&st).unwrap();
        let back = read_state(18042).unwrap();
        assert_eq!(back.admin_key, st.admin_key);
        assert_eq!(back.salt, st.salt);
        assert_eq!(back.project_root, st.project_root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Two colliding projects must NOT be handed the same port: the first reserves
    // it durably (before any proxy runs), the second probes past it.
    #[test]
    fn reserve_port_prevents_collision_pre_launch() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-resv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };

        let a = "/proj/a";
        let b = "/proj/b";
        let pa = reserve_port(a).unwrap();
        // Reservation is on disk with pid 0 and a's root, even though no proxy ran.
        let rec = read_state(pa).unwrap();
        assert_eq!(rec.pid, 0);
        assert_eq!(rec.project_root, a);
        assert!(rec.admin_key.is_empty(), "reservation carries no key");

        // init for b is idempotent for itself and never collides with a.
        let pb = reserve_port(b).unwrap();
        assert_ne!(
            pa, pb,
            "second project must not reuse the first's reserved port"
        );
        assert_eq!(reserve_port(a).unwrap(), pa, "re-reserve is idempotent");

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_STATE_DIR") };
    }

    // The core F1 fix: a *foreign reservation* (pid 0, no proxy running) on a
    // project's derived port must push it to a different port. The pre-fix bug was
    // that init wrote no reservation, so this record didn't exist pre-launch.
    #[test]
    fn foreign_reservation_blocks_derived_port_pre_launch() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };

        let x = "/proj/x";
        let port = derive_port(x);
        write_state(&ProxyState {
            port,
            admin_key: String::new(),
            salt: String::new(),
            base_url: format!("http://127.0.0.1:{port}"),
            pid: 0, // a standing reservation — no proxy running
            project_root: "/proj/foreign".into(),
        })
        .unwrap();

        let got = reserve_port(x).unwrap();
        assert_ne!(
            got, port,
            "a foreign pre-launch reservation must block the derived port"
        );
        assert_eq!(read_state(got).unwrap().project_root, x);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_STATE_DIR") };
    }

    // A stale live-proxy record (dead pid) must not pin a port forever.
    #[test]
    fn stale_dead_proxy_record_is_reclaimable() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };

        let port = derive_port("/proj/x");
        // A different project's record with a definitely-dead pid.
        write_state(&ProxyState {
            port,
            admin_key: "aa".repeat(32),
            salt: "bb".repeat(16),
            base_url: format!("http://127.0.0.1:{port}"),
            pid: 0x7FFF_FFFE, // not a live process
            project_root: "/proj/other".into(),
        })
        .unwrap();
        // /proj/x derives this very port; since the other record is dead, x reclaims it.
        assert_eq!(
            pick_port("/proj/x"),
            port,
            "dead proxy record should be reclaimable"
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_STATE_DIR") };
    }

    // write_state replaces an existing record and leaves no temp file behind (the
    // atomic temp+rename must clean up after itself).
    #[test]
    fn write_state_replaces_atomically_no_temp_leak() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("ZLAUDER_STATE_DIR", &dir) };

        let mk = |k: &str| ProxyState {
            port: 18099,
            admin_key: k.into(),
            salt: "00".repeat(16),
            base_url: "x".into(),
            pid: 1,
            project_root: "/p".into(),
        };
        write_state(&mk("first")).unwrap();
        write_state(&mk("second")).unwrap(); // overwrite an existing file
        assert_eq!(read_state(18099).unwrap().admin_key, "second");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_STATE_DIR") };
    }

    // The plumbed-projects registry round-trips state, filters Plumbed for the sweep, and
    // honors an opt-out so a disabled project is never auto-re-plumbed.
    #[test]
    fn registry_round_trips_and_filters_plumbed() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("zlauder-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test; points the registry at a temp config dir.
        unsafe { std::env::set_var("ZLAUDER_USER_CONFIG", dir.join("config.toml")) };

        assert_eq!(registry_get("/proj/a"), None);
        registry_set("/proj/a", PlumbState::Plumbed).unwrap();
        registry_set("/proj/b", PlumbState::Optout).unwrap();
        assert_eq!(registry_get("/proj/a"), Some(PlumbState::Plumbed));
        assert_eq!(registry_get("/proj/b"), Some(PlumbState::Optout));

        // Only Plumbed roots are swept; an opted-out project is excluded.
        assert_eq!(registry_plumbed_roots(), vec!["/proj/a".to_string()]);

        // Re-enabling clears a prior opt-out.
        registry_set("/proj/b", PlumbState::Plumbed).unwrap();
        let mut roots = registry_plumbed_roots();
        roots.sort();
        assert_eq!(roots, vec!["/proj/a".to_string(), "/proj/b".to_string()]);

        registry_remove("/proj/a").unwrap();
        assert_eq!(registry_get("/proj/a"), None);

        // A wrong-named (`<hash>` != blake3(root)) registry file is NOT swept: registry_get's
        // filename guard also applies to registry_plumbed_roots, so a mismatched/hand-copied
        // record can't inject a foreign root into the disable sweep.
        let stray = registry_dir().join("deadbeef.json");
        std::fs::write(&stray, br#"{"root":"/proj/stray","state":"plumbed"}"#).unwrap();
        assert!(
            !registry_plumbed_roots().contains(&"/proj/stray".to_string()),
            "a record whose filename != blake3(root) must be ignored by the sweep"
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("ZLAUDER_USER_CONFIG") };
    }
}
