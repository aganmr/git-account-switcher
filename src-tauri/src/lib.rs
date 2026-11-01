use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/* ------------------------------------------------------------------ */
/* Models                                                              */
/* ------------------------------------------------------------------ */

/// Supported git hosting providers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    GitHub,
    GitLab,
    Gitea,
    Gitee,
}

impl Provider {
    pub fn default_host(&self) -> &'static str {
        match self {
            Provider::GitHub => "github.com",
            Provider::GitLab => "gitlab.com",
            Provider::Gitea => "gitea.com",
            Provider::Gitee => "gitee.com",
        }
    }

    /// Effective host for an account (empty host = provider default).
    pub fn resolve_host(&self, host: &str) -> String {
        let h = host.trim();
        if h.is_empty() {
            self.default_host().to_string()
        } else {
            h.to_string()
        }
    }

    /// Providers that support self-hosted instances get a host field in the UI.
    pub fn supports_custom_host(&self) -> bool {
        !matches!(self, Provider::Gitee)
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Provider::GitHub => "github",
            Provider::GitLab => "gitlab",
            Provider::Gitea => "gitea",
            Provider::Gitee => "gitee",
        };
        f.write_str(s)
    }
}

fn default_provider() -> Provider {
    Provider::GitHub
}

/// An account. The token itself never lives here — it is kept in a
/// per-account Windows Credential Manager entry (see `cred_target`).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    /// Defaults to GitHub for accounts saved before providers existed.
    #[serde(default = "default_provider")]
    pub provider: Provider,
    /// Empty = provider default host.
    #[serde(default)]
    pub host: String,
    pub label: String,
    pub name: String,
    pub email: String,
    /// Provider username (login)
    pub login: String,
    /// True when a token for this account exists in Credential Manager.
    #[serde(default)]
    pub token_stored: bool,
    pub ssh_key_path: String,
}

/// Legacy on-disk shape (pre token-migration): tokens were stored in the
/// JSON file in plaintext.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAccount {
    id: String,
    #[serde(default = "default_provider")]
    provider: Provider,
    #[serde(default)]
    host: String,
    label: String,
    name: String,
    email: String,
    login: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    ssh_key_path: String,
    /// Parsed for legacy compatibility; the live value is re-derived from GCM.
    #[serde(default)]
    #[allow(dead_code)]
    token_stored: Option<bool>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    pub system: String,
    pub label: String,
    pub value: String,
    /// id of the account this system currently points to, when matched
    pub account_id: Option<String>,
    pub known: bool,
    /// token row only: RFC3339 expiry when the provider reports one
    /// (GitHub fine-grained PATs, GitLab PATs; classic tokens have none)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// token row only: the active slot token was rejected by the API
    #[serde(default)]
    pub invalid: bool,
    /// cli row only: the account glab is signed in as. The cli row's
    /// `account_id` carries gh's attribution; each CLI is judged by its
    /// own account (GitHub → gh, GitLab → glab).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glab_account: Option<String>,
    /// cli row only: the tool is installed (regardless of sign-in state)
    #[serde(default)]
    pub gh_installed: bool,
    /// cli row only: the tool is installed (regardless of sign-in state)
    #[serde(default)]
    pub glab_installed: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SwitchResult {
    pub system: String,
    pub ok: bool,
    pub skipped: bool,
    pub message: String,
    /// cli row only: gh rejected the stored token (missing scope, expired,
    /// revoked) — a browser re-login can fix it.
    pub needs_browser: bool,
}

/// Non-secret app settings (settings.json, plain JSON).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub close_to_tray: bool,
    pub launch_at_startup: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            launch_at_startup: false,
        }
    }
}

/* ------------------------------------------------------------------ */
/* File payload encryption (AES-256-GCM)                               */
/*                                                                     */
/* accounts.json = `GAS1` + 12-byte random nonce + AES-256-GCM         */
/* ciphertext (tag included). The key is embedded in the binary. The   */
/* file holds no secrets — the token lives in Credential Manager — so  */
/* this only keeps the metadata from being casually readable on disk.  */
/* (DPAPI was the original choice, but some machines block it for      */
/* native processes; this scheme has no OS dependency and exports are  */
/* importable on any machine.)                                         */
/* ------------------------------------------------------------------ */

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

const FILE_MAGIC: &[u8] = b"GAS1";
const NONCE_LEN: usize = 12;
const AES_KEY: &[u8; 32] = &[
    0xad, 0x67, 0x73, 0x5f, 0x47, 0x7d, 0xc9, 0x5d, 0x8c, 0x2c, 0x7f, 0xf0, 0x58, 0x37, 0x5d, 0xac,
    0x28, 0x3b, 0xd3, 0x5e, 0x58, 0x2f, 0x9e, 0x64, 0xb8, 0x9d, 0xa8, 0xc3, 0xcb, 0x15, 0xc4, 0xe8,
];

fn encrypt_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(AES_KEY));
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN + 16 {
        return None; // too short: nonce (12) + at least the GCM tag (16)
    }
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(AES_KEY));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).ok()
}

/* ------------------------------------------------------------------ */
/* Per-account tokens in the Windows Credential Manager                */
/* ------------------------------------------------------------------ */

/// GCM target for a specific account: `git-account-switcher:{provider}:{host}:{login}`
fn cred_target(provider: &Provider, host: &str, login: &str) -> String {
    format!(
        "git-account-switcher:{provider}:{host}:{}",
        login.to_lowercase()
    )
}

const MAX_CRED_BLOB: usize = 2560; // Windows Credential Manager blob limit

/// Display identity stored with credential entries: `Name <email>`.
fn cred_identity(name: &str, email: &str) -> String {
    if email.is_empty() {
        name.to_string()
    } else {
        format!("{name} <{email}>")
    }
}

fn gcm_write_token(
    target: &str,
    login: &str,
    identity: &str,
    token: &str,
) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    if token.len() > MAX_CRED_BLOB {
        return Err(format!(
            "token is too long to store (max {MAX_CRED_BLOB} characters)"
        ));
    }

    let target_w: Vec<u16> = OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let login_w: Vec<u16> = OsStr::new(login)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let identity_w: Vec<u16> = OsStr::new(identity)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let blob: Vec<u8> = token.as_bytes().to_vec();

    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target_w.as_ptr() as *mut u16;
    cred.UserName = login_w.as_ptr() as *mut u16;
    cred.Comment = identity_w.as_ptr() as *mut u16;
    cred.CredentialBlobSize = blob.len() as u32;
    cred.CredentialBlob = blob.as_ptr() as *mut u8;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    // Writing to an existing target updates it (update semantics).
    let ok = unsafe { CredWriteW(&mut cred, 0) };
    if ok == 0 {
        Err("failed to store token in Windows Credential Manager".into())
    } else {
        Ok(())
    }
}

fn gcm_read_token(target: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{CredFree, CredReadW, CREDENTIALW};

    let target_w: Vec<u16> = OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    let ok = unsafe { CredReadW(target_w.as_ptr(), 1, 0, &mut cred) };
    if ok == 0 {
        return None;
    }
    let token = unsafe {
        let c = &*cred;
        if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
            None
        } else {
            let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
            let s = String::from_utf8_lossy(bytes);
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        }
    };
    unsafe { CredFree(cred as *const _) };
    token
}

fn gcm_delete_token(target: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::CredDeleteW;

    let target_w: Vec<u16> = OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let _ = unsafe { CredDeleteW(target_w.as_ptr(), 1, 0) };
}

/* ------------------------------------------------------------------ */
/* Account storage (app config dir)                                    */
/*                                                                     */
/* accounts.json = `GAS1` + AES-256-GCM-encrypted pretty JSON.         */
/* Legacy plaintext JSON is migrated once on load: tokens move to      */
/* per-account Credential Manager entries and the file is re-encrypted */
/* ------------------------------------------------------------------ */

fn accounts_file(app: &AppHandle) -> PathBuf {
    app.path()
        .app_config_dir()
        .expect("failed to resolve app config dir")
        .join("accounts.json")
}

fn settings_file(app: &AppHandle) -> PathBuf {
    app.path()
        .app_config_dir()
        .expect("failed to resolve app config dir")
        .join("settings.json")
}

fn read_settings(app: &AppHandle) -> Settings {
    fs::read_to_string(settings_file(app))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_file(app);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let s = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(&path, s).map_err(|e| e.to_string())
}

fn load_accounts(app: &AppHandle) -> Vec<Account> {
    let Ok(bytes) = fs::read(accounts_file(app)) else {
        return Vec::new();
    };

    // New format: magic + AES-256-GCM payload (nonce + ciphertext).
    if bytes.starts_with(FILE_MAGIC) {
        let plain = decrypt_payload(&bytes[FILE_MAGIC.len()..])
            .and_then(|p| String::from_utf8(p).ok());
        return plain
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
    }

    // Legacy format: plaintext JSON with tokens in the file.
    let Ok(s) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    let Ok(raws) = serde_json::from_str::<Vec<RawAccount>>(&s) else {
        return Vec::new();
    };

    let mut migrated = Vec::new();
    for r in raws {
        let host = r.provider.resolve_host(&r.host);
        let target = cred_target(&r.provider, &host, &r.login);
        let mut stored = gcm_read_token(&target).is_some();
        if let Some(t) = &r.token {
            let t = t.trim();
            if !t.is_empty()
                && !stored
                && gcm_write_token(&target, &r.login, &cred_identity(&r.name, &r.email), t)
                    .is_ok()
            {
                stored = true;
            }
        }
        migrated.push(Account {
            id: r.id,
            provider: r.provider,
            host: r.host,
            label: r.label,
            name: r.name,
            email: r.email,
            login: r.login,
            token_stored: stored,
            ssh_key_path: r.ssh_key_path,
        });
    }

    // Re-save in the encrypted format (best effort; idempotent).
    let _ = save_accounts(app, &migrated);
    migrated
}

fn save_accounts(app: &AppHandle, accounts: &[Account]) -> Result<(), String> {
    let path = accounts_file(app);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(accounts).map_err(|e| e.to_string())?;
    let blob = encrypt_payload(json.as_bytes())?;
    let mut out = Vec::with_capacity(FILE_MAGIC.len() + blob.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&blob);
    fs::write(&path, out).map_err(|e| e.to_string())
}

/* ------------------------------------------------------------------ */
/* Process helpers                                                     */
/* ------------------------------------------------------------------ */

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Child-process flag: never allocate a console window for the spawned
/// console programs (git, gh, …) — without it the app flashes a console
/// on every call.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn new_cmd(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

fn std_new_cmd(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

async fn run_cmd(program: &str, args: &[&str]) -> (bool, String) {
    match new_cmd(program).args(args).output().await {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ),
        Err(e) => (false, format!("{program} not found: {e}")),
    }
}

async fn run_cmd_stdin(program: &str, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = match new_cmd(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("{program} not found: {e}")),
    };
    if let Some(mut s) = child.stdin.take() {
        if s.write_all(stdin.as_bytes()).await.is_err() {
            return (false, "failed to write stdin".into());
        }
    }
    match child.wait_with_output().await {
        Ok(out) => {
            // CLI tools write their errors to stderr — surface both.
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .trim()
            .to_string();
            (out.status.success(), combined)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Expand a leading `~` to the user home dir.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("USERPROFILE")
            .ok()
            .or_else(|| std::env::var("HOME").ok());
        if let Some(home) = home {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

fn mask_token(t: &str) -> String {
    let keep = t.len().min(8);
    format!("{}…", &t[..keep])
}

/// Synchronous read of the global git identity (for the tray menu, which
/// has no async context).
fn git_global_identity_sync() -> Option<(String, String)> {
    let name = std_new_cmd("git")
        .args(["config", "--global", "user.name"])
        .output()
        .ok()?;
    let email = std_new_cmd("git")
        .args(["config", "--global", "user.email"])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&name.stdout).trim().to_string();
    let email = String::from_utf8_lossy(&email.stdout).trim().to_string();
    if name.is_empty() && email.is_empty() {
        None
    } else {
        Some((name, email))
    }
}

/* ------------------------------------------------------------------ */
/* Git-credential (GCM `git:` slot) reading                            */
/*                                                                     */
/* Read-only. We deliberately never call `git credential fill` — that  */
/* can trigger the GCM/GitLab connect popups. We only read what git    */
/* has already stored in `git:https://{host}`.                         */
/* ------------------------------------------------------------------ */

/// Read the stored git credential for `git:https://{host}` directly from
/// the Windows Credential Manager via `CredReadW`.
fn cred_manager_token(host: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{CredFree, CredReadW, CREDENTIALW};

    let target: Vec<u16> = OsStr::new(&format!("git:https://{host}"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    let ok = unsafe { CredReadW(target.as_ptr(), 1, 0, &mut cred) };
    if ok == 0 {
        return None; // no such credential (ERROR_NOT_FOUND) or other failure
    }
    let token = unsafe {
        let c = &*cred;
        if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
            None
        } else {
            let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
            let s = String::from_utf8_lossy(bytes);
            extract_token(&s, host)
        }
    };
    unsafe { CredFree(cred as *const _) };
    token
}

/// Write the active account's username, identity, and token into the GCM
/// `git:https://{host}` slot directly. `git credential approve` silently
/// no-ops for known hosts (github.com) in the built-in GCM, so the app
/// writes the credential itself. The existing entry's attributes (GCM
/// markers) and persist scope are preserved; the blob is the bare token,
/// matching what GCM stores.
fn update_git_slot(
    host: &str,
    login: &str,
    identity: &str,
    token: &str,
) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CredWriteW, CREDENTIALW,
    };

    let target: Vec<u16> = OsStr::new(&format!("git:https://{host}"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let login_w: Vec<u16> = OsStr::new(login)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let identity_w: Vec<u16> = OsStr::new(identity)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let blob = token.as_bytes();

    let mut existing: *mut CREDENTIALW = std::ptr::null_mut();
    let have = unsafe { CredReadW(target.as_ptr(), 1, 0, &mut existing) } != 0;

    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = 1; // CRED_GENERIC
    cred.TargetName = target.as_ptr() as *mut _;
    cred.UserName = login_w.as_ptr() as *mut _;
    cred.Comment = identity_w.as_ptr() as *mut _;
    cred.CredentialBlob = blob.as_ptr() as *mut _;
    cred.CredentialBlobSize = blob.len() as u32;
    if have {
        let e = unsafe { &*existing };
        cred.Persist = e.Persist;
        cred.AttributeCount = e.AttributeCount;
        cred.Attributes = e.Attributes;
    } else {
        cred.Persist = 2; // LOCAL_MACHINE
    }
    let ok = unsafe { CredWriteW(&cred, 0) };
    if have {
        unsafe { CredFree(existing as *const _) };
    }
    if ok == 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(0);
        Err(format!("failed to write the git credential slot ({code})"))
    } else {
        Ok(())
    }
}

/// Extract the token from a git credential blob. Two shapes occur in the
/// wild:
///   - GCM core: `<token>https://{host}` (no separator, UTF-8)
///   - some writers: a bare token, sometimes UTF-16LE (NUL-interleaved)
fn extract_token(blob: &str, host: &str) -> Option<String> {
    // Normalize UTF-16LE blobs (drop the NUL bytes).
    let b: String = blob.chars().filter(|c| *c != '\0').collect();
    let b = b.trim();
    if b.is_empty() {
        return None;
    }
    let suffix = format!("https://{host}");
    if let Some(t) = b.strip_suffix(&suffix) {
        let t = t.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    // No host suffix: accept a bare token (no whitespace, sane length).
    if !b.contains(' ') && b.len() >= 10 && b.len() <= 2560 {
        return Some(b.to_string());
    }
    None
}

/// Outcome of validating a token against the provider's `/user` API.
enum TokenCheck {
    /// API accepted the token; `expires` is RFC3339 when the provider
    /// reports one (GitHub fine-grained PATs, GitLab PATs).
    Valid {
        login: String,
        name: String,
        expires: Option<String>,
    },
    /// API rejected the token (401/403/404) — revoked or expired.
    Invalid,
    /// Network failure — the token's state is unknown.
    Unreachable,
}

fn check_token(provider: &Provider, host: &str, token: &str) -> TokenCheck {
    let url = match provider {
        // GitHub's public API lives on api.github.com; the /api/v3 path
        // only exists on GitHub Enterprise Server (custom host).
        Provider::GitHub => {
            if host == "github.com" {
                "https://api.github.com/user".to_string()
            } else {
                format!("https://{host}/api/v3/user")
            }
        }
        Provider::GitLab => format!("https://{host}/api/v4/user"),
        Provider::Gitea => format!("https://{host}/api/v1/user"),
        Provider::Gitee => "https://gitee.com/api/v5/user".to_string(),
    };
    let req = ureq::get(&url).set("User-Agent", "git-account-switcher");
    let req = match provider {
        Provider::GitLab => req.set("PRIVATE-TOKEN", token),
        Provider::Gitee => req.set("token", token),
        _ => req.set("Authorization", &format!("token {token}")),
    };
    let v: serde_json::Value = match req.call() {
        Ok(r) => match r.into_json() {
            Ok(v) => v,
            Err(_) => return TokenCheck::Invalid,
        },
        Err(ureq::Error::Status(..)) => return TokenCheck::Invalid,
        Err(ureq::Error::Transport(_)) => return TokenCheck::Unreachable,
    };
    // GitHub/Gitea/Gitee use `login`, GitLab uses `username`.
    // GitHub/Gitee/Gitee use `name`, Gitea also `full_name`.
    let Some(login) = v
        .get("login")
        .or_else(|| v.get("username"))
        .and_then(|l| l.as_str())
        .filter(|s| !s.is_empty())
    else {
        return TokenCheck::Invalid;
    };
    let name = v
        .get("name")
        .or_else(|| v.get("full_name"))
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| login.to_string());
    let expires = v
        .get("token_expires_at") // GitHub fine-grained PATs
        .or_else(|| v.get("expires_at")) // GitLab PATs
        .and_then(|e| e.as_str())
        .map(|s| s.to_string());
    TokenCheck::Valid {
        login: login.to_string(),
        name,
        expires,
    }
}

/// Validate a token against the provider's `/user` API; returns
/// (login, name, expiry-when-reported) on success.
fn api_user(
    provider: &Provider,
    host: &str,
    token: &str,
) -> Option<(String, String, Option<String>)> {
    match check_token(provider, host, token) {
        TokenCheck::Valid {
            login,
            name,
            expires,
        } => Some((login, name, expires)),
        _ => None,
    }
}

/// Best-effort pickup of a token that already exists on this machine:
/// if the account has no stored token, candidates are gathered from the
/// `git:https://{host}` slot and from a signed-in CLI session (gh/glab),
/// and the first one the provider API confirms belongs to this account's
/// login is adopted. Never stores the wrong account's token; never
/// touches the git slot. Returns true if a token was stored.
async fn auto_sync_token(account: &Account) -> bool {
    let host = account.provider.resolve_host(&account.host);
    let target = cred_target(&account.provider, &host, &account.login);
    if gcm_read_token(&target).is_some() {
        return false; // already has a stored token
    }
    let mut candidates: Vec<String> = Vec::new();
    if let Some(t) = cred_manager_token(&host) {
        candidates.push(t);
    }
    if let Some(t) = cli_session_token(&account.provider, &host).await {
        if !candidates.contains(&t) {
            candidates.push(t);
        }
    }
    for cand in &candidates {
        let Some((login, _, _)) = api_user(&account.provider, &host, cand) else {
            continue; // offline or dead token: try the next candidate
        };
        if login.eq_ignore_ascii_case(&account.login) {
            return gcm_write_token(
                &target,
                &account.login,
                &cred_identity(&account.name, &account.email),
                cand,
            )
            .is_ok();
        }
    }
    false
}

/// Read the token from a signed-in CLI session, if any (gh → GitHub,
/// glab → GitLab; Gitea/Gitee have no CLI).
async fn cli_session_token(provider: &Provider, host: &str) -> Option<String> {
    let (ok, out) = match provider {
        Provider::GitHub => run_cmd(&cli_exe("gh"), &["auth", "token"]).await,
        Provider::GitLab => {
            run_cmd(&cli_exe("glab"), &["auth", "token", "--hostname", host]).await
        }
        _ => return None,
    };
    let t = out.trim().to_string();
    (ok && !t.is_empty() && !t.contains('\n')).then_some(t)
}

/* ------------------------------------------------------------------ */
/* Tray                                                                */
/* ------------------------------------------------------------------ */

/// Label for the tray menu's disabled "active account" line.
fn active_account_label(app: &AppHandle) -> String {
    let Some((name, email)) = git_global_identity_sync() else {
        return "No active account".to_string();
    };
    let accounts = load_accounts(app);
    match accounts
        .iter()
        .find(|a| (!a.email.is_empty() && a.email == email) || a.name == name)
    {
        Some(a) => format!("Active: {} - {}", a.login, a.provider),
        None => format!("Active: {name}"),
    }
}

fn rebuild_tray_menu(app: &AppHandle) {
    let Some(tray) = app.tray_by_id("tray") else {
        return;
    };
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "active", active_account_label(app), false, None::<&str>)
                .expect("active menu item"),
            &PredefinedMenuItem::separator(app).expect("separator"),
            &MenuItem::with_id(app, "quit", "Quit", true, None::<&str>).expect("quit item"),
        ],
    )
    .expect("tray menu");
    let _ = tray.set_menu(Some(menu));
}

/* ------------------------------------------------------------------ */
/* Tauri commands                                                      */
/* ------------------------------------------------------------------ */

#[tauri::command]
async fn list_accounts(app: AppHandle) -> Result<Vec<Account>, String> {
    let mut accounts = load_accounts(&app);
    // Accounts added without a token: try to pick the token up from the git
    // slot (validated against the provider API). One-time per account.
    let mut changed = false;
    for a in accounts.iter_mut() {
        if !a.token_stored && auto_sync_token(a).await {
            a.token_stored = true;
            changed = true;
        }
    }
    if changed {
        save_accounts(&app, &accounts)?;
    }
    Ok(accounts)
}

/// Save an account. `token`:
///   - `Some(non-empty)` → (re)write the per-account Credential Manager entry
///   - `Some("")` / `None` → keep the existing entry untouched; if there is
///     none, try `auto_sync_token` (git-slot pickup, API-validated)
#[tauri::command]
async fn save_account(
    app: AppHandle,
    account: Account,
    token: Option<String>,
) -> Result<Account, String> {
    let mut acc = account;
    let host = acc.provider.resolve_host(&acc.host);
    let target = cred_target(&acc.provider, &host, &acc.login);

    if let Some(t) = token.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        gcm_write_token(&target, &acc.login, &cred_identity(&acc.name, &acc.email), t)?;
    }
    if gcm_read_token(&target).is_none() {
        // No token given: try to pick one up (git slot / CLI session)
        auto_sync_token(&acc).await;
    }
    acc.token_stored = gcm_read_token(&target).is_some();

    let mut accounts = load_accounts(&app);
    match accounts.iter().position(|a| a.id == acc.id) {
        Some(i) => accounts[i] = acc.clone(),
        None => accounts.push(acc.clone()),
    }
    save_accounts(&app, &accounts)?;
    Ok(acc)
}

#[tauri::command]
async fn delete_account(app: AppHandle, id: String) -> Result<(), String> {
    let mut accounts = load_accounts(&app);
    if let Some(a) = accounts.iter().find(|a| a.id == id) {
        let host = a.provider.resolve_host(&a.host);
        gcm_delete_token(&cred_target(&a.provider, &host, &a.login));
    }
    accounts.retain(|a| a.id != id);
    save_accounts(&app, &accounts)
}

/// Import the git credentials currently saved in the Windows Credential
/// Manager (one per known provider host) as accounts. Idempotent: an entry
/// is skipped when there is no stored token for that host, when the login
/// is already known for that provider+host, or when the token is rejected
/// by the provider API. Only reads `git:` slots — never prompts.
#[tauri::command]
async fn import_saved_credentials(app: AppHandle) -> Result<Vec<Account>, String> {
    let mut imported: Vec<Account> = Vec::new();

    for provider in [Provider::GitHub, Provider::GitLab, Provider::Gitea, Provider::Gitee] {
        let host = provider.default_host();
        let Some(token) = cred_manager_token(host) else {
            continue;
        };

        let accounts = load_accounts(&app);
        // Only import credentials that are actually valid.
        let Some((login, name, _)) = api_user(&provider, host, &token) else {
            continue;
        };
        if accounts.iter().any(|a| {
            a.login == login
                && a.provider == provider
                && a.provider.resolve_host(&a.host) == host
        }) {
            continue;
        }

        // Best-effort email: the current global git identity is most likely
        // this account's (the API does not expose the primary email).
        let (_, email) = run_cmd("git", &["config", "--global", "user.email"]).await;

        let target = cred_target(&provider, host, &login);
        let _ = gcm_write_token(&target, &login, &cred_identity(&name, &email), &token);

        let account = Account {
            id: uuid::Uuid::new_v4().to_string(),
            provider: provider.clone(),
            host: String::new(),
            label: login.clone(),
            name,
            email: email.trim().to_string(),
            login,
            token_stored: true,
            ssh_key_path: String::new(),
        };

        let mut accounts = load_accounts(&app);
        accounts.push(account.clone());
        save_accounts(&app, &accounts)?;
        imported.push(account);
    }

    Ok(imported)
}

#[tauri::command]
async fn detect_systems(app: AppHandle) -> Result<Vec<SystemStatus>, String> {
    let accounts = load_accounts(&app);
    let mut statuses = Vec::new();

    // --- 1. Git identity ---
    let (ok, email) = run_cmd("git", &["config", "--global", "user.email"]).await;
    let git_known = ok && !email.is_empty();
    let git_account = if git_known {
        accounts
            .iter()
            .find(|a| a.email == email.trim())
            .map(|a| a.id.clone())
    } else {
        None
    };
    statuses.push(SystemStatus {
        system: "git".into(),
        label: "Git identity".into(),
        value: if git_known { email } else { "not set".into() },
        account_id: git_account,
        known: git_known,
        expires_at: None,
        invalid: false,
        glab_account: None,
        gh_installed: false,
        glab_installed: false,
    });

    // --- 2. Stored git tokens (Credential Manager `git:` slots) ---
    let mut stored: Vec<(Provider, String, String)> = Vec::new(); // (provider, host, token)
    for provider in [Provider::GitHub, Provider::GitLab, Provider::Gitea, Provider::Gitee] {
        let host = provider.default_host();
        if let Some(t) = cred_manager_token(host) {
            stored.push((provider.clone(), host.to_string(), t));
        }
    }
    let (token_value, token_account, token_known) = match stored.len() {
        0 => ("not found".into(), None, false),
        _ => {
            // Match accounts whose per-account stored token equals one of
            // the git slot tokens.
            let account = accounts.iter().find_map(|a| {
                let host = a.provider.resolve_host(&a.host);
                let target = cred_target(&a.provider, &host, &a.login);
                let t = gcm_read_token(&target)?;
                if stored.iter().any(|(_, _, slot_t)| *slot_t == t) {
                    Some(a.id.clone())
                } else {
                    None
                }
            });
            let value = stored
                .iter()
                .map(|(_, h, t)| format!("{h}: {}", mask_token(t)))
                .collect::<Vec<_>>()
                .join(",  ");
            (value, account, true)
        }
    };
    // Token health: is the active slot token still accepted by the API,
    // and (when the provider reports it) when does it expire?
    let mut token_expires: Option<String> = None;
    let mut token_invalid = false;
    for (p, h, t) in &stored {
        match check_token(p, h, t) {
            TokenCheck::Valid { expires, .. } => token_expires = expires,
            TokenCheck::Invalid => token_invalid = true,
            TokenCheck::Unreachable => {} // offline: state unknown, stay quiet
        }
    }
    statuses.push(SystemStatus {
        system: "token".into(),
        label: "Git token (stored)".into(),
        value: token_value,
        account_id: token_account,
        known: token_known,
        expires_at: token_expires,
        invalid: token_invalid,
        glab_account: None,
        gh_installed: false,
        glab_installed: false,
    });

    // --- 3. CLIs (gh for GitHub, glab for GitLab) ---
    let (gh_ok, gh_login) = run_cmd(&cli_exe("gh"), &["api", "user", "-q", ".login"]).await;
    let (glab_ok, glab_login) =
        run_cmd(&cli_exe("glab"), &["api", "user", "-q", ".username"]).await;
    let gh_login = gh_login.trim().to_string();
    let glab_login = glab_login.trim().to_string();
    let gh_known = gh_ok && !gh_login.is_empty();
    let glab_known = glab_ok && !glab_login.is_empty();
    let (gh_i, _) = run_cmd(&cli_exe("gh"), &["--version"]).await;
    let (glab_i, _) = run_cmd(&cli_exe("glab"), &["--version"]).await;
    let gh_account = accounts
        .iter()
        .find(|a| a.provider == Provider::GitHub && a.login == gh_login)
        .map(|a| a.id.clone());
    let glab_account = accounts
        .iter()
        .find(|a| a.provider == Provider::GitLab && a.login == glab_login)
        .map(|a| a.id.clone());
    let cli_value = match (gh_known, glab_known) {
        (true, true) => format!("gh: {gh_login}   ·   glab: {glab_login}"),
        (true, false) => format!("gh: {gh_login}   ·   glab: not signed in"),
        (false, true) => format!("glab: {glab_login}   ·   gh: not signed in"),
        (false, false) => "not signed in".to_string(),
    };
    statuses.push(SystemStatus {
        system: "cli".into(),
        label: "CLI (gh / glab)".into(),
        value: cli_value,
        account_id: gh_account,
        known: gh_known || glab_known,
        expires_at: None,
        invalid: false,
        glab_account: glab_account,
        gh_installed: gh_i,
        glab_installed: glab_i,
    });

    // --- 4. SSH agent ---
    let (ok, listed) = run_cmd("ssh-add", &["-L"]).await;
    let mut ssh_account: Option<String> = None;
    if ok {
        for a in &accounts {
            if a.ssh_key_path.is_empty() {
                continue;
            }
            let path = expand_tilde(&a.ssh_key_path);
            let (k_ok, fp_out) = run_cmd("ssh-keygen", &["-lf", &path]).await;
            if !k_ok {
                continue;
            }
            // "256 SHA256:AbCd… comment (ED25519)"
            if let Some(fp) = fp_out.split_whitespace().find(|w| w.starts_with("SHA256:")) {
                if listed.contains(fp) {
                    ssh_account = Some(a.id.clone());
                    break;
                }
            }
        }
    }
    statuses.push(SystemStatus {
        system: "ssh".into(),
        label: "SSH key".into(),
        value: if ok {
            "agent loaded".into()
        } else {
            "agent not running".into()
        },
        account_id: ssh_account,
        known: ok,
        expires_at: None,
        invalid: false,
        glab_account: None,
        gh_installed: false,
        glab_installed: false,
    });

    Ok(statuses)
}

fn skip(system: &str, message: &str) -> SwitchResult {
    SwitchResult {
        system: system.into(),
        ok: true,
        skipped: true,
        message: message.into(),
        needs_browser: false,
    }
}

/// Resolve a usable token for the account: stored one first, otherwise try
/// to adopt one from this machine (the git slot or a signed-in gh/glab
/// session). Candidates are API-verified to belong to this account's login
/// before being stored — the wrong account's token is never adopted.
async fn resolve_token(account: &Account, target: &str) -> Option<String> {
    let mut token = gcm_read_token(target);
    if token.is_none() && auto_sync_token(account).await {
        token = gcm_read_token(target);
    }
    token
}

/// gh output signatures meaning the *token itself* is unusable (missing
/// scope, expired, revoked) — a fresh browser login replaces it. Transient
/// errors (network, rate limits) deliberately don't match.
fn gh_token_rejected(out: &str) -> bool {
    let l = out.to_lowercase();
    l.contains("error validating token")
        || l.contains("missing required scope")
        || l.contains("bad credentials")
        || l.contains("http 401")
        || l.contains("has been revoked")
        || l.contains("token expired")
}

/// The actual machine-wide switch, given a verified token for the account.
async fn perform_switch(
    app: &AppHandle,
    account: &Account,
    token: &str,
    host: &str,
) -> Vec<SwitchResult> {
    let token_ref: Option<&str> = Some(token);
    let mut results = Vec::new();

    // --- Git identity ---
    let (ok1, _) = run_cmd("git", &["config", "--global", "user.name", &account.name]).await;
    let (ok2, out2) =
        run_cmd("git", &["config", "--global", "user.email", &account.email]).await;
    results.push(SwitchResult {
        system: "git".into(),
        ok: ok1 && ok2,
        skipped: false,
        message: if ok1 && ok2 {
            format!("{} / {}", account.name, account.email)
        } else {
            out2
        },
        needs_browser: false,
    });

    // --- Git token (the GCM `git:https://{host}` slot, written directly) ---
    match token_ref {
        Some(t) => match update_git_slot(
            host,
            &account.login,
            &cred_identity(&account.name, &account.email),
            t,
        ) {
            Ok(()) => results.push(SwitchResult {
                system: "token".into(),
                ok: true,
                skipped: false,
                message: format!("credential updated ({host})"),
                needs_browser: false,
            }),
            Err(e) => results.push(SwitchResult {
                system: "token".into(),
                ok: false,
                skipped: false,
                message: e,
                needs_browser: false,
            }),
        },
        None => results.push(skip("token", "no token stored")),
    }

    // --- CLI: gh for GitHub, glab for GitLab, none for the rest ---
    let (cli_ok, cli_skipped, cli_msg, cli_needs_browser) =
        match (&account.provider, token_ref) {
            (Provider::GitHub, Some(t)) => {
                let mut args: Vec<&str> = vec!["auth", "login", "--with-token"];
                if host != "github.com" {
                    args.push("--hostname");
                    args.push(&host);
                }
                let (ok, out) = run_cmd_stdin(&cli_exe("gh"), &args, &format!("{t}\n")).await;
                // gh rejected the token itself (missing scope, expired,
                // revoked) — a browser re-login can fix it.
                let rejected = !ok && gh_token_rejected(&out);
                (
                    ok,
                    false,
                    if ok {
                        format!("signed in as {}", account.login)
                    } else {
                        out
                    },
                    rejected,
                )
            }
            (Provider::GitLab, Some(t)) => {
                let (ok, out) = run_cmd_stdin(
                    &cli_exe("glab"),
                    &["auth", "login", "--hostname", host],
                    &format!("{t}\n"),
                )
                .await;
                (
                    ok,
                    false,
                    if ok {
                        format!("signed in as {}", account.login)
                    } else {
                        format!("glab: {out}")
                    },
                    false,
                )
            }
            (_, None) => (true, true, "no token stored".to_string(), false),
            _ => (true, true, "no CLI for this provider".to_string(), false),
        };
    results.push(SwitchResult {
        system: "cli".into(),
        ok: cli_ok,
        skipped: cli_skipped,
        message: cli_msg,
        needs_browser: cli_needs_browser,
    });

    // --- SSH key: isolate the agent so no other account's key lingers ---
    let (agent_up, _) = run_cmd("ssh-add", &["-L"]).await;
    let mut clear_note = String::new();
    if agent_up {
        let (d_ok, d_out) = run_cmd("ssh-add", &["-D"]).await;
        if !d_ok {
            clear_note = format!(" (warning: agent not cleared: {d_out})");
        }
    }
    if account.ssh_key_path.is_empty() {
        results.push(skip(
            "ssh",
            if agent_up { "no key path (agent cleared)" } else { "no key path" },
        ));
    } else {
        let path = expand_tilde(&account.ssh_key_path);
        let (ok, out) = run_cmd("ssh-add", &[&path]).await;
        // "already registered" is a benign success for our purposes.
        let ok = ok || out.contains("already registered");
        results.push(SwitchResult {
            system: "ssh".into(),
            ok,
            skipped: false,
            message: if ok {
                format!("{path}{clear_note}")
            } else {
                format!("{out}{clear_note}")
            },
            needs_browser: false,
        });
    }

    // Refresh the tray "active account" line.
    rebuild_tray_menu(app);

    results
}

#[tauri::command]
async fn switch_account(app: AppHandle, id: String) -> Result<Vec<SwitchResult>, String> {
    let account = load_accounts(&app)
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| "account not found".to_string())?;
    let host = account.provider.resolve_host(&account.host);
    let target = cred_target(&account.provider, &host, &account.login);
    // All-or-nothing: an account without a usable token cannot become the
    // sole usable account, so fail before touching anything on this machine.
    let Some(token) = resolve_token(&account, &target).await else {
        return Err(format!(
            "cannot switch to {}: no git token available. Add one via Edit, or sign in with gh/glab as this account and try again.",
            account.label
        ));
    };
    Ok(perform_switch(&app, &account, &token, &host).await)
}

/* gh browser login (tokenless GitHub accounts) */

/// PID of the in-flight `gh auth login --web` process, so the UI can
/// cancel it (taskkill). The child itself is waited on a blocking thread.
static GH_LOGIN_PID: Mutex<Option<u32>> = Mutex::new(None);
static GH_LOGIN_CANCELLED: AtomicBool = AtomicBool::new(false);

/// CLI executable: known install locations first (the process PATH can be
/// stale right after a fresh install), then the bare program name from PATH.
fn cli_exe(prog: &str) -> String {
    for p in known_cli_paths(prog) {
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }
    prog.to_string()
}

/// Switch to a tokenless GitHub account by running `gh auth login --web`:
/// the browser opens, the user finishes the login, and the switch proceeds
/// automatically. The token is API-verified to belong to this account's
/// login before anything on the machine is touched.
///
/// `force` skips the stored-token shortcut — used to re-authenticate after
/// gh rejected the stored token (missing scope, expired, revoked). The new
/// token replaces the stored one when the login succeeds.
#[tauri::command]
async fn switch_account_browser(
    app: AppHandle,
    id: String,
    force: bool,
) -> Result<Vec<SwitchResult>, String> {
    let account = load_accounts(&app)
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| "account not found".to_string())?;
    if account.provider != Provider::GitHub {
        return Err("browser login is only supported for GitHub accounts (gh)".into());
    }
    let host = account.provider.resolve_host(&account.host);
    let target = cred_target(&account.provider, &host, &account.login);

    // Prefer an existing token — no browser needed in that case. `force`
    // skips this: the stored token is known-bad, so go straight to the
    // browser login.
    if !force {
        if let Some(token) = resolve_token(&account, &target).await {
            return Ok(perform_switch(&app, &account, &token, &host).await);
        }
    }

    let gh = cli_exe("gh");
    let (ok, _) = run_cmd(&gh, &["--version"]).await;
    if !ok {
        return Err(format!(
            "gh is not installed, so {} cannot be switched to. Install gh in Settings → CLI tools, or add a token via Edit.",
            account.label
        ));
    }

    // Browser flow: gh opens the default browser and blocks until the user
    // finishes (or cancels) the login there.
    let mut args: Vec<String> = vec![
        "auth".into(),
        "login".into(),
        "--web".into(),
        "--git-protocol".into(),
        "https".into(),
    ];
    if host != "github.com" {
        args.push("--hostname".into());
        args.push(host.clone());
    }
    GH_LOGIN_CANCELLED.store(false, Ordering::SeqCst);
    let mut cmd = std_new_cmd(&gh);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to start gh: {e}"))?;
    *GH_LOGIN_PID.lock().unwrap() = Some(child.id());

    // gh only opens the browser itself when it has a console; headless it
    // prints the one-time code (to stderr, e.g. "One-time code (ABCD-EFGH)
    // copied to clipboard") and polls. So we read that code, open the
    // device page in the default browser ourselves, and hand the code to
    // the UI.
    let device_url = if host == "github.com" {
        "https://github.com/login/device".to_string()
    } else {
        format!("https://{host}/login/device")
    };
    let emit_app = app.clone();
    if let Some(stderr) = child.stderr.take() {
        tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            /// A device-flow code token: ABCD-EFGH (4–5 chars each side).
            fn extract_code(line: &str) -> Option<String> {
                line.split_whitespace().find_map(|raw| {
                    let t = raw.trim_start_matches('(').trim_end_matches(')');
                    let mut parts = t.split('-');
                    let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next())
                    else {
                        return None;
                    };
                    let ok = (4..=5usize).contains(&a.len())
                        && (4..=5usize).contains(&b.len())
                        && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
                    ok.then(|| t.to_uppercase())
                })
            }
            let lines = std::io::BufReader::new(stderr).lines();
            for line in lines {
                let Ok(line) = line else { break };
                if !line.to_lowercase().contains("one-time code") {
                    continue;
                }
                let Some(code) = extract_code(&line) else { continue };
                // Prefer the URL gh printed; fall back to the computed one.
                let url = line
                    .split_whitespace()
                    .find(|w| w.starts_with("https://"))
                    .unwrap_or(&device_url)
                    .to_string();
                let _ = emit_app.emit("gh-login-code", code);
                let _ = std_new_cmd("cmd")
                    .args(["/C", "start", "", &url])
                    .status();
                break;
            }
        });
    }

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()))?;
    *GH_LOGIN_PID.lock().unwrap() = None;
    if !status.success() {
        return if GH_LOGIN_CANCELLED.swap(false, Ordering::SeqCst) {
            Err(if force {
                "gh re-login cancelled — git identity and token are switched, but gh is still signed in as before.".into()
            } else {
                "gh login cancelled — nothing was changed.".into()
            })
        } else {
            Err(if force {
                "gh re-login failed — git identity and token are switched, but gh could not be re-authenticated.".into()
            } else {
                "gh login failed — nothing was changed.".into()
            })
        };
    }

    // Read the fresh token and verify it belongs to this account's login.
    let mut targs: Vec<String> = vec!["auth".into(), "token".into()];
    if host != "github.com" {
        targs.push("--hostname".into());
        targs.push(host.clone());
    }
    let trefs: Vec<&str> = targs.iter().map(|s| s.as_str()).collect();
    let (ok, token) = run_cmd(&gh, &trefs).await;
    if !ok || token.is_empty() {
        return Err("gh login finished, but no token could be read — nothing was stored.".into());
    }
    let Some((login, _, _)) = api_user(&account.provider, &host, &token) else {
        return Err("the gh session token was rejected (or you are offline) — nothing was stored.".into());
    };
    if !login.eq_ignore_ascii_case(&account.login) {
        return Err(format!(
            "gh signed in as {login}, but this account is {} — nothing was changed.",
            account.login
        ));
    }
    gcm_write_token(
        &target,
        &account.login,
        &cred_identity(&account.name, &account.email),
        &token,
    )
    .map_err(|e| format!("failed to store the token: {e}"))?;

    Ok(perform_switch(&app, &account, &token, &host).await)
}

/// Kill the in-flight `gh auth login --web` (user clicked Cancel).
#[tauri::command]
fn cancel_cli_login() -> Result<(), String> {
    let g = GH_LOGIN_PID.lock().unwrap();
    if let Some(pid) = *g {
        GH_LOGIN_CANCELLED.store(true, Ordering::SeqCst);
        std_new_cmd("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("no login in progress".into())
    }
}

/* --- Settings --- */

#[tauri::command]
async fn get_settings(app: AppHandle) -> Settings {
    read_settings(&app)
}

#[tauri::command]
async fn set_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    save_settings(&app, &settings)
}

/// Path of the app data folder (shown in Settings → Data).
#[tauri::command]
async fn app_data_path(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_config_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// Open a URL in the user's default browser (`cmd /C start` — the same
/// mechanism the gh device page uses).
#[tauri::command]
async fn open_external(url: String) -> Result<(), String> {
    std_new_cmd("cmd")
        .args(["/C", "start", "", &url])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/* --- CLI tools (gh / glab): check & install --- */

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CliToolStatus {
    pub installed: bool,
    pub version: String,
    /// signed-in login, empty when the CLI is not signed in
    pub login: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CliToolsStatus {
    pub gh: CliToolStatus,
    pub glab: CliToolStatus,
}

/// The version token (first word starting with a digit) of `--version` output.
fn extract_version(out: &str) -> String {
    out.lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or("")
        .to_string()
}

/// Candidate locations when the tool is not on this process's PATH yet
/// (e.g. right after a fresh install).
fn known_cli_paths(prog: &str) -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        v.push(format!("{local}\\Programs\\{prog}\\{prog}.exe"));
    }
    if let Ok(user) = std::env::var("USERPROFILE") {
        v.push(format!("{user}\\scoop\\shims\\{prog}.exe"));
    }
    // MSI installs (winget's default) land in Program Files
    if let Ok(pf) = std::env::var("ProgramFiles") {
        if prog == "gh" {
            v.push(format!("{pf}\\GitHub CLI\\{prog}.exe"));
        } else if prog == "glab" {
            v.push(format!("{pf}\\glab\\{prog}.exe"));
        }
    }
    v
}

async fn check_cli_one(prog: &str) -> CliToolStatus {
    let (ok, out) = run_cmd(prog, &["--version"]).await;
    let (mut installed, mut version) = if ok && !out.is_empty() {
        (true, extract_version(&out))
    } else {
        (false, String::new())
    };
    if !installed {
        for p in known_cli_paths(prog) {
            if !std::path::Path::new(&p).exists() {
                continue;
            }
            let (ok2, out2) = run_cmd(&p, &["--version"]).await;
            if ok2 && !out2.is_empty() {
                installed = true;
                version = extract_version(&out2);
                break;
            }
        }
    }
    let login = if installed {
        let args: &[&str] = if prog == "gh" {
            &["api", "user", "-q", ".login"]
        } else {
            &["api", "user", "-q", ".username"]
        };
        let (lok, lout) = run_cmd(prog, args).await;
        if lok {
            lout.trim().to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    CliToolStatus {
        installed,
        version,
        login,
    }
}

#[tauri::command]
async fn check_cli_tools() -> CliToolsStatus {
    let gh = check_cli_one("gh").await;
    let glab = check_cli_one("glab").await;
    CliToolsStatus { gh, glab }
}

/// Expand the %VARS% that PATH values commonly contain. The machine PATH is
/// stored as REG_EXPAND_SZ and typically uses %SystemRoot% & friends.
fn expand_env_refs(s: &str) -> String {
    let mut out = s.to_string();
    for name in [
        "SystemRoot",
        "SystemDrive",
        "ProgramFiles",
        "ProgramData",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
        "windir",
    ] {
        if let Ok(v) = std::env::var(name) {
            out = out.replace(&format!("%{name}%"), &v);
        }
    }
    out
}

/// Read the `Path` value (REG_SZ or REG_EXPAND_SZ) from a registry hive.
/// `reg query` wraps long values across continuation lines, so keep
/// appending indented lines until a blank line or the next key.
fn registry_path(hive: &str) -> String {
    let Some(out) = std_new_cmd("reg")
        .args(["query", hive, "/v", "Path"])
        .output()
        .ok()
    else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut value = String::new();
    let mut in_value = false;
    for line in text.lines() {
        if !in_value {
            let upper = line.to_uppercase();
            for marker in ["REG_EXPAND_SZ", "REG_SZ"] {
                if let Some(i) = upper.find(marker) {
                    value = line[i + marker.len()..].trim().to_string();
                    in_value = true;
                    break;
                }
            }
        } else if line.is_empty() || !line.starts_with(char::is_whitespace) {
            break;
        } else {
            value.push_str(line.trim());
        }
    }
    expand_env_refs(&value)
}

/// Rebuild this process's PATH from the registry (HKCU + HKLM). The PATH
/// cached at startup is stale right after a fresh install.
fn refresh_path_env() {
    let user = registry_path(r"HKCU\Environment");
    let sys = registry_path(
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    );
    let combined = if user.is_empty() {
        sys
    } else if sys.is_empty() {
        user
    } else {
        format!("{user};{sys}")
    };
    if !combined.is_empty() {
        std::env::set_var("PATH", combined);
    }
}

#[tauri::command]
async fn install_cli_tool(which: String) -> Result<CliToolStatus, String> {
    let (prog, winget_id) = match which.as_str() {
        "gh" => ("gh", "GitHub.cli"),
        "glab" => ("glab", "GLab.GLab"),
        _ => return Err("unknown tool".into()),
    };
    let (ok, _) = run_cmd("winget", &["--version"]).await;
    if !ok {
        return Err("winget not found".into());
    }
    let (ok, out) = run_cmd(
        "winget",
        &[
            "install",
            winget_id,
            // Pin the community source: the package also exists in
            // `msstore`, and without this winget can abort with
            // "specify one of them using the --source option".
            "--source",
            "winget",
            "--disable-interactivity",
            "--accept-source-agreements",
            "--accept-package-agreements",
            "--silent",
        ],
    )
    .await;
    if !ok {
        return Err(format!("winget install failed: {}", out.trim()));
    }
    refresh_path_env();
    Ok(check_cli_one(prog).await)
}

/* --- Export / Import (rfd dialogs are blocking → spawn_blocking) --- */

#[tauri::command]
async fn export_accounts(app: AppHandle) -> Result<String, String> {
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let accounts = load_accounts(&app2);
        if accounts.is_empty() {
            return Err("no accounts to export".into());
        }
        let json = serde_json::to_string_pretty(&accounts).map_err(|e| e.to_string())?;
        let blob = encrypt_payload(json.as_bytes())?;
        let mut out = Vec::with_capacity(FILE_MAGIC.len() + blob.len());
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&blob);

        let path = rfd::FileDialog::new()
            .set_title("Export accounts")
            .add_filter("Git Account Switcher export", &["gas1"])
            .set_file_name("git-accounts.gas1")
            .save_file()
            .ok_or_else(|| "cancelled".to_string())?;
        fs::write(&path, out).map_err(|e| e.to_string())?;
        Ok(path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn import_accounts(app: AppHandle) -> Result<u32, String> {
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let path = rfd::FileDialog::new()
            .set_title("Import accounts")
            .add_filter("Export / legacy JSON", &["gas1", "json"])
            .pick_file()
            .ok_or_else(|| "cancelled".to_string())?;
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;

        // Accept both the GAS1+AES-256-GCM format and legacy plaintext JSON.
        let json = if bytes.starts_with(FILE_MAGIC) {
            String::from_utf8(decrypt_payload(&bytes[FILE_MAGIC.len()..]).ok_or_else(
                || "could not decrypt file (invalid or corrupted export)".to_string(),
            )?)
            .map_err(|e| e.to_string())?
        } else {
            String::from_utf8(bytes).map_err(|_| "not a valid export file".to_string())?
        };
        let incoming: Vec<RawAccount> =
            serde_json::from_str(&json).map_err(|e| format!("invalid export: {e}"))?;

        let mut accounts = load_accounts(&app2);
        for r in incoming {
            let host = r.provider.resolve_host(&r.host);
            let target = cred_target(&r.provider, &host, &r.login);
            // The token itself is never in the file; it exists locally only
            // if a per-account Credential Manager entry is already present.
            let stored = gcm_read_token(&target).is_some();
            let account = Account {
                id: r.id,
                provider: r.provider,
                host: r.host,
                label: r.label,
                name: r.name,
                email: r.email,
                login: r.login,
                token_stored: stored,
                ssh_key_path: r.ssh_key_path,
            };
            match accounts.iter().position(|a| a.id == account.id) {
                Some(i) => accounts[i] = account,
                None => accounts.push(account),
            }
        }
        save_accounts(&app2, &accounts)?;
        Ok(accounts.len() as u32)
    })
    .await
    .map_err(|e| e.to_string())?
}

/* ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrip() {
        let data = b"git-account-switcher self-test payload";
        let enc = encrypt_payload(data).expect("encrypt failed");
        // Encrypted output must differ from the plaintext and carry a nonce.
        assert!(enc.len() >= NONCE_LEN + 16);
        assert_ne!(&enc[NONCE_LEN..NONCE_LEN + data.len()], data);
        let dec = decrypt_payload(&enc).expect("decrypt failed");
        assert_eq!(dec, data);
    }

    #[test]
    fn payload_rejects_garbage() {
        // A non-GAS1 (or corrupted) payload must not decrypt to valid data.
        assert!(decrypt_payload(&[0u8; 64]).is_none());
        assert!(decrypt_payload(&[]).is_none());
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Only one instance: a second launch focuses the existing window.
        .plugin(tauri_plugin_single_instance::init(|app_handle, _args, _cwd| {
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        // Close-to-tray: intercept close and hide instead of quitting.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = &event {
                if read_settings(window.app_handle()).close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .on_tray_icon_event(|tray, event| {
            use tauri::tray::{MouseButton, TrayIconEvent};
            if let TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
        })
        .on_menu_event(|app, event| {
            if event.id.as_ref() == "quit" {
                app.exit(0);
            }
        })
        .setup(|app| {
            let handle = app.handle();
            let menu = Menu::with_items(
                handle,
                &[
                    &MenuItem::with_id(handle, "active", active_account_label(handle), false, None::<&str>)?,
                    &PredefinedMenuItem::separator(handle)?,
                    &MenuItem::with_id(handle, "quit", "Quit", true, None::<&str>)?,
                ],
            )?;
            let _tray = tauri::tray::TrayIconBuilder::with_id("tray")
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .ok_or_else(|| "no app icon available".to_string())?,
                )
                .menu(&menu)
                .tooltip("Git Account Switcher")
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_accounts,
            save_account,
            delete_account,
            import_saved_credentials,
            detect_systems,
            switch_account,
            switch_account_browser,
            cancel_cli_login,
            get_settings,
            set_settings,
            app_data_path,
            open_external,
            check_cli_tools,
            install_cli_tool,
            export_accounts,
            import_accounts
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
