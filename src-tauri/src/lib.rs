pub mod core;

use core::{
    api_user, auto_sync_token, check_cli_one, cli_exe, cred_identity, cred_manager_token,
    cred_target, decrypt_payload, detect_systems as detect_systems_impl, encrypt_payload,
    gcm_delete_token, gcm_read_token, gcm_write_token, git_global_identity_sync, load_accounts,
    perform_switch,
    read_settings, refresh_path_env, resolve_token, run_cmd, save_accounts, save_settings,
    std_new_cmd, Account, CliToolStatus, CliToolsStatus, Provider, RawAccount, Settings,
    SystemStatus, SwitchResult, FILE_MAGIC,
};
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::{AppHandle, Emitter, Manager};

/// App config dir. `gas-cli` resolves the same directory itself
/// (`%APPDATA%\com.markaiserver.gitaccountswitcher`).
fn cfg(app: &AppHandle) -> PathBuf {
    app.path()
        .app_config_dir()
        .expect("failed to resolve app config dir")
}

/* ------------------------------------------------------------------ */
/* Tray                                                                */
/* ------------------------------------------------------------------ */

/// Label for the tray menu's disabled "active account" line.
fn active_account_label(app: &AppHandle) -> String {
    let Some((name, email)) = git_global_identity_sync() else {
        return "No active account".to_string();
    };
    let accounts = load_accounts(&cfg(app));
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
    let mut accounts = load_accounts(&cfg(&app));
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
        save_accounts(&cfg(&app), &accounts)?;
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

    let mut accounts = load_accounts(&cfg(&app));
    match accounts.iter().position(|a| a.id == acc.id) {
        Some(i) => accounts[i] = acc.clone(),
        None => accounts.push(acc.clone()),
    }
    save_accounts(&cfg(&app), &accounts)?;
    Ok(acc)
}

#[tauri::command]
async fn delete_account(app: AppHandle, id: String) -> Result<(), String> {
    let mut accounts = load_accounts(&cfg(&app));
    if let Some(a) = accounts.iter().find(|a| a.id == id) {
        let host = a.provider.resolve_host(&a.host);
        gcm_delete_token(&cred_target(&a.provider, &host, &a.login));
    }
    accounts.retain(|a| a.id != id);
    save_accounts(&cfg(&app), &accounts)
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

        let accounts = load_accounts(&cfg(&app));
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

        let mut accounts = load_accounts(&cfg(&app));
        accounts.push(account.clone());
        save_accounts(&cfg(&app), &accounts)?;
        imported.push(account);
    }

    Ok(imported)
}

#[tauri::command]
async fn detect_systems(app: AppHandle) -> Result<Vec<SystemStatus>, String> {
    let accounts = load_accounts(&cfg(&app));
    Ok(detect_systems_impl(&accounts).await)
}

#[tauri::command]
async fn switch_account(app: AppHandle, id: String) -> Result<Vec<SwitchResult>, String> {
    let account = load_accounts(&cfg(&app))
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
    let results = perform_switch(&account, &token, &host).await;
    rebuild_tray_menu(&app);
    Ok(results)
}

/* gh browser login (tokenless GitHub accounts) */

/// PID of the in-flight `gh auth login --web` process, so the UI can
/// cancel it (taskkill). The child itself is waited on a blocking thread.
static GH_LOGIN_PID: Mutex<Option<u32>> = Mutex::new(None);
static GH_LOGIN_CANCELLED: AtomicBool = AtomicBool::new(false);

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
    let account = load_accounts(&cfg(&app))
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
            let results = perform_switch(&account, &token, &host).await;
            rebuild_tray_menu(&app);
            return Ok(results);
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

    let results = perform_switch(&account, &token, &host).await;
    rebuild_tray_menu(&app);
    Ok(results)
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
    read_settings(&cfg(&app))
}

#[tauri::command]
async fn set_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    save_settings(&cfg(&app), &settings)
}

/// Path of the app data folder (shown in Settings → Data).
#[tauri::command]
async fn app_data_path(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_config_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// Path of the `gas-cli` binary that ships next to the app executable
/// (shown in Settings).
#[tauri::command]
async fn cli_path() -> Result<String, String> {
    std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(|p| p.join("gas-cli.exe").to_string_lossy().to_string())
        .ok_or_else(|| "failed to resolve CLI path".to_string())
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

#[tauri::command]
async fn check_cli_tools() -> CliToolsStatus {
    let gh = check_cli_one("gh").await;
    let glab = check_cli_one("glab").await;
    CliToolsStatus { gh, glab }
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
        let accounts = load_accounts(&cfg(&app2));
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

        let mut accounts = load_accounts(&cfg(&app2));
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
        save_accounts(&cfg(&app2), &accounts)?;
        Ok(accounts.len() as u32)
    })
    .await
    .map_err(|e| e.to_string())?
}

/* ------------------------------------------------------------------ */

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
                if read_settings(&cfg(window.app_handle())).close_to_tray {
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
            cli_path,
            open_external,
            check_cli_tools,
            install_cli_tool,
            export_accounts,
            import_accounts
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
