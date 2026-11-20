//! gas-cli — command-line entry point for Git Account Switcher.
//!
//! Built for AI agents: three commands, deterministic output, explicit
//! exit codes, no interactive prompts, no browser.
//!
//!   status            active account + per-system state
//!   list              all saved accounts
//!   switch <account>  switch the machine to a saved account
//!
//! v1 has no browser flow: when a switch would need one (no token
//! anywhere, or the provider rejecting the stored token), the CLI exits
//! 1 with `needsBrowser: true` in the JSON output — the user finishes
//! that in the app.

use std::path::PathBuf;
use std::process::ExitCode;

use git_account_switcher_lib::core::{
    cred_target, detect_systems, gcm_read_token, load_accounts, perform_switch, resolve_token,
    Account,
};

/// The app's Tauri identifier — the per-user config dir is
/// `%APPDATA%\<identifier>`, exactly where the app resolves it.
const CONFIG_SUBDIR: &str = "com.markaiserver.gitaccountswitcher";

fn config_dir() -> PathBuf {
    match std::env::var("APPDATA") {
        Ok(p) => PathBuf::from(p).join(CONFIG_SUBDIR),
        Err(_) => PathBuf::from(CONFIG_SUBDIR),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let rest: Vec<&str> = args
        .iter()
        .filter(|a| a.as_str() != "--json")
        .map(|s| s.as_str())
        .collect();

    let Some(command) = rest.first().copied() else {
        print_help();
        return ExitCode::from(2);
    };

    match command {
        "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            println!("gas-cli {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "status" => {
            if rest.len() != 1 {
                eprintln!("usage: gas-cli status [--json]");
                return ExitCode::from(2);
            }
            cmd_status(json)
        }
        "list" => {
            if rest.len() != 1 {
                eprintln!("usage: gas-cli list [--json]");
                return ExitCode::from(2);
            }
            cmd_list(json)
        }
        "switch" => {
            if rest.len() != 2 {
                eprintln!("usage: gas-cli switch <account> [--json]");
                return ExitCode::from(2);
            }
            cmd_switch(rest[1], json)
        }
        other => {
            eprintln!("error: unknown command '{other}'");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "gas-cli {} — switch git accounts from the command line

Usage:
  gas-cli status [--json]            active account + per-system state
  gas-cli list [--json]              all saved accounts
  gas-cli switch <account> [--json]  switch to a saved account

<account> is a label, a login, or a unique prefix of either.

Options:
  --json        machine-readable output (tokens are always masked)
  -h, --help    show this help
  -V, --version show the version

Exit codes: 0 = ok, 1 = operation failed, 2 = usage error

Browser login is not supported by the CLI yet — when a switch needs
it, the exit code is 1 and the JSON carries \"needsBrowser\": true.
Finish that in the app.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Resolve a user-supplied name to an account: exact label first, then
/// exact login (case-insensitive), then a unique prefix of either.
fn resolve_account<'a>(accounts: &'a [Account], query: &str) -> Result<&'a Account, String> {
    let q = query.trim();
    if q.is_empty() {
        return Err("empty account name".into());
    }
    if let Some(a) = accounts.iter().find(|a| a.label == q) {
        return Ok(a);
    }
    if let Some(a) = accounts.iter().find(|a| a.login.eq_ignore_ascii_case(q)) {
        return Ok(a);
    }
    let ql = q.to_lowercase();
    let matches: Vec<&Account> = accounts
        .iter()
        .filter(|a| {
            a.label.to_lowercase().starts_with(&ql) || a.login.to_lowercase().starts_with(&ql)
        })
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("no account matches '{q}' (see `gas-cli list`)")),
        _ => Err(format!(
            "'{q}' is ambiguous: {}",
            matches
                .iter()
                .map(|a| a.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn cmd_status(json: bool) -> ExitCode {
    let accounts = load_accounts(&config_dir());
    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    let statuses = rt.block_on(detect_systems(&accounts));

    // The active account is the one the git identity points to.
    let active_id = statuses
        .iter()
        .find(|s| s.system == "git")
        .and_then(|s| s.account_id.clone());
    let active = active_id.and_then(|id| accounts.iter().find(|a| a.id == id));

    if json {
        let out = serde_json::json!({
            "active": active,
            "systems": statuses,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return ExitCode::SUCCESS;
    }

    match active {
        Some(a) => println!(
            "active account: {} ({}) — {}",
            a.login, a.name, a.provider
        ),
        None => {
            let git_value = statuses
                .iter()
                .find(|s| s.system == "git")
                .map(|s| s.value.as_str())
                .unwrap_or("not set");
            println!("active account: none ({git_value})");
        }
    }
    println!();
    for s in &statuses {
        let flag = if s.known { "ok" } else { "?" };
        let mut value = s.value.clone();
        if s.system == "token" && s.invalid {
            value.push_str(" (REJECTED by API)");
        }
        if let Some(exp) = &s.expires_at {
            value.push_str(&format!(" (expires {exp})"));
        }
        println!("  {:<6} {:<8} {}", s.system, flag, value);
    }
    ExitCode::SUCCESS
}

fn cmd_list(json: bool) -> ExitCode {
    let accounts = load_accounts(&config_dir());
    if json {
        let out = serde_json::json!({ "accounts": accounts });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return ExitCode::SUCCESS;
    }
    if accounts.is_empty() {
        println!("no accounts saved (add them in the app)");
        return ExitCode::SUCCESS;
    }
    let w = accounts.iter().map(|a| a.label.len()).max().unwrap_or(5).max(5);
    for a in &accounts {
        // Live check: the file's tokenStored flag can lag behind the
        // Credential Manager (the app refreshes it; the CLI never writes).
        let host = a.provider.resolve_host(&a.host);
        let stored =
            gcm_read_token(&cred_target(&a.provider, &host, &a.login)).is_some();
        println!(
            "{:<w$} {:<8} {:<40} token: {}",
            a.label,
            a.provider,
            format!("{} <{}>", a.name, a.email),
            if stored { "yes" } else { "no" }
        );
    }
    ExitCode::SUCCESS
}

fn cmd_switch(query: &str, json: bool) -> ExitCode {
    let accounts = load_accounts(&config_dir());
    let account = match resolve_account(&accounts, query) {
        Ok(a) => a,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("error: {e}");
            }
            return ExitCode::from(2);
        }
    };

    let host = account.provider.resolve_host(&account.host);
    let target = cred_target(&account.provider, &host, &account.login);
    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");

    // All-or-nothing: an account without a usable token cannot become the
    // sole usable account, so fail before touching anything on this machine.
    let Some(token) = rt.block_on(resolve_token(account, &target)) else {
        let msg = format!(
            "no git token available for {} ({}). Add a token in the app, or sign in with gh/glab as this account, then retry. (browser login from the CLI is not supported yet — use the app)",
            account.label, account.login
        );
        if json {
            let out = serde_json::json!({
                "ok": false,
                "needsBrowser": true,
                "account": account.label,
                "error": msg,
                "results": [],
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            eprintln!("error: {msg}");
        }
        return ExitCode::from(1);
    };

    let results = rt.block_on(perform_switch(account, &token, &host));
    let needs_browser = results.iter().any(|r| r.needs_browser);
    let ok = results.iter().all(|r| r.ok);

    if json {
        let out = serde_json::json!({
            "ok": ok,
            "needsBrowser": needs_browser,
            "account": account.label,
            "results": results,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!(
            "switched to {} ({}) — {}",
            account.label, account.name, account.provider
        );
        for r in &results {
            let flag = if r.skipped { "skipped" } else if r.ok { "ok" } else { "FAILED" };
            println!("  {:<6} {:<8} {}", r.system, flag, r.message);
        }
        if !ok {
            let hint = if needs_browser {
                format!(
                    "partial switch — re-authenticate {} via the app's browser login, then re-run",
                    account.label
                )
            } else {
                "partial switch — see the failed rows above".to_string()
            };
            eprintln!("error: {hint}");
        }
    }
    ExitCode::from(u8::from(!ok))
}
