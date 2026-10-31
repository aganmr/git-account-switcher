import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "./tauri";
import type {
  Account,
  CliToolsStatus,
  CliToolStatus,
  Settings,
  SystemStatus,
  SwitchResult,
} from "./types";

/* In a plain browser (npm run dev) a mock API is used so the UI can be
   developed without the Tauri runtime. */

const MOCK_ACCOUNTS: Account[] = [
  {
    id: "acc-1",
    provider: "github",
    host: "",
    label: "Mark Dev",
    name: "Mark Dev",
    email: "mark.dev@gmail.com",
    login: "mark-dev",
    tokenStored: true,
    sshKeyPath: "~/.ssh/id_ed25519_personal",
  },
  {
    id: "acc-2",
    provider: "gitlab",
    host: "gitlab.com",
    label: "Work",
    name: "Mark (Company)",
    email: "mark@company.com",
    login: "mark-work",
    tokenStored: true,
    sshKeyPath: "",
  },
  {
    id: "acc-3",
    provider: "gitea",
    host: "code.example.dev",
    label: "Open Source",
    name: "Mark OSS",
    email: "oss@mark.dev",
    login: "mark-oss",
    tokenStored: false,
    sshKeyPath: "",
  },
  {
    id: "acc-4",
    provider: "gitee",
    host: "",
    label: "Test Account",
    name: "Test",
    email: "test@mark.dev",
    login: "mark-test",
    tokenStored: true,
    sshKeyPath: "",
  },
];

const MOCK_SETTINGS: Settings = {
  closeToTray: true,
  launchAtStartup: false,
};

function mockStatuses(): SystemStatus[] {
  const [a] = MOCK_ACCOUNTS;
  return [
    {
      system: "git",
      label: "Git identity",
      value: a.email,
      accountId: a.id,
      known: true,
    },
    {
      system: "token",
      label: "Git token (stored)",
      value: "github.com: gho_mock…   ·   gitlab.com: glpat-mock…",
      accountId: a.id,
      known: true,
    },
    {
      system: "cli",
      label: "CLI (gh / glab)",
      value: `gh: ${a.login}   ·   glab: not signed in`,
      accountId: a.id,
      known: true,
    },
    {
      system: "ssh",
      label: "SSH key",
      value: a.sshKeyPath,
      accountId: a.id,
      known: true,
    },
  ];
}

function mockResults(): SwitchResult[] {
  return [
    { system: "git", ok: true, skipped: false, message: "" },
    { system: "token", ok: true, skipped: false, message: "" },
    { system: "cli", ok: true, skipped: false, message: "" },
    { system: "ssh", ok: true, skipped: false, message: "" },
  ];
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function listAccounts(): Promise<Account[]> {
  if (isTauri()) return invoke<Account[]>("list_accounts");
  await delay(150);
  return MOCK_ACCOUNTS;
}

export async function detectSystems(): Promise<SystemStatus[]> {
  if (isTauri()) return invoke<SystemStatus[]>("detect_systems");
  await delay(300);
  return mockStatuses();
}

export async function switchAccount(id: string): Promise<SwitchResult[]> {
  if (isTauri()) return invoke<SwitchResult[]>("switch_account", { id });
  await delay(600);
  return mockResults();
}

/** Tokenless GitHub accounts: starts `gh auth login --web`, waits for the
    browser login to finish, then performs the switch. With `force`, skips
    the stored-token shortcut — used to re-authenticate after gh rejected
    the stored token (missing scope, expired, revoked). */
export async function switchAccountBrowser(
  id: string,
  force = false,
): Promise<SwitchResult[]> {
  if (isTauri()) {
    return invoke<SwitchResult[]>("switch_account_browser", { id, force });
  }
  await delay(600);
  return mockResults();
}

/** Cancel the in-flight `gh auth login --web`. */
export async function cancelCliLogin(): Promise<void> {
  if (isTauri()) return invoke("cancel_cli_login");
}

/** Save an account. `token` (trimmed) is stored in Windows Credential
    Manager; pass `null` to keep the currently stored token. */
export async function saveAccount(
  account: Account,
  token: string | null,
): Promise<Account> {
  if (isTauri()) {
    return invoke<Account>("save_account", { account, token });
  }
  await delay(150);
  return { ...account, tokenStored: token !== null };
}

export async function deleteAccount(id: string): Promise<void> {
  if (isTauri()) {
    await invoke("delete_account", { id });
    return;
  }
  await delay(150);
}

/** Import the git credentials saved in Windows Credential Manager (one per
    known provider host) as accounts. No-op in browser dev mode, where there
    is no credential mgr. */
export async function importSavedCredentials(): Promise<Account[]> {
  if (isTauri()) return invoke<Account[]>("import_saved_credentials");
  return [];
}

/* --- Settings --- */

export async function getSettings(): Promise<Settings> {
  if (isTauri()) return invoke<Settings>("get_settings");
  return { ...MOCK_SETTINGS };
}

export async function setSettings(s: Settings): Promise<void> {
  if (isTauri()) {
    await invoke("set_settings", { settings: s });
    return;
  }
  Object.assign(MOCK_SETTINGS, s);
}

/* --- CLI tools (gh / glab) --- */

export async function checkCliTools(): Promise<CliToolsStatus> {
  if (isTauri()) return invoke<CliToolsStatus>("check_cli_tools");
  return {
    gh: { installed: true, version: "2.65.0", login: "mark-dev" },
    glab: { installed: false, version: "", login: "" },
  };
}

export async function installCliTool(
  which: "gh" | "glab",
): Promise<CliToolStatus> {
  if (isTauri()) return invoke<CliToolStatus>("install_cli_tool", { which });
  await delay(800);
  return { installed: true, version: "0.0.0", login: "" };
}

/** Path of the app data folder (shown in Settings → Data). */
export async function appDataPath(): Promise<string> {
  if (isTauri()) return invoke<string>("app_data_path");
  return "%APPDATA%\\com.markaiserver.gitaccountswitcher";
}

/* --- Export / Import (rfd dialogs; unavailable in browser dev mode) --- */

export async function exportAccounts(): Promise<string> {
  return invoke<string>("export_accounts");
}

/** Returns the total number of accounts after the import. */
export async function importAccounts(): Promise<number> {
  return invoke<number>("import_accounts");
}

/* --- Launch at startup (tauri-plugin-autostart) --- */

export async function isAutostartEnabled(): Promise<boolean> {
  if (isTauri()) return invoke<boolean>("is_enabled");
  return MOCK_SETTINGS.launchAtStartup;
}

export async function enableAutostart(): Promise<void> {
  if (isTauri()) {
    await invoke("enable");
    return;
  }
  MOCK_SETTINGS.launchAtStartup = true;
}

export async function disableAutostart(): Promise<void> {
  if (isTauri()) {
    await invoke("disable");
    return;
  }
  MOCK_SETTINGS.launchAtStartup = false;
}
