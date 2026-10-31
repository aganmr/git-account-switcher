import { useCallback, useEffect, useRef, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { DetailPanel } from "./components/DetailPanel";
import { AccountModal } from "./components/AccountModal";
import { SettingsModal } from "./components/SettingsModal";
import { Dialog } from "./components/Dialog";
import {
  listAccounts,
  detectSystems,
  switchAccount,
  switchAccountBrowser,
  cancelCliLogin,
  saveAccount,
  deleteAccount,
  importSavedCredentials,
  getSettings,
  setSettings as persistSettings,
  appDataPath,
  exportAccounts,
  importAccounts,
  isAutostartEnabled,
  enableAutostart,
  disableAutostart,
  checkCliTools,
  installCliTool,
} from "./api";
import type {
  Account,
  CliToolsStatus,
  Settings,
  SystemStatus,
  SwitchResult,
} from "./types";

type ModalState =
  | { mode: "new" }
  | { mode: "edit"; account: Account }
  | null;

export default function App() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<SystemStatus[]>([]);
  const [switching, setSwitching] = useState(false);
  const [cliLogin, setCliLogin] = useState(false);
  const [ghCode, setGhCode] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<SwitchResult[] | null>(null);
  const [modal, setModal] = useState<ModalState>(null);

  /* --- in-app dialogs (replace the native alert()/confirm() prompts) --- */
  const [dialog, setDialog] = useState<{
    kind: "alert" | "confirm";
    title: string;
    message: string;
    confirmLabel?: string;
  } | null>(null);
  const dialogResolve = useRef<((ok: boolean) => void) | null>(null);

  function showAlert(title: string, message: string) {
    setDialog({ kind: "alert", title, message });
  }

  function askConfirm(
    title: string,
    message: string,
    confirmLabel?: string,
  ): Promise<boolean> {
    return new Promise((resolve) => {
      dialogResolve.current = resolve;
      setDialog({ kind: "confirm", title, message, confirmLabel });
    });
  }

  function closeDialog(ok: boolean) {
    const r = dialogResolve.current;
    dialogResolve.current = null;
    setDialog(null);
    r?.(ok);
  }

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<Settings>({
    closeToTray: true,
    launchAtStartup: false,
  });
  const [dataPath, setDataPath] = useState("");
  const [dataBusy, setDataBusy] = useState<"export" | "import" | "reimport" | null>(
    null,
  );
  const [cli, setCli] = useState<CliToolsStatus | null>(null);
  const [cliBusy, setCliBusy] = useState<"gh" | "glab" | null>(null);

  const refresh = useCallback(async () => {
    const [accs, sts] = await Promise.all([listAccounts(), detectSystems()]);
    setAccounts(accs);
    setStatuses(sts);
    setSelectedId((prev) => prev ?? accs[0]?.id ?? null);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        // Auto-import git credentials saved in Credential Manager
        // (idempotent; skipped when already tracked or invalid).
        await importSavedCredentials();
      } catch {
        // non-fatal — manual add still works
      }
      await refresh();
      try {
        const [s, p] = await Promise.all([getSettings(), appDataPath()]);
        // The real autostart state comes from the OS (registry), not the file.
        const auto = await isAutostartEnabled();
        setSettings({ ...s, launchAtStartup: auto });
        setDataPath(p);
      } catch {
        // non-fatal
      }
    })();
  }, [refresh]);

  const selected = accounts.find((a) => a.id === selectedId) ?? null;

  async function doSwitch() {
    if (!selected || switching) return;
    // Tokenless GitHub accounts go through the gh browser login: the
    // browser opens, the user finishes the login, the switch continues.
    const useBrowser =
      selected.provider === "github" && !selected.tokenStored;
    setSwitching(true);
    setCliLogin(useBrowser);
    setLastResult(null);
    let result: SwitchResult[] | null = null;
    try {
      result = useBrowser
        ? await switchAccountBrowser(selected.id)
        : await switchAccount(selected.id);
      // gh rejected the stored token (missing scope, expired, revoked):
      // continue into the browser re-login, exactly like a tokenless
      // account. The stored token is replaced when the login succeeds.
      if (
        selected.provider === "github" &&
        !useBrowser &&
        result.some((r) => r.needsBrowser)
      ) {
        setCliLogin(true);
        result = await switchAccountBrowser(selected.id, true);
      }
      setLastResult(result);
      await refresh();
    } catch (e) {
      if (result) {
        // The browser re-login failed or was cancelled: keep the first
        // phase's results and append the failure to the cli row.
        result = result.map((r) =>
          r.system === "cli" ? { ...r, message: `${r.message} — ${e}` } : r,
        );
      } else {
        result = [
          {
            system: "git",
            ok: false,
            skipped: false,
            message: String(e),
          },
        ];
      }
      setLastResult(result);
    } finally {
      setSwitching(false);
      setCliLogin(false);
    }
  }

  // While the gh browser login is in flight, the one-time code arrives via
  // an event (gh won't open the browser itself when run headless).
  useEffect(() => {
    if (!cliLogin) {
      setGhCode(null);
      return;
    }
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<string>("gh-login-code", (e) =>
          setGhCode(e.payload),
        );
      } catch {
        // browser dev mode: no events
      }
    })();
    return () => {
      unlisten?.();
    };
  }, [cliLogin]);

  async function handleCancelCliLogin() {
    try {
      await cancelCliLogin();
    } catch {
      // non-fatal: the login command will surface its own error
    }
  }

  async function handleSave(a: Account, token: string | null) {
    try {
      await saveAccount(a, token);
      setModal(null);
      setSelectedId(a.id);
      await refresh();
    } catch (e) {
      showAlert("Save failed", `Could not save account: ${String(e)}`);
    }
  }

  async function handleRemove() {
    if (!selected) return;
    if (
      !(await askConfirm(
        "Remove account?",
        `This removes ${selected.label} and its stored token from this machine. Nothing else is changed.`,
        "Remove",
      ))
    )
      return;
    await deleteAccount(selected.id);
    setSelectedId(null);
    setLastResult(null);
    await refresh();
  }

  /* --- CLI tools (checked when the settings view opens) --- */

  useEffect(() => {
    if (!settingsOpen) return;
    (async () => {
      try {
        setCli(await checkCliTools());
      } catch {
        // non-fatal
      }
    })();
  }, [settingsOpen]);

  async function handleCheckCli() {
    try {
      setCli(await checkCliTools());
    } catch {
      // non-fatal
    }
  }

  async function handleInstallCli(which: "gh" | "glab") {
    setCliBusy(which);
    try {
      const st = await installCliTool(which);
      setCli((prev) => (prev ? { ...prev, [which]: st } : prev));
      await refresh(); // the CLI row in the main view is affected too
    } catch (e) {
      const msg = String(e);
      if (msg.includes("winget not found")) {
        // No winget: fall back to the official download page.
        window.open(
          which === "gh"
            ? "https://cli.github.com/"
            : "https://gitlab.com/gitlab-org/cli",
          "_blank",
        );
      } else {
        showAlert("Install failed", msg);
      }
    } finally {
      setCliBusy(null);
    }
  }

  /* --- settings handlers --- */

  async function toggleCloseToTray(v: boolean) {
    const next = { ...settings, closeToTray: v };
    setSettings(next);
    try {
      await persistSettings(next);
    } catch {
      // non-fatal
    }
  }

  async function toggleLaunchAtStartup(v: boolean) {
    const next = { ...settings, launchAtStartup: v };
    setSettings(next);
    try {
      if (v) await enableAutostart();
      else await disableAutostart();
      await persistSettings(next);
    } catch (e) {
      setSettings(settings);
      showAlert("Launch at startup", `Could not change: ${String(e)}`);
    }
  }

  async function handleReimport() {
    setDataBusy("reimport");
    try {
      const imported = await importSavedCredentials();
      await refresh();
      showAlert(
        "Re-import",
        imported.length > 0
          ? `Imported ${imported.length} account(s).`
          : "Nothing new to import.",
      );
    } catch (e) {
      showAlert("Re-import failed", String(e));
    } finally {
      setDataBusy(null);
    }
  }

  async function handleExport() {
    setDataBusy("export");
    try {
      const path = await exportAccounts();
      showAlert("Export complete", `Exported to:\n${path}`);
    } catch (e) {
      const msg = String(e);
      if (!msg.includes("cancelled")) showAlert("Export failed", msg);
    } finally {
      setDataBusy(null);
    }
  }

  async function handleImport() {
    setDataBusy("import");
    try {
      const total = await importAccounts();
      await refresh();
      showAlert("Import complete", `${total} account(s) in total.`);
    } catch (e) {
      const msg = String(e);
      if (!msg.includes("cancelled")) showAlert("Import failed", msg);
    } finally {
      setDataBusy(null);
    }
  }

  return (
    <div className="win" onContextMenu={(e) => e.preventDefault()}>
      <Sidebar
        accounts={accounts}
        selectedId={selectedId}
        onSelect={(id) => {
          setSelectedId(id);
          setLastResult(null);
        }}
        onAdd={() => setModal({ mode: "new" })}
        onSettings={() => setSettingsOpen(true)}
      />
      <DetailPanel
        account={selected}
        accounts={accounts}
        statuses={statuses}
        switching={switching}
        cliLogin={cliLogin}
        ghCode={ghCode}
        onCancelCliLogin={handleCancelCliLogin}
        lastResult={lastResult}
        onSwitch={doSwitch}
        onEdit={() => selected && setModal({ mode: "edit", account: selected })}
        onRemove={handleRemove}
      />
      {modal && (
        <AccountModal
          initial={modal.mode === "edit" ? modal.account : null}
          onSave={handleSave}
          onCancel={() => setModal(null)}
        />
      )}
      {settingsOpen && (
        <SettingsModal
          settings={settings}
          dataPath={dataPath}
          busy={dataBusy}
          cli={cli}
          cliBusy={cliBusy}
          onCheckCli={handleCheckCli}
          onInstallCli={handleInstallCli}
          onToggleCloseToTray={toggleCloseToTray}
          onToggleLaunchAtStartup={toggleLaunchAtStartup}
          onReimport={handleReimport}
          onExport={handleExport}
          onImport={handleImport}
          onClose={() => setSettingsOpen(false)}
        />
      )}
      {dialog && (
        <Dialog
          kind={dialog.kind}
          title={dialog.title}
          message={dialog.message}
          confirmLabel={dialog.confirmLabel}
          onOk={() => closeDialog(true)}
          onCancel={() => closeDialog(false)}
        />
      )}
    </div>
  );
}
