import type { CliToolsStatus, Settings } from "../types";

interface Props {
  settings: Settings;
  dataPath: string;
  busy: "export" | "import" | "reimport" | null;
  cli: CliToolsStatus | null;
  cliBusy: "gh" | "glab" | null;
  onToggleCloseToTray: (v: boolean) => void;
  onToggleLaunchAtStartup: (v: boolean) => void;
  onReimport: () => void;
  onExport: () => void;
  onImport: () => void;
  onCheckCli: () => void;
  onInstallCli: (which: "gh" | "glab") => void;
  onClose: () => void;
}

export function SettingsModal({
  settings,
  dataPath,
  busy,
  cli,
  cliBusy,
  onToggleCloseToTray,
  onToggleLaunchAtStartup,
  onReimport,
  onExport,
  onImport,
  onCheckCli,
  onInstallCli,
  onClose,
}: Props) {
  return (
    <div className="overlay" onClick={onClose}>
      <div className="settings" onClick={(e) => e.stopPropagation()}>
        <div className="set-head">
          <h1>
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
            Settings
          </h1>
          <button className="xbtn" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="set-body">
          <div className="set-sect">About</div>
          <div className="about">
            <div className="logo">G</div>
            <div>
              <div className="nm">Git Account Switcher</div>
              <div className="by">by Mark Agan</div>
              <div className="ver">Version 0.1.1 · Windows</div>
            </div>
            <button className="btn primary" onClick={() => window.open(REPORT_URL)}>
              Report an issue
            </button>
          </div>

          <div className="set-sect">General</div>
          <div className="set-row">
            <div>
              <div className="lbl">Keep running in tray when closed</div>
              <div className="hint">Closing the window hides to the system tray</div>
            </div>
            <div
              className={`toggle ${settings.closeToTray ? "on" : ""}`}
              onClick={() => onToggleCloseToTray(!settings.closeToTray)}
            />
          </div>
          <div className="set-row">
            <div>
              <div className="lbl">Launch at startup</div>
              <div className="hint">Start the app when you sign in to Windows</div>
            </div>
            <div
              className={`toggle ${settings.launchAtStartup ? "on" : ""}`}
              onClick={() => onToggleLaunchAtStartup(!settings.launchAtStartup)}
            />
          </div>

          <div className="set-sect">Accounts</div>
          <div className="set-row">
            <div>
              <div className="lbl">Re-import saved credentials</div>
              <div className="hint">Scan Windows Credential Manager again</div>
            </div>
            <button className="btn" disabled={busy !== null} onClick={onReimport}>
              {busy === "reimport" ? "Scanning…" : "Re-import"}
            </button>
          </div>

          <div className="set-sect">CLI tools</div>
          {(["gh", "glab"] as const).map((which) => {
            const t = cli?.[which];
            const state = !t
              ? "checking…"
              : !t.installed
                ? "not installed"
                : t.login
                  ? `v${t.version} · signed in as ${t.login}`
                  : `v${t.version} · not signed in`;
            return (
              <div className="set-row" key={which}>
                <div>
                  <div className="lbl">
                    {which === "gh" ? "gh (GitHub CLI)" : "glab (GitLab CLI)"}
                  </div>
                  <div className="hint">{state}</div>
                </div>
                <button
                  className="btn"
                  disabled={cliBusy !== null}
                  onClick={() =>
                    t?.installed ? onCheckCli() : onInstallCli(which)
                  }
                >
                  {cliBusy === which
                    ? "Installing…"
                    : t?.installed
                      ? "Check"
                      : "Install"}
                </button>
              </div>
            );
          })}

          <div className="set-sect">Data</div>
          <div className="set-row">
            <div>
              <div className="lbl">Export accounts</div>
              <div className="hint">Save an encrypted backup of your accounts</div>
            </div>
            <button className="btn" disabled={busy !== null} onClick={onExport}>
              {busy === "export" ? "Exporting…" : "Export…"}
            </button>
          </div>
          <div className="set-row">
            <div>
              <div className="lbl">Import accounts</div>
              <div className="hint">Append or overwrite accounts from a backup file</div>
            </div>
            <button className="btn" disabled={busy !== null} onClick={onImport}>
              {busy === "import" ? "Importing…" : "Import…"}
            </button>
          </div>

          <div className="pathline">App data: {dataPath}</div>
        </div>
      </div>
    </div>
  );
}

const REPORT_URL = "https://github.com/aganmr/git-account-switcher/issues";
