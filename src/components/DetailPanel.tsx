import type { Account, SystemStatus, SwitchResult } from "../types";
import { avatarColor, hostFor, initials } from "../util";

interface Props {
  account: Account | null;
  accounts: Account[];
  statuses: SystemStatus[];
  switching: boolean;
  cliLogin: boolean;
  ghCode: string | null;
  lastResult: SwitchResult[] | null;
  onSwitch: () => void;
  onCancelCliLogin: () => void;
  onEdit: () => void;
  onRemove: () => void;
}

export function DetailPanel({
  account,
  accounts,
  statuses,
  switching,
  cliLogin,
  ghCode,
  lastResult,
  onSwitch,
  onCancelCliLogin,
  onEdit,
  onRemove,
}: Props) {
  if (!account) {
    return (
      <div className="main">
        <div className="empty">
          <div style={{ fontSize: 15, fontWeight: 600 }}>No account selected</div>
          <div>Use “+ Add account” to get started.</div>
        </div>
      </div>
    );
  }

  // "Active" = the account whose git identity is currently configured.
  // (Per-system sync is shown on the status rows; a token match alone
  // must not light the badge, or two accounts can both show ACTIVE.)
  const gitStatus = statuses.find((s) => s.system === "git");
  const active =
    !!gitStatus?.known && gitStatus.accountId === account.id;

  // Mixed state: identity and token point to two different accounts.
  const tokenStatus = statuses.find((s) => s.system === "token");
  const mixed =
    !!gitStatus?.accountId &&
    !!tokenStatus?.accountId &&
    gitStatus.accountId !== tokenStatus.accountId;
  const labelOf = (id: string) =>
    accounts.find((a) => a.id === id)?.label ?? id;

  // A switch is all-or-nothing: without a stored token the button is off,
  // UNLESS the matching CLI can supply one:
  //  - signed in as this account → its token is adopted (API-verified), or
  //  - simply installed → the switch starts the CLI's browser login
  //    (GitHub/gh only for now; GitLab/glab is pending).
  const noToken = !account.tokenStored;
  const cliStatus = statuses.find((s) => s.system === "cli");
  const cliCovers =
    account.provider === "gitlab"
      ? cliStatus?.glabAccountId === account.id
      : account.provider === "github"
        ? cliStatus?.accountId === account.id
        : false;
  const cliCanHelp =
    (account.provider === "github" && !!cliStatus?.ghInstalled) ||
    (account.provider === "gitlab" && !!cliStatus?.glabInstalled);
  const blocked = noToken && !cliCovers && !cliCanHelp;

  return (
    <div className="main">
      <div className="hero">
        <div
          className="avatar lg"
          style={{ background: avatarColor(account.id) }}
        >
          {initials(account.name)}
        </div>
        <div>
          <div className="hname">{account.label}</div>
          <div className="hemail">
            {[account.email, hostFor(account)].filter(Boolean).join("  ·  ")}
          </div>
        </div>
        {active && (
          <div className="active">
            <div className="dot" />
            ACTIVE
          </div>
        )}
      </div>

      <div className="sect">System status</div>
      <div className="rows">
        {statuses.map((s) => {
          let state = !s.known
            ? "unknown"
            : s.accountId === account.id
              ? "ok"
              : "bad";
          let text =
            state === "unknown" ? "unknown" : state === "ok" ? "in sync" : "out of sync";
          let value = s.value;
          if (s.system === "token" && s.known) {
            if (s.invalid) {
              state = "dead";
              text = "expired token";
            } else if (s.expiresAt) {
              const days = (new Date(s.expiresAt).getTime() - Date.now()) / 86400000;
              if (days <= 0) {
                state = "dead";
                text = "expired token";
              } else if (days <= 30) {
                state = "bad";
                text = `expires in ${Math.ceil(days)}d`;
              }
              value = `${s.value}  ·  expires ${new Date(s.expiresAt).toLocaleDateString()}`;
            }
          }
          return (
            <div key={s.system} className="row">
              <div className="lbl">{s.label}</div>
              <div className="val">{value}</div>
              <div className={`st ${state}`}>{text}</div>
            </div>
          );
        })}
      </div>

      {mixed && (
        <div className="mixed">
          Mixed state: identity = <b>{labelOf(gitStatus!.accountId!)}</b>, token ={" "}
          <b>{labelOf(tokenStatus!.accountId!)}</b>. Switch to one account to clean up.
        </div>
      )}

      <div className="result-actions">
        {lastResult && !switching && (
          <div className="result">
            {lastResult.map((r) => (
              <span key={r.system}>
                <span className={r.skipped ? "" : r.ok ? "ok" : "fail"}>
                  {r.system}
                </span>{" "}
                {r.skipped ? "skipped" : r.ok ? "ok" : r.message}
              </span>
            ))}
          </div>
        )}

        <div className="actions">
          <button className="iconbtn" title="Edit account" onClick={onEdit}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" />
            </svg>
          </button>
          <button className="iconbtn danger" title="Remove account" onClick={onRemove}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M3 6h18" />
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
              <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
              <line x1="10" y1="11" x2="10" y2="17" />
              <line x1="14" y1="11" x2="14" y2="17" />
            </svg>
          </button>
        </div>
      </div>

      <div className="footer">
        <button
          className={`btn primary${active || blocked || cliLogin ? " idle" : ""}`}
          disabled={switching || active || blocked || cliLogin}
          onClick={onSwitch}
        >
          {cliLogin
            ? "Waiting for browser login…"
            : switching
              ? "Switching…"
              : "Switch to this account"}
        </button>
        {cliLogin ? (
          <div className="switch-hint">
            {ghCode ? (
              <>
                Enter the code <b>{ghCode}</b> in the opened browser page —
                the switch continues automatically.
              </>
            ) : (
              "Opening the browser — the switch continues automatically."
            )}{" "}
            <button className="linkbtn" onClick={onCancelCliLogin}>
              Cancel
            </button>
          </div>
        ) : blocked ? (
          <div className="switch-hint">
            {account.provider === "github"
              ? "Either add a token (Edit) or install gh/glab before switching"
              : "Add a token (Edit) manually before switching"}
          </div>
        ) : null}
      </div>
    </div>
  );
}
