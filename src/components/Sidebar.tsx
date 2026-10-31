import type { Account } from "../types";
import { avatarColor, hostFor, initials } from "../util";

interface Props {
  accounts: Account[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onSettings: () => void;
}

export function Sidebar({ accounts, selectedId, onSelect, onAdd, onSettings }: Props) {
  return (
    <div className="side">
      <div className="side-head">
        <span>Accounts</span>
        <button className="cogbtn" title="Settings" onClick={onSettings}>
          <svg
            width="14"
            height="14"
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
        </button>
      </div>
      <div className="acc-list">
        {accounts.map((a) => (
          <div
            key={a.id}
            className={`acc ${a.id === selectedId ? "sel" : ""}`}
            onClick={() => onSelect(a.id)}
          >
            <div
              className="avatar"
              style={{ background: avatarColor(a.id) }}
            >
              {initials(a.name)}
            </div>
            <div style={{ minWidth: 0 }}>
              <div className="n">{a.label}</div>
              <div className="e">
                {a.login ? `${a.login} · ${hostFor(a)}` : hostFor(a)}
              </div>
            </div>
          </div>
        ))}
        {accounts.length === 0 && (
          <div style={{ padding: "12px 14px", color: "var(--muted)", fontSize: 12 }}>
            No accounts yet.
          </div>
        )}
      </div>
      <div className="side-foot" onClick={onAdd}>
        + Add account
      </div>
    </div>
  );
}
