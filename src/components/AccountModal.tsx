import { useState } from "react";
import type { Account, Provider } from "../types";
import {
  PROVIDER_DEFAULT_HOST,
  PROVIDER_LABEL,
  supportsCustomHost,
  tokenPlaceholder,
} from "../util";

interface Props {
  initial: Account | null;
  onSave: (a: Account, token: string | null) => void;
  onCancel: () => void;
}

const PROVIDERS: Provider[] = ["github", "gitlab", "gitea", "gitee"];

export function AccountModal({ initial, onSave, onCancel }: Props) {
  const [provider, setProvider] = useState<Provider>(initial?.provider ?? "github");
  const [host, setHost] = useState(initial?.host ?? "");
  const [label, setLabel] = useState(initial?.label ?? "");
  const [name, setName] = useState(initial?.name ?? "");
  const [email, setEmail] = useState(initial?.email ?? "");
  const [login, setLogin] = useState(initial?.login ?? "");
  const [token, setToken] = useState("");
  const [sshKeyPath, setSshKeyPath] = useState(initial?.sshKeyPath ?? "");

  const valid = label.trim() && name.trim() && email.trim() && login.trim();

  function submit() {
    if (!valid) return;
    onSave(
      {
        id: initial?.id ?? crypto.randomUUID(),
        provider,
        host: supportsCustomHost(provider) ? host.trim() : "",
        label: label.trim(),
        name: name.trim(),
        email: email.trim(),
        login: login.trim(),
        tokenStored: initial?.tokenStored ?? false,
        sshKeyPath: sshKeyPath.trim(),
      },
      token.trim() ? token.trim() : null,
    );
  }

  return (
    <div className="overlay" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>{initial ? "Edit account" : "Add account"}</h2>
        </div>
        <div className="modal-body">
          <div className="field">
            <label>Provider</label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value as Provider)}
            >
              {PROVIDERS.map((p) => (
                <option key={p} value={p}>
                  {PROVIDER_LABEL[p]}
                </option>
              ))}
            </select>
          </div>
          {supportsCustomHost(provider) && (
            <div className="field">
              <label>Host</label>
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder={PROVIDER_DEFAULT_HOST[provider]}
              />
            </div>
          )}
          <div className="field">
            <label>Label<span className="req">*</span></label>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Work"
              autoFocus
            />
          </div>
          <div className="field">
            <label>Name (git user.name)<span className="req">*</span></label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your Name"
            />
          </div>
          <div className="field">
            <label>Email (git user.email)<span className="req">*</span></label>
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
          </div>
          <div className="field">
            <label>Username<span className="req">*</span></label>
            <input
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              placeholder="your-login"
            />
          </div>
          <div className="field">
            <label>
              Personal access token
              {initial?.tokenStored && (
                <span className="field-note">
                  {" "}
                  · stored in Credential Manager
                </span>
              )}
            </label>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={
                initial?.tokenStored
                  ? "leave blank to keep current"
                  : tokenPlaceholder(provider)
              }
            />
          </div>
          <div className="field">
            <label>SSH key path</label>
            <input
              value={sshKeyPath}
              onChange={(e) => setSshKeyPath(e.target.value)}
              placeholder="~/.ssh/id_ed25519 (optional)"
            />
          </div>
        </div>
        <div className="modal-foot">
          <button className="btn small ghost" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn small primary" disabled={!valid} onClick={submit}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
