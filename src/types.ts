export type Provider = "github" | "gitlab" | "gitea" | "gitee";

export interface Account {
  id: string;
  provider: Provider;
  /** Empty = provider default host */
  host: string;
  label: string;
  name: string;
  email: string;
  /** Provider username (login) */
  login: string;
  /** True when a token for this account exists in Windows Credential Manager */
  tokenStored: boolean;
  sshKeyPath: string;
}

export interface Settings {
  closeToTray: boolean;
  launchAtStartup: boolean;
}

export interface CliToolStatus {
  installed: boolean;
  version: string;
  /** signed-in login; empty when the CLI is not signed in */
  login: string;
}

export interface CliToolsStatus {
  gh: CliToolStatus;
  glab: CliToolStatus;
}

export interface SystemStatus {
  system: "git" | "token" | "cli" | "ssh";
  label: string;
  value: string;
  /** id of the account this system currently points to, when matched */
  accountId: string | null;
  known: boolean;
  /** token row only: RFC3339 expiry when the provider reports one */
  expiresAt?: string | null;
  /** token row only: the active slot token was rejected by the provider API */
  invalid?: boolean;
  /** cli row only: the account glab is signed in as (accountId carries gh) */
  glabAccountId?: string | null;
  /** cli row only: the tool is installed (regardless of sign-in state) */
  ghInstalled?: boolean;
  /** cli row only: the tool is installed (regardless of sign-in state) */
  glabInstalled?: boolean;
}

export interface SwitchResult {
  system: "git" | "token" | "cli" | "ssh";
  ok: boolean;
  skipped: boolean;
  message: string;
  /** cli row only: gh rejected the stored token — a browser re-login can fix it */
  needsBrowser?: boolean;
}
