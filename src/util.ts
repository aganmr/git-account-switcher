import type { Account, Provider } from "./types";

const PALETTE = [
  "#1f6feb",
  "#8250df",
  "#bf3989",
  "#3fb950",
  "#d29922",
  "#f85149",
  "#39a5c9",
];

export function avatarColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

export const PROVIDER_LABEL: Record<Provider, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  gitea: "Gitea / Forgejo",
  gitee: "Gitee",
};

export const PROVIDER_DEFAULT_HOST: Record<Provider, string> = {
  github: "github.com",
  gitlab: "gitlab.com",
  gitea: "gitea.com",
  gitee: "gitee.com",
};

/** Providers that support self-hosted instances get a host field. */
export function supportsCustomHost(p: Provider): boolean {
  return p !== "gitee";
}

/** Effective host for an account (empty host = provider default). */
export function hostFor(a: Account): string {
  const h = a.host.trim();
  if (h) return h;
  return PROVIDER_DEFAULT_HOST[a.provider] ?? PROVIDER_DEFAULT_HOST.github;
}

export function tokenPlaceholder(p: Provider): string {
  switch (p) {
    case "github":
      return "gho_… or github_pat_… (fine-grained)";
    case "gitlab":
      return "glpat-…";
    case "gitea":
      return "instance token (no fixed prefix)";
    case "gitee":
      return "Gitee personal token";
  }
}
