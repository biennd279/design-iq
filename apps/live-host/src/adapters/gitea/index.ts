/**
 * Gitea implementation of the provider seam (docs/extending/connectors.md):
 * a self-hosted Gitea instead of a GitHub App.
 *
 *   GitProvider           — push URL + PR creation on the platform PAT
 *   RepoConnectionSource  — org membership enumerates the connected repos (no
 *                           installations: one "connection" = the PAT), the PAT
 *                           clones, Gitea's GitHub-compatible collaborator
 *                           endpoint answers per-user permission, and Gitea's
 *                           webhooks (X-Hub-Signature-256 / X-Gitea-Signature,
 *                           both HMAC-SHA256) are verified fail-closed.
 *
 * Gitea's REST is GitHub-v3-shaped (`/repos/{owner}/{repo}/pulls`,
 * `.../collaborators/{user}/permission`), so the calls mirror the GitHub
 * adapters — but there are no App mechanics anywhere: `connectionRef` is a
 * constant, `cloneToken` returns the platform PAT, and the connected set is
 * "every repo of the configured orgs" (or of the token owner when no org is
 * configured), kept current by `repository`/`organization` webhooks.
 *
 * Env is read ONLY in server.ts (ADR 0003): GITEA_URL, GITEA_TOKEN,
 * GITEA_ORGS, GITEA_WEBHOOK_SECRET. `fetchImpl` is injectable for tests —
 * no network seam outside adapters (dependency-cruiser enforced).
 */
import { createHmac, timingSafeEqual } from "node:crypto";

import type {
  ConnectionSnapshot,
  RepoConnectionSource,
  RepoPermission,
  SourceRepo,
} from "../../ports/connection-source.ts";
import type { GitProvider, PullRequestRef } from "../../ports/git-provider.ts";

export interface GiteaConfig {
  /** web base, e.g. https://gitea.example.com (API at <base>/api/v1) */
  baseUrl: string;
  /** platform PAT: repo read for enumeration/clone, write + PR for releases */
  token: string;
  /** org allowlist — the connected set is every repo of these orgs.
   * Empty: the token owner's own repositories. */
  orgs?: string[];
  webhookSecret?: string;
  /** test seam — defaults to global fetch */
  fetchImpl?: typeof fetch;
}

export const giteaApi = (baseUrl: string): string => `${baseUrl.replace(/\/$/, "")}/api/v1`;

/** Gitea's pagination is ?page=N (1-based, no Link headers) */
async function giteaPaginate<T>(f: typeof fetch, api: string, token: string, path: string): Promise<T[]> {
  const out: T[] = [];
  for (let page = 1; page <= 50; page++) {
    const sep = path.includes("?") ? "&" : "?";
    const res = await f(`${api}${path}${sep}limit=50&page=${page}`, {
      headers: { authorization: `token ${token}`, accept: "application/json" },
    });
    if (!res.ok) throw new Error(`gitea ${path} → ${res.status} ${await res.text()}`);
    const batch = (await res.json()) as T[];
    out.push(...batch);
    if (batch.length < 50) return out;
  }
  return out;
}

export function createGiteaSource(cfg: GiteaConfig): RepoConnectionSource {
  const api = giteaApi(cfg.baseUrl);
  const f = cfg.fetchImpl ?? fetch;
  const orgs = cfg.orgs ?? [];
  // no App installations in Gitea: the PAT itself is THE connection
  const REF = 1;

  async function reposOfOrg(org: string): Promise<SourceRepo[]> {
    const repos = await giteaPaginate<GiteaRepo>(f, api, cfg.token, `/orgs/${encodeURIComponent(org)}/repos`);
    return repos.map(toSourceRepo);
  }
  async function ownRepos(): Promise<SourceRepo[]> {
    const repos = await giteaPaginate<GiteaRepo>(f, api, cfg.token, "/user/repos");
    return repos.map(toSourceRepo);
  }

  function toSourceRepo(r: GiteaRepo): SourceRepo {
    return {
      fullName: r.full_name,
      defaultBranch: r.default_branch ?? "main",
      private: !!r.private,
      avatarUrl: r.owner?.avatar_url ?? null,
      connectionRef: REF,
      providerId: r.id,
      pushedAt: r.updated_at ?? null,
    };
  }

  return {
    id: "gitea-pat",
    canEnumerate: true,

    async listConnectedRepos(): Promise<ConnectionSnapshot> {
      const repos: SourceRepo[] = [];
      if (orgs.length > 0) {
        for (const org of orgs) repos.push(...(await reposOfOrg(org)));
      } else {
        repos.push(...(await ownRepos()));
      }
      return {
        repos,
        knownRefs: new Set([REF]),
        enumeratedRefs: new Set([REF]),
        suspendedRefs: new Set(),
      };
    },

    async cloneToken() {
      return cfg.token;
    },

    async checkUserPermission(_connectionRef: number, username: string, repo: string): Promise<RepoPermission> {
      const res = await f(`${api}/repos/${repo}/collaborators/${encodeURIComponent(username)}/permission`, {
        headers: { authorization: `token ${cfg.token}`, accept: "application/json" },
      });
      if (res.status === 404 || res.status === 403) return "none"; // not a collaborator / not visible
      if (!res.ok) throw new Error(`gitea permission ${repo}/${username} → ${res.status} ${await res.text()}`);
      const body = (await res.json()) as { permission?: string };
      const p = (body.permission ?? "none").toLowerCase();
      if (p === "owner") return "admin"; // Gitea reports the repo owner as "owner"
      return (["admin", "write", "read"].includes(p) ? p : "none") as RepoPermission;
    },

    connectUrl() {
      // no install picker in Gitea: repos join the connected set through org
      // membership; `repository`/`organization` webhooks keep it in sync
      return undefined;
    },

    verifyWebhook(headers, rawBody) {
      if (!cfg.webhookSecret) return undefined;
      const expected = createHmac("sha256", cfg.webhookSecret).update(rawBody).digest("hex");
      const eq = (sig: string | string[] | undefined): boolean => {
        if (typeof sig !== "string") return false;
        const bare = sig.startsWith("sha256=") ? sig.slice("sha256=".length) : sig;
        return bare.length === expected.length && timingSafeEqual(Buffer.from(bare), Buffer.from(expected));
      };
      // gitea-type webhooks sign as X-Gitea-Signature (bare hex), github-type
      // as X-Hub-Signature-256 ("sha256=hex") — accept either
      const authentic = eq(headers["x-hub-signature-256"]) || eq(headers["x-gitea-signature"]);
      const event = (headers["x-gitea-event"] ?? headers["x-github-event"]) as string | undefined;
      return {
        authentic,
        membershipChanged: authentic && (event === "repository" || event === "organization"),
      };
    },
  };
}

interface GiteaRepo {
  id: number;
  full_name: string;
  default_branch?: string;
  private?: boolean;
  updated_at?: string | null;
  owner?: { avatar_url?: string };
}

export function createGiteaProvider(cfg: GiteaConfig): GitProvider {
  const host = cfg.baseUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const api = giteaApi(cfg.baseUrl);
  const f = cfg.fetchImpl ?? fetch;

  return {
    id: "gitea",

    pushUrl(token, repo) {
      const proto = cfg.baseUrl.startsWith("http://") ? "http" : "https";
      return `${proto}://x-access-token:${token}@${host}/${repo}.git`;
    },

    async createPullRequest(
      token,
      repo,
      args: { branch: string; base: string; title: string; body: string },
    ): Promise<PullRequestRef> {
      const res = await f(`${api}/repos/${repo}/pulls`, {
        method: "POST",
        headers: { authorization: `token ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ head: args.branch, base: args.base, title: args.title, body: args.body }),
      });
      if (!res.ok) throw new Error(`gitea PR creation failed: ${res.status} ${await res.text()}`);
      const pr = (await res.json()) as { html_url: string; number: number };
      return { url: pr.html_url, number: pr.number } satisfies PullRequestRef;
    },
  };
}
