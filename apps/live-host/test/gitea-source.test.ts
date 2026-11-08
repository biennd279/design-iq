/**
 * Gitea adapter (adapters/gitea) — the platform-credentialed seam against a
 * fake Gitea REST (fetchImpl-injected; no server, no network). Mirrors the
 * assertions of connection-source.test.ts for the GitHub source: enumeration
 * + mapping, permission mapping incl. Gitea's "owner" level, clone token,
 * both Gitea webhook signature forms, and the provider's push URL / PR call.
 */
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import { createGiteaProvider, createGiteaSource, type GiteaConfig } from "../src/adapters/gitea/index.ts";

const SECRET = "gitea-webhook-secret";

/** fake Gitea API: routes on (method, path) with canned JSON */
function fakeGitea(routes: Array<{ method?: string; path: string; status?: number; body: unknown }>): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = url.replace(/^https?:\/\/[^/]+\/api\/v1/, "").split("?")[0];
    const method = init?.method ?? "GET";
    const route = routes.find((r) => (r.method ?? "GET") === method && r.path === path);
    if (!route) return new Response(JSON.stringify({ message: `no route ${method} ${path}` }), { status: 404 });
    return new Response(JSON.stringify(route.body), { status: route.status ?? 200 });
  }) as typeof fetch;
}

const orgRepo = (full: string, id: number) => ({
  id,
  full_name: full,
  default_branch: "main",
  private: true,
  updated_at: "2026-11-01T10:00:00Z",
  owner: { avatar_url: `https://gitea.example.com/avatars/${id}` },
});

const base: Omit<GiteaConfig, "fetchImpl"> = {
  baseUrl: "https://gitea.example.com",
  token: "pat-token",
  orgs: ["acme"],
  webhookSecret: SECRET,
};

test("listConnectedRepos: every repo of every configured org, mapped to SourceRepo", async () => {
  const f = fakeGitea([
    { path: "/orgs/acme/repos", body: [orgRepo("acme/designiq-content", 7), orgRepo("acme/ops", 8)] },
  ]);
  const source = createGiteaSource({ ...base, fetchImpl: f });
  assert.equal(source.canEnumerate, true);
  const snap = await source.listConnectedRepos();
  assert.deepEqual(snap.repos.map((r) => r.fullName).sort(), ["acme/designiq-content", "acme/ops"]);
  assert.deepEqual([...snap.knownRefs], [1], "the PAT is THE one connection");
  assert.deepEqual([...snap.enumeratedRefs], [1]);
  assert.equal(snap.repos[0]!.providerId, 7);
  assert.equal(snap.repos[0]!.defaultBranch, "main");
  assert.equal(snap.repos[0]!.connectionRef, 1);
  assert.equal(snap.repos[0]!.pushedAt, "2026-11-01T10:00:00Z");
});

test("listConnectedRepos: no orgs configured → the token owner's own repos", async () => {
  const f = fakeGitea([{ path: "/user/repos", body: [orgRepo("petra/notes", 9)] }]);
  const source = createGiteaSource({ ...base, orgs: [], fetchImpl: f });
  const snap = await source.listConnectedRepos();
  assert.deepEqual(
    snap.repos.map((r) => r.fullName),
    ["petra/notes"],
  );
});

test("listConnectedRepos: a missing branch falls back to main", async () => {
  const repo = { ...orgRepo("acme/empty", 5) } as Record<string, unknown>;
  delete repo.default_branch;
  const f = fakeGitea([{ path: "/orgs/acme/repos", body: [repo] }]);
  const source = createGiteaSource({ ...base, fetchImpl: f });
  const snap = await source.listConnectedRepos();
  assert.equal(snap.repos[0]!.defaultBranch, "main");
});

test("checkUserPermission: Gitea levels map, owner→admin, 404→none", async () => {
  const f = fakeGitea([
    { path: "/repos/acme/ops/collaborators/petra/permission", body: { permission: "write" } },
    { path: "/repos/acme/ops/collaborators/owner/permission", body: { permission: "owner" } },
    { path: "/repos/acme/ops/collaborators/guest/permission", body: { permission: "read" } },
    { path: "/repos/acme/ops/collaborators/stranger/permission", status: 404, body: {} },
  ]);
  const source = createGiteaSource({ ...base, fetchImpl: f });
  assert.equal(await source.checkUserPermission(1, "petra", "acme/ops"), "write");
  assert.equal(await source.checkUserPermission(1, "owner", "acme/ops"), "admin");
  assert.equal(await source.checkUserPermission(1, "guest", "acme/ops"), "read");
  assert.equal(await source.checkUserPermission(1, "stranger", "acme/ops"), "none");
});

test("cloneToken returns the platform PAT", async () => {
  const source = createGiteaSource({ ...base, fetchImpl: fakeGitea([]) });
  assert.equal(await source.cloneToken(1), "pat-token");
  // the PAT can clone a statically registered fallback repo too (ref null)
  assert.equal(await source.cloneToken(null), "pat-token");
});

test("connectUrl: undefined — membership is org-side, webhooks resync", () => {
  const source = createGiteaSource({ ...base, fetchImpl: fakeGitea([]) });
  assert.equal(source.connectUrl(), undefined);
});

test("webhook verification: both Gitea signature forms, fail-closed, membership classification", () => {
  const source = createGiteaSource({ ...base, fetchImpl: fakeGitea([]) });
  const body = Buffer.from(JSON.stringify({ action: "added" }));
  const hex = createHmac("sha256", SECRET).update(body).digest("hex");

  // gitea-type webhook: X-Gitea-Signature (bare hex) + X-Gitea-Event
  const gitea = source.verifyWebhook({ "x-gitea-signature": hex, "x-gitea-event": "repository" }, body);
  assert.equal(gitea?.authentic, true);
  assert.equal(gitea?.membershipChanged, true);

  // github-type webhook in Gitea: X-Hub-Signature-256 ("sha256=hex") + X-GitHub-Event
  const hub = source.verifyWebhook({ "x-hub-signature-256": `sha256=${hex}`, "x-github-event": "organization" }, body);
  assert.equal(hub?.authentic, true);
  assert.equal(hub?.membershipChanged, true);

  // push events are authentic but not a membership change (workspace fetch covers them)
  const push = source.verifyWebhook({ "x-gitea-signature": hex, "x-gitea-event": "push" }, body);
  assert.equal(push?.membershipChanged, false);

  // wrong signature: rejected
  const bad = source.verifyWebhook({ "x-gitea-signature": "deadbeef", "x-gitea-event": "repository" }, body);
  assert.equal(bad?.authentic, false);

  // no secret configured: webhooks off (fail closed)
  const noSecret = createGiteaSource({ ...base, webhookSecret: undefined, fetchImpl: fakeGitea([]) });
  assert.equal(noSecret.verifyWebhook({ "x-gitea-event": "repository" }, body), undefined);
});

test("provider: push URL embeds the PAT; createPullRequest posts to the Gitea pulls API", async () => {
  let posted: { url: string; body: unknown; auth: string | null } | undefined;
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    posted = {
      url: String(input),
      body: JSON.parse(String(init?.body)),
      auth: (init?.headers as Record<string, string>)?.authorization ?? null,
    };
    return new Response(JSON.stringify({ html_url: "https://gitea.example.com/acme/ops/pulls/3", number: 3 }), {
      status: 201,
    });
  }) as typeof fetch;
  const provider = createGiteaProvider({ ...base, fetchImpl: f });

  assert.equal(provider.id, "gitea");
  assert.equal(provider.pushUrl("tok", "acme/ops"), "https://x-access-token:tok@gitea.example.com/acme/ops.git");

  const pr = await provider.createPullRequest("tok", "acme/ops", {
    branch: "release/x",
    base: "main",
    title: "Release",
    body: "notes",
  });
  assert.deepEqual(pr, { url: "https://gitea.example.com/acme/ops/pulls/3", number: 3 });
  assert.equal(posted!.url, "https://gitea.example.com/api/v1/repos/acme/ops/pulls");
  assert.equal(posted!.auth, "token tok");
  assert.deepEqual(posted!.body, { head: "release/x", base: "main", title: "Release", body: "notes" });
});
