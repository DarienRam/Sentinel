import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = ts.transpileModule(readFileSync(new URL("../lib/api.ts", import.meta.url), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 }
}).outputText;
const user = { id: 1, username: "synthetic", email: "synthetic@example.com", created_at: "2026-01-01" };
const account = csrf => ({ token_type: "cookie", user, csrf_token: csrf, expires_at: 2000000000 });
function harness(responses) {
  const calls = [], events = [];
  const context = {
    exports: {}, process: { env: {} }, Headers, Response, Event,
    window: { location: { hostname: "localhost" }, dispatchEvent: event => events.push(event.type),
      localStorage: { getItem() { throw new Error("Account credentials must never be read from localStorage"); },
        setItem() { throw new Error("Account credentials must never be persisted in localStorage"); } } },
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      const next = responses.shift();
      assert.ok(next, "Unexpected extra network request");
      assert.equal(new URL(url).pathname, next.path);
      assert.equal(options.credentials, "include");
      return new Response(next.status === 204 ? null : JSON.stringify(next.body ?? {}), { status: next.status });
    }
  };
  vm.runInNewContext(source, context);
  return { api: context.exports, calls, events };
}
const scan = { input_type: "message", raw_content: "Synthetic transport test." };

test("guest requests bootstrap cookies and CSRF without localStorage credentials", async () => {
  const h = harness([{ path: "/auth/session", status: 401 },
    { path: "/auth/anonymous-session", status: 200, body: { csrf_token: "anonymous", expires_at: 2000000000 } },
    { path: "/scans", status: 200, body: { id: 1 } }]);
  assert.equal((await h.api.createScan(scan)).id, 1);
  const headers = new Headers(h.calls[2].options.headers);
  assert.equal(headers.get("X-CSRF-Token"), "anonymous");
  assert.equal(headers.has("Authorization"), false);
});

test("account expiry never replays a scan under guest ownership", async () => {
  const h = harness([{ path: "/auth/session", status: 200, body: account("first") },
    { path: "/scans", status: 401, body: { detail: "Invalid or expired authentication token." } }]);
  await assert.rejects(h.api.createScan(scan));
  assert.equal(h.calls.length, 2);
  assert.deepEqual(h.events, ["sentinel:session-expired"]);
});

test("stale account CSRF restores the account and never bootstraps a guest", async () => {
  const h = harness([{ path: "/auth/session", status: 200, body: account("first") },
    { path: "/scans", status: 403, body: { detail: "CSRF validation failed." } },
    { path: "/auth/session", status: 200, body: account("second") },
    { path: "/scans", status: 200, body: { id: 2 } }]);
  assert.equal((await h.api.createScan(scan)).id, 2);
  assert.equal(new Headers(h.calls[3].options.headers).get("X-CSRF-Token"), "second");
});

test("security-service failure prevents silent guest downgrade", async () => {
  const h = harness([{ path: "/auth/session", status: 503 }]);
  await assert.rejects(h.api.createScan(scan));
  assert.equal(h.calls.length, 1);
});

test("failed logout keeps account state for retry", async () => {
  const h = harness([{ path: "/auth/session", status: 200, body: account("first") },
    { path: "/auth/logout", status: 503 }]);
  await assert.rejects(h.api.logoutUser());
  assert.equal((await h.api.fetchCurrentUser()).id, 1);
  assert.equal(h.calls.length, 2);
});

test("confirmed logout clears account state and permits a fresh guest scope", async () => {
  const h = harness([{ path: "/auth/session", status: 200, body: account("first") },
    { path: "/auth/logout", status: 204 },
    { path: "/auth/anonymous-session", status: 200, body: { csrf_token: "guest", expires_at: 2000000000 } },
    { path: "/scans", status: 200, body: { id: 3 } }]);
  await h.api.logoutUser();
  assert.equal(await h.api.fetchCurrentUser(), null);
  assert.equal((await h.api.createScan(scan)).id, 3);
});
