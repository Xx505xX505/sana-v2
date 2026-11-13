import test, { before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { ObjectId } from "mongodb";
import { createApp, verifyActivationToken } from "../src/app.js";

const ADMIN_KEY = "test-only-admin-key-that-is-long-enough-123";
const DEVICE_A = "a".repeat(64);
const DEVICE_B = "b".repeat(64);

function matches(doc, query) {
  for (const [key, expected] of Object.entries(query)) {
    if (key === "$or") {
      if (!expected.some(part => matches(doc, part))) return false;
      continue;
    }
    const actual = doc[key];
    if (expected && typeof expected === "object" && !(expected instanceof Date) && !(expected instanceof ObjectId)) {
      if (Object.hasOwn(expected, "$exists") && (actual !== undefined) !== expected.$exists) return false;
      if (Object.hasOwn(expected, "$ne") && (actual instanceof ObjectId ? String(actual) : actual) === expected.$ne) return false;
      continue;
    }
    if (expected instanceof ObjectId) {
      if (String(actual) !== String(expected)) return false;
    } else if (actual !== expected) return false;
  }
  return true;
}

class MemoryCollection {
  constructor(db) { this.db = db; }
  rows = [];
  async insertOne(value) {
    if (!this.db.available) throw new Error("simulated database outage");
    const doc = { ...value, _id: value._id || new ObjectId() };
    this.rows.push(doc);
    return { insertedId: doc._id };
  }
  async findOne(query) { if (!this.db.available) throw new Error("simulated database outage"); return this.rows.find(row => matches(row, query)) || null; }
  async findOneAndUpdate(query, update) {
    if (!this.db.available) throw new Error("simulated database outage");
    const doc = this.rows.find(row => matches(row, query));
    if (!doc) return null;
    Object.assign(doc, update.$set || {});
    return doc;
  }
  async updateOne(query, update) {
    if (!this.db.available) throw new Error("simulated database outage");
    const doc = this.rows.find(row => matches(row, query));
    if (!doc) return { modifiedCount: 0 };
    Object.assign(doc, update.$set || {});
    for (const key of Object.keys(update.$unset || {})) delete doc[key];
    return { modifiedCount: 1 };
  }
  find(query = {}) {
    let rows = this.rows.filter(row => matches(row, query));
    const cursor = {
      sort: sort => { const [key, direction] = Object.entries(sort)[0] || []; if (key) rows = rows.toSorted((a, b) => direction * (new Date(a[key]) - new Date(b[key]))); return cursor; },
      limit: count => { rows = rows.slice(0, count); return cursor; },
      toArray: async () => { if (!this.db.available) throw new Error("simulated database outage"); return rows; }
    };
    return cursor;
  }
}

class MemoryDb {
  collections = new Map();
  available = true;
  collection(name) { if (!this.collections.has(name)) this.collections.set(name, new MemoryCollection(this)); return this.collections.get(name); }
  async command() { if (!this.available) throw new Error("simulated database outage"); return { ok: 1 }; }
}

const signing = generateKeyPairSync("ed25519");
let db;
let server;
let baseUrl;

async function startApp({ limits } = {}) {
  const testDb = new MemoryDb();
  const app = createApp({ db: testDb, adminApiKey: ADMIN_KEY, ...signing, corsOrigins: ["http://tauri.localhost"], limits });
  const httpServer = createServer(app);
  await new Promise(resolve => httpServer.listen(0, "127.0.0.1", resolve));
  return { db: testDb, server: httpServer, url: `http://127.0.0.1:${httpServer.address().port}` };
}

async function request(path, { method = "GET", body, token = ADMIN_KEY, headers = {} } = {}) {
  const response = await fetch(baseUrl + path, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { response, data: await response.json() };
}

before(async () => {
  const started = await startApp({ limits: { activation: 1000, admin: 1000 } });
  db = started.db; server = started.server; baseUrl = started.url;
});
after(async () => { if (server) await new Promise(resolve => server.close(resolve)); });
beforeEach(() => { for (const collection of db.collections.values()) collection.rows.length = 0; db.available = true; });

test("health reports database readiness and fails when MongoDB is unavailable", async () => {
  let result = await request("/health", { token: null });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.database, "connected");
  db.available = false;
  result = await request("/health", { token: null });
  assert.equal(result.response.status, 500);
  assert.equal(result.data.error, "Internal server error. Check service and database health.");
});

test("admin endpoints require valid bearer authentication and validate issue counts", async () => {
  let result = await request("/v1/admin/licenses", { token: null });
  assert.equal(result.response.status, 401);
  result = await request("/v1/admin/licenses", { token: "wrong-secret" });
  assert.equal(result.response.status, 401);
  result = await request("/v1/admin/licenses", { method: "POST", body: { count: 51 } });
  assert.equal(result.response.status, 400);
  result = await request("/v1/admin/licenses", { method: "POST", body: { count: 1 } });
  assert.equal(result.response.status, 201);
  assert.equal(result.data.licenses.length, 1);
  assert.match(result.data.licenses[0].licenseKey, /^SANA-/);
  assert.ok(!Object.hasOwn(db.collection("licenses").rows[0], "licenseKey"));
});

test("issues up to 50 keys and records an audit event for each issued key", async () => {
  const result = await request("/v1/admin/licenses", { method: "POST", body: { count: 50 } });
  assert.equal(result.response.status, 201);
  assert.equal(result.data.licenses.length, 50);
  assert.equal(new Set(result.data.licenses.map(x => x.licenseKey)).size, 50);
  assert.equal(db.collection("audit_logs").rows.filter(x => x.action === "issue").length, 50);
});

test("activation binds one device, permits same-device reactivation, and signs verifiable time-limited tokens", async () => {
  const issued = await request("/v1/admin/licenses", { method: "POST", body: { count: 1 } });
  const license = issued.data.licenses[0];
  const body = { licenseKey: license.licenseKey, deviceId: DEVICE_A };
  let activation = await request("/v1/licenses/activate", { method: "POST", token: null, body });
  assert.equal(activation.response.status, 200);
  assert.equal((await request("/v1/licenses/activate", { method: "POST", token: null, body })).response.status, 200);
  assert.equal((await request("/v1/licenses/activate", { method: "POST", token: null, body: { ...body, deviceId: DEVICE_B } })).response.status, 403);
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body: { activationToken: activation.data.activationToken, deviceId: DEVICE_A } })).response.status, 200);
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body: { activationToken: activation.data.activationToken, deviceId: DEVICE_B } })).response.status, 403);
  const [headerPart, payloadPart, signaturePart] = activation.data.activationToken.split(".");
  const changedPayload = (payloadPart[0] === "A" ? "B" : "A") + payloadPart.slice(1);
  const tampered = `${headerPart}.${changedPayload}.${signaturePart}`;
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body: { activationToken: tampered, deviceId: DEVICE_A } })).response.status, 403);
  const remainingLifetime = Date.parse(activation.data.tokenExpiresAt) - Date.now();
  assert.ok(remainingLifetime > 7 * 86400000 - 1000 && remainingLifetime <= 7 * 86400000);
  assert.equal(verifyActivationToken(activation.data.activationToken, signing.publicKey, new Date(Date.parse(activation.data.tokenExpiresAt) + 1000)), null);
  const publicKey = await request("/v1/keys/activation", { token: null });
  assert.equal(publicKey.data.algorithm, "EdDSA");
  assert.match(publicKey.data.publicKey, /BEGIN PUBLIC KEY/);
});

test("revocation rejects new activation and online token verification", async () => {
  const issued = await request("/v1/admin/licenses", { method: "POST", body: { count: 1 } });
  const license = issued.data.licenses[0];
  const activation = await request("/v1/licenses/activate", { method: "POST", token: null, body: { licenseKey: license.licenseKey, deviceId: DEVICE_A } });
  const revoked = await request(`/v1/admin/licenses/${license.id}/revoke`, { method: "POST" });
  assert.equal(revoked.data.ok, true);
  assert.equal((await request("/v1/licenses/activate", { method: "POST", token: null, body: { licenseKey: license.licenseKey, deviceId: DEVICE_A } })).response.status, 403);
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body: { activationToken: activation.data.activationToken, deviceId: DEVICE_A } })).response.status, 403);
});

test("transfer requires explicit admin approval and reason, then allows binding a new device", async () => {
  const issued = await request("/v1/admin/licenses", { method: "POST", body: { count: 1 } });
  const license = issued.data.licenses[0];
  const oldActivation = await request("/v1/licenses/activate", { method: "POST", token: null, body: { licenseKey: license.licenseKey, deviceId: DEVICE_A } });
  assert.equal((await request(`/v1/admin/licenses/${license.id}/transfer`, { method: "POST", body: { approved: true } })).response.status, 400);
  const transferred = await request(`/v1/admin/licenses/${license.id}/transfer`, { method: "POST", body: { approved: true, reason: "Approved device replacement" } });
  assert.equal(transferred.data.ok, true);
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body: { activationToken: oldActivation.data.activationToken, deviceId: DEVICE_A } })).response.status, 403);
  assert.equal((await request("/v1/licenses/activate", { method: "POST", token: null, body: { licenseKey: license.licenseKey, deviceId: DEVICE_B } })).response.status, 200);
  const audit = await request("/v1/admin/audit");
  assert.ok(audit.data.events.some(event => event.action === "transfer" && event.details.approved === true));
});

test("license listing supports status and search filters and returns full device hash", async () => {
  const issued = await request("/v1/admin/licenses", { method: "POST", body: { count: 2 } });
  const active = issued.data.licenses[0];
  await request("/v1/licenses/activate", { method: "POST", token: null, body: { licenseKey: active.licenseKey, deviceId: DEVICE_A } });
  await request(`/v1/admin/licenses/${issued.data.licenses[1].id}/revoke`, { method: "POST" });
  const deviceHash = db.collection("licenses").rows.find(row => row.status === "active").deviceHash;
  const found = await request("/v1/admin/licenses?status=active&q=" + deviceHash.slice(0, 12));
  assert.equal(found.data.licenses.length, 1);
  assert.equal(found.data.licenses[0].deviceHash, deviceHash);
  assert.equal((await request("/v1/admin/licenses?status=bad")).response.status, 400);
});

test("database failures return a safe JSON error and malformed bodies are rejected", async () => {
  db.available = false;
  let result = await request("/v1/admin/licenses");
  assert.equal(result.response.status, 500);
  assert.equal(result.data.error, "Internal server error. Check service and database health.");
  db.available = true;
  const response = await fetch(baseUrl + "/v1/licenses/activate", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "Malformed JSON request body.");
});

test("activation endpoint rate limits repeated requests", async () => {
  const limited = await startApp({ limits: { activation: 2, admin: 20 } });
  try {
    for (let i = 0; i < 2; i++) {
      const response = await fetch(limited.url + "/v1/licenses/activate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ licenseKey: "invalid", deviceId: DEVICE_A }) });
      assert.equal(response.status, 400);
    }
    const limitedResponse = await fetch(limited.url + "/v1/licenses/activate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ licenseKey: "invalid", deviceId: DEVICE_A }) });
    assert.equal(limitedResponse.status, 429);
  } finally {
    await new Promise(resolve => limited.server.close(resolve));
  }
});
