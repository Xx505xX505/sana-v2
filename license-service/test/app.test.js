import test, { after, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";
import { ObjectId } from "mongodb";
import { createApp, verifyActivationToken } from "../src/app.js";

const ADMIN_KEY = "test-only-admin-key-that-is-long-enough-123";
const DEVICE_A = makeIdentity();
const DEVICE_B = makeIdentity();

function makeIdentity() {
  const pair = generateKeyPairSync("ed25519");
  const devicePublicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  return { ...pair, devicePublicKey, prove: message => sign(null, Buffer.from(message), pair.privateKey).toString("base64url") };
}

function equalValue(a, b) {
  if (a instanceof ObjectId || b instanceof ObjectId) return String(a) === String(b);
  if (a instanceof Date || b instanceof Date) return new Date(a).getTime() === new Date(b).getTime();
  return a === b;
}

function matches(doc, query) {
  for (const [key, expected] of Object.entries(query)) {
    if (key === "$or") {
      if (!expected.some(part => matches(doc, part))) return false;
      continue;
    }
    const actual = doc[key];
    if (expected && typeof expected === "object" && !(expected instanceof Date) && !(expected instanceof ObjectId)) {
      if (Object.hasOwn(expected, "$exists") && (actual !== undefined) !== expected.$exists) return false;
      if (Object.hasOwn(expected, "$ne") && equalValue(actual, expected.$ne)) return false;
      if (Object.hasOwn(expected, "$gt") && !(new Date(actual).getTime() > new Date(expected.$gt).getTime())) return false;
      continue;
    }
    if (!equalValue(actual, expected)) return false;
  }
  return true;
}

function cloneValue(value) {
  if (value instanceof Date) return new Date(value);
  if (value instanceof ObjectId) return new ObjectId(String(value));
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneValue(item)]));
  return value;
}

class MemoryCollection {
  constructor(db) { this.db = db; }
  rows = [];
  ensureAvailable() { if (!this.db.available) throw new Error("simulated database outage"); }
  async insertOne(value) {
    this.ensureAvailable();
    const doc = { ...value, _id: value._id || new ObjectId() };
    this.rows.push(doc);
    return { insertedId: doc._id };
  }
  async findOne(query) { this.ensureAvailable(); return this.rows.find(row => matches(row, query)) || null; }
  async findOneAndUpdate(query, update) {
    this.ensureAvailable();
    const doc = this.rows.find(row => matches(row, query));
    if (!doc) return null;
    Object.assign(doc, update.$set || {});
    return doc;
  }
  async findOneAndDelete(query) {
    this.ensureAvailable();
    const index = this.rows.findIndex(row => matches(row, query));
    if (index < 0) return null;
    return this.rows.splice(index, 1)[0];
  }
  async updateOne(query, update) {
    this.ensureAvailable();
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
      toArray: async () => { this.ensureAvailable(); return rows; }
    };
    return cursor;
  }
}

class MemoryDb {
  collections = new Map();
  available = true;
  transactionTail = Promise.resolve();
  collection(name) { if (!this.collections.has(name)) this.collections.set(name, new MemoryCollection(this)); return this.collections.get(name); }
  async command() { if (!this.available) throw new Error("simulated database outage"); return { ok: 1 }; }
  async transaction(callback) {
    let release;
    const previous = this.transactionTail;
    this.transactionTail = new Promise(resolve => { release = resolve; });
    await previous;
    const snapshot = new Map([...this.collections].map(([name, collection]) => [name, collection.rows.map(cloneValue)]));
    try { return await callback(undefined); }
    catch (error) {
      for (const [name, rows] of snapshot) this.collections.get(name).rows = rows;
      throw error;
    } finally { release(); }
  }
}

const signing = generateKeyPairSync("ed25519");
let db;
let server;
let baseUrl;
let currentTime;

async function startApp({ limits } = {}) {
  const testDb = new MemoryDb();
  const app = createApp({
    db: testDb, adminApiKey: ADMIN_KEY, ...signing, corsOrigins: ["http://tauri.localhost"],
    runTransaction: callback => testDb.transaction(callback), clock: () => new Date(currentTime), limits
  });
  const httpServer = createServer(app);
  await new Promise(resolve => httpServer.listen(0, "127.0.0.1", resolve));
  return { db: testDb, server: httpServer, url: `http://127.0.0.1:${httpServer.address().port}` };
}

async function request(path, { method = "GET", body, token = ADMIN_KEY, headers = {}, url = baseUrl } = {}) {
  const response = await fetch(url + path, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  let data;
  try { data = await response.json(); } catch { data = null; }
  return { response, data };
}

async function issue(count = 1) {
  return request("/v1/admin/licenses", { method: "POST", body: { count } });
}

async function activate(licenseKey, identity = DEVICE_A, { signatureIdentity = identity } = {}) {
  const challenge = await request("/v1/licenses/challenge", {
    method: "POST", token: null, body: { licenseKey, devicePublicKey: identity.devicePublicKey }
  });
  if (challenge.response.status !== 201) return challenge;
  return request("/v1/licenses/activate", {
    method: "POST", token: null,
    body: {
      licenseKey, devicePublicKey: identity.devicePublicKey, challengeId: challenge.data.challengeId,
      proof: signatureIdentity.prove(challenge.data.message)
    }
  });
}

async function verifyOnline(token, identity = DEVICE_A) {
  const challenge = await request("/v1/licenses/verify/challenge", {
    method: "POST", token: null, body: { activationToken: token, devicePublicKey: identity.devicePublicKey }
  });
  if (challenge.response.status !== 201) return challenge;
  return request("/v1/licenses/verify", {
    method: "POST", token: null,
    body: {
      activationToken: token, devicePublicKey: identity.devicePublicKey,
      challengeId: challenge.data.challengeId, proof: identity.prove(challenge.data.message)
    }
  });
}

before(async () => {
  currentTime = new Date("2026-01-01T00:00:00.000Z");
  const started = await startApp({ limits: { activation: 1000, admin: 1000 } });
  db = started.db; server = started.server; baseUrl = started.url;
});
after(async () => { if (server) await new Promise(resolve => server.close(resolve)); });
beforeEach(() => { for (const collection of db.collections.values()) collection.rows.length = 0; db.available = true; currentTime = new Date("2026-01-01T00:00:00.000Z"); });

test("health reports database readiness and safely handles MongoDB outage", async () => {
  let result = await request("/health", { token: null });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.database, "connected");
  db.available = false;
  result = await request("/health", { token: null });
  assert.equal(result.response.status, 500);
  assert.equal(result.data.error, "Internal server error. Check service and database health.");
});

test("CORS rejects non-allowlisted browser origins", async () => {
  const result = await request("/health", { token: null, headers: { Origin: "https://attacker.example" } });
  assert.equal(result.response.status, 403);
  assert.equal(result.data.error, "Origin not allowed.");
});

test("admin routes reject absent and incorrect bearer keys", async () => {
  assert.equal((await request("/v1/admin/licenses", { token: null })).response.status, 401);
  assert.equal((await request("/v1/admin/licenses", { token: "wrong-secret" })).response.status, 401);
  assert.equal((await request("/v1/admin/audit", { token: null })).response.status, 401);
});

test("issues one key, returns it once, and stores only its hash", async () => {
  const result = await issue();
  assert.equal(result.response.status, 201);
  assert.equal(result.data.licenses.length, 1);
  assert.match(result.data.licenses[0].licenseKey, /^SANA-/);
  assert.ok(!Object.hasOwn(db.collection("licenses").rows[0], "licenseKey"));
  assert.match(db.collection("licenses").rows[0].keyHash, /^[a-f0-9]{64}$/);
});

test("issues between one and fifty unique keys and rejects invalid counts", async () => {
  for (const count of [0, 51, "2", true, 2.5]) assert.equal((await request("/v1/admin/licenses", { method: "POST", body: { count } })).response.status, 400);
  const result = await issue(50);
  assert.equal(result.response.status, 201);
  assert.equal(result.data.licenses.length, 50);
  assert.equal(new Set(result.data.licenses.map(item => item.licenseKey)).size, 50);
  assert.equal(db.collection("audit_logs").rows.filter(event => event.action === "issue").length, 50);
});

test("activation requires a valid Ed25519 device public key", async () => {
  const result = await request("/v1/licenses/challenge", { method: "POST", token: null, body: { licenseKey: "SANA-AAAAA-AAAAA-AAAAA-AAAAA", devicePublicKey: "not-a-key" } });
  assert.equal(result.response.status, 400);
});

test("first activation and same-key reinstall succeed; another device is rejected", async () => {
  const license = (await issue()).data.licenses[0];
  const first = await activate(license.licenseKey, DEVICE_A);
  assert.equal(first.response.status, 200);
  const reinstall = await activate(license.licenseKey, DEVICE_A);
  assert.equal(reinstall.response.status, 200);
  assert.equal((await activate(license.licenseKey, DEVICE_B)).response.status, 403);
  const stored = db.collection("licenses").rows[0];
  assert.equal(stored.devicePublicKey, DEVICE_A.devicePublicKey);
  assert.ok(!("deviceId" in stored));
});

test("device challenge requires a proof from the private key and cannot be replayed", async () => {
  const license = (await issue()).data.licenses[0];
  const challenge = await request("/v1/licenses/challenge", { method: "POST", token: null, body: { licenseKey: license.licenseKey, devicePublicKey: DEVICE_A.devicePublicKey } });
  const rejected = await request("/v1/licenses/activate", {
    method: "POST", token: null,
    body: { licenseKey: license.licenseKey, devicePublicKey: DEVICE_A.devicePublicKey, challengeId: challenge.data.challengeId, proof: DEVICE_B.prove(challenge.data.message) }
  });
  assert.equal(rejected.response.status, 403);
  assert.equal((await request("/v1/licenses/activate", {
    method: "POST", token: null,
    body: { licenseKey: license.licenseKey, devicePublicKey: DEVICE_A.devicePublicKey, challengeId: challenge.data.challengeId, proof: DEVICE_A.prove(challenge.data.message) }
  })).response.status, 403);
});

test("activation challenges expire and are one-time", async () => {
  const license = (await issue()).data.licenses[0];
  const challenge = await request("/v1/licenses/challenge", { method: "POST", token: null, body: { licenseKey: license.licenseKey, devicePublicKey: DEVICE_A.devicePublicKey } });
  currentTime = new Date(currentTime.getTime() + 6 * 60 * 1000);
  const result = await request("/v1/licenses/activate", {
    method: "POST", token: null,
    body: { licenseKey: license.licenseKey, devicePublicKey: DEVICE_A.devicePublicKey, challengeId: challenge.data.challengeId, proof: DEVICE_A.prove(challenge.data.message) }
  });
  assert.equal(result.response.status, 403);
});

test("simultaneous activation attempts on two devices bind exactly one device", async () => {
  const license = (await issue()).data.licenses[0];
  const [left, right] = await Promise.all([activate(license.licenseKey, DEVICE_A), activate(license.licenseKey, DEVICE_B)]);
  assert.deepEqual([left.response.status, right.response.status].sort(), [200, 403]);
  assert.ok([DEVICE_A.devicePublicKey, DEVICE_B.devicePublicKey].includes(db.collection("licenses").rows[0].devicePublicKey));
});

test("EdDSA token validates offline metadata, rejects tampering and expiry", async () => {
  const license = (await issue()).data.licenses[0];
  const activated = await activate(license.licenseKey);
  assert.equal(activated.response.status, 200);
  const { token } = { token: activated.data.activationToken };
  const decodedPublicKey = signing.publicKey;
  assert.equal(verifyActivationToken(token, decodedPublicKey, currentTime).dkh.length, 64);
  const [headerPart, payloadPart, signaturePart] = token.split(".");
  const tamperedPayload = (payloadPart[0] === "A" ? "B" : "A") + payloadPart.slice(1);
  const tampered = `${headerPart}.${tamperedPayload}.${signaturePart}`;
  assert.equal(verifyActivationToken(tampered, decodedPublicKey, currentTime), null);
  currentTime = new Date(Date.parse(activated.data.tokenExpiresAt) + 1000);
  assert.equal(verifyActivationToken(token, decodedPublicKey, currentTime), null);
});

test("online verification proves the device key and rejects challenge replay", async () => {
  const license = (await issue()).data.licenses[0];
  const activated = await activate(license.licenseKey);
  const token = activated.data.activationToken;
  currentTime = new Date(currentTime.getTime() + 60 * 60 * 1000);
  const verified = await verifyOnline(token);
  assert.equal(verified.response.status, 200);
  assert.notEqual(verified.data.activationToken, token);
  assert.ok(Date.parse(verified.data.tokenExpiresAt) > Date.parse(activated.data.tokenExpiresAt));
  const challenge = await request("/v1/licenses/verify/challenge", { method: "POST", token: null, body: { activationToken: token, devicePublicKey: DEVICE_A.devicePublicKey } });
  const body = { activationToken: token, devicePublicKey: DEVICE_A.devicePublicKey, challengeId: challenge.data.challengeId, proof: DEVICE_A.prove(challenge.data.message) };
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body })).response.status, 200);
  assert.equal((await request("/v1/licenses/verify", { method: "POST", token: null, body })).response.status, 403);
});

test("revocation rejects activation and online/offline renewal", async () => {
  const license = (await issue()).data.licenses[0];
  const activated = await activate(license.licenseKey);
  assert.equal((await request(`/v1/admin/licenses/${license.id}/revoke`, { method: "POST" })).data.ok, true);
  assert.equal((await activate(license.licenseKey)).response.status, 403);
  assert.equal((await verifyOnline(activated.data.activationToken)).response.status, 403);
});

test("transfer requires approval and a reason, invalidates the old key, then permits a replacement", async () => {
  const license = (await issue()).data.licenses[0];
  const oldActivation = await activate(license.licenseKey, DEVICE_A);
  assert.equal((await request(`/v1/admin/licenses/${license.id}/transfer`, { method: "POST", body: { approved: true } })).response.status, 400);
  const moved = await request(`/v1/admin/licenses/${license.id}/transfer`, { method: "POST", body: { approved: true, reason: "Approved reinstall after profile loss" } });
  assert.equal(moved.data.ok, true);
  assert.equal((await verifyOnline(oldActivation.data.activationToken, DEVICE_A)).response.status, 403);
  assert.equal((await activate(license.licenseKey, DEVICE_B)).response.status, 200);
  const transferEvent = db.collection("audit_logs").rows.find(event => event.action === "transfer");
  assert.equal(transferEvent.details.approved, true);
});

test("audit endpoint records issuance, challenges, activation, verification and transfer events", async () => {
  const license = (await issue()).data.licenses[0];
  const activated = await activate(license.licenseKey);
  await verifyOnline(activated.data.activationToken);
  await request(`/v1/admin/licenses/${license.id}/transfer`, { method: "POST", body: { approved: true, reason: "Audit test" } });
  const result = await request("/v1/admin/audit?limit=100");
  const actions = result.data.events.map(event => event.action);
  for (const action of ["issue", "activation_challenge", "activate", "verification_challenge", "transfer"]) assert.ok(actions.includes(action), action);
  assert.ok(!("ipHash" in result.data.events[0]));
});

test("database failures return safe JSON and malformed/invalid ids are rejected", async () => {
  db.available = false;
  const result = await request("/v1/admin/licenses");
  assert.equal(result.response.status, 500);
  assert.equal(result.data.error, "Internal server error. Check service and database health.");
  db.available = true;
  const malformed = await fetch(baseUrl + "/v1/licenses/challenge", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" });
  assert.equal(malformed.status, 400);
  assert.equal((await request("/v1/admin/licenses/not-an-id/revoke", { method: "POST" })).response.status, 400);
});

test("device endpoints and admin endpoints enforce rate limits", async () => {
  const limited = await startApp({ limits: { activation: 2, admin: 2 } });
  try {
    const body = { licenseKey: "SANA-AAAAA-AAAAA-AAAAA-AAAAA", devicePublicKey: DEVICE_A.devicePublicKey };
    assert.equal((await request("/v1/licenses/challenge", { method: "POST", token: null, body, url: limited.url })).response.status, 201);
    assert.equal((await request("/v1/licenses/challenge", { method: "POST", token: null, body, url: limited.url })).response.status, 201);
    assert.equal((await request("/v1/licenses/challenge", { method: "POST", token: null, body, url: limited.url })).response.status, 429);
    assert.equal((await request("/v1/admin/licenses", { url: limited.url })).response.status, 200);
    assert.equal((await request("/v1/admin/licenses", { url: limited.url })).response.status, 200);
    assert.equal((await request("/v1/admin/licenses", { url: limited.url })).response.status, 429);
  } finally { await new Promise(resolve => limited.server.close(resolve)); }
});

test("the Ed25519 key loader rejects malformed or non-Ed25519 private keys", async () => {
  const { importSigningKey } = await import("../src/app.js");
  assert.throws(() => importSigningKey("not-base64!"));
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const der = rsa.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  assert.throws(() => importSigningKey(der), /Ed25519/);
});
