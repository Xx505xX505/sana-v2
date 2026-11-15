import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";
import { createApp, importSigningKey } from "../src/app.js";
import { ensureDatabaseIndexes } from "../src/database.js";

const uri = process.env.MONGODB_TEST_URI || "";
const databaseName = process.env.MONGODB_TEST_DB || "";
const productionUri = process.env.MONGODB_URI || "";
const hasTestConfig = Boolean(uri && databaseName);
const hasPartialTestConfig = Boolean(uri) !== Boolean(databaseName);

function deviceIdentity() {
  const pair = generateKeyPairSync("ed25519");
  return {
    publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    prove: message => sign(null, Buffer.from(message, "utf8"), pair.privateKey).toString("base64url")
  };
}

test("Mongo integration configuration is either complete or absent", () => {
  assert.equal(hasPartialTestConfig, false, "Set both MONGODB_TEST_URI and MONGODB_TEST_DB, or neither.");
});

test("Mongo replica-set transactions issue and atomically bind a license", {
  skip: hasTestConfig ? false : "Set MONGODB_TEST_URI and MONGODB_TEST_DB to run against a dedicated test database."
}, async t => {
  assert.match(databaseName, /^sana_licenses_test_[a-z0-9_-]{1,48}$/i,
    "MONGODB_TEST_DB must be a dedicated database named sana_licenses_test_<suffix>.");
  const parsed = new URL(uri);
  assert.match(parsed.protocol, /^mongodb(?:\+srv)?:$/i, "MONGODB_TEST_URI must be a MongoDB URI.");
  assert.equal(decodeURIComponent(parsed.pathname.replace(/^\//, "")), databaseName,
    "The URI path must select exactly MONGODB_TEST_DB.");
  assert.notEqual(uri, productionUri, "The test URI must not equal MONGODB_URI.");
  if (productionUri) {
    const production = new URL(productionUri);
    assert.ok(parsed.username !== production.username || parsed.password !== production.password,
      "Use a test database credential, not the configured production credential.");
    assert.ok(decodeURIComponent(parsed.pathname.replace(/^\//, "")) !== decodeURIComponent(production.pathname.replace(/^\//, "")),
      "The integration database must not be the configured production database.");
  }

  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000, maxPoolSize: 5 });
  let server;
  let connected = false;
  const licenseIds = [];
  const licenseKeyHashes = [];
  const deviceKeyHashes = [];
  try {
    await client.connect();
    connected = true;
    const db = client.db(databaseName);
    await ensureDatabaseIndexes(db);
    const signing = generateKeyPairSync("ed25519");
    const signingKeyB64 = signing.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
    const { privateKey, publicKey } = importSigningKey(signingKeyB64);
    const adminApiKey = randomBytes(48).toString("base64url");
    const app = createApp({
      db,
      adminApiKey,
      privateKey,
      publicKey,
      corsOrigins: [],
      runTransaction: callback => {
        const session = client.startSession();
        return session.withTransaction(() => callback(session)).finally(() => session.endSession());
      }
    });
    server = createServer(app);
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const call = async (path, { method = "GET", body, admin = true } = {}) => {
      const response = await fetch(baseUrl + path, {
        method,
        headers: {
          ...(admin ? { Authorization: `Bearer ${adminApiKey}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" })
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      return { response, data: await response.json() };
    };

    const issued = await call("/v1/admin/licenses", { method: "POST", body: { count: 1 } });
    assert.equal(issued.response.status, 201);
    const license = issued.data.licenses[0];
    licenseIds.push(license.id);
    const keyHash = createHash("sha256").update(license.licenseKey).digest("hex");
    licenseKeyHashes.push(keyHash);
    const storedByHash = await db.collection("licenses").findOne({ keyHash });
    assert.ok(storedByHash, "Issued license should be committed to MongoDB.");
    assert.equal(storedByHash.licenseKey, undefined, "MongoDB must not store the raw license key.");
    assert.equal(String(storedByHash._id), license.id);

    const devices = [deviceIdentity(), deviceIdentity()];
    deviceKeyHashes.push(...devices.map(device => createHash("sha256").update(Buffer.from(device.publicKey, "base64url")).digest("hex")));
    const activations = await Promise.all(devices.map(async device => {
      const challenge = await call("/v1/licenses/challenge", {
        method: "POST", admin: false, body: { licenseKey: license.licenseKey, devicePublicKey: device.publicKey }
      });
      assert.equal(challenge.response.status, 201);
      return call("/v1/licenses/activate", {
        method: "POST", admin: false,
        body: {
          licenseKey: license.licenseKey,
          devicePublicKey: device.publicKey,
          challengeId: challenge.data.challengeId,
          proof: device.prove(challenge.data.message)
        }
      });
    }));
    assert.deepEqual(activations.map(result => result.response.status).sort(), [200, 403],
      "Concurrent transactions must bind the license to only one device.");
    assert.equal(await db.collection("audit_logs").countDocuments({
      action: "activation_denied", "details.deviceKeyHash": { $in: deviceKeyHashes }
    }), 1, "The losing device attempt should have an audit event tied to this test run.");
    const afterActivation = await db.collection("licenses").findOne({ _id: storedByHash._id });
    assert.ok(devices.some(device => device.publicKey === afterActivation.devicePublicKey));

    const revoked = await call(`/v1/admin/licenses/${license.id}/revoke`, { method: "POST" });
    assert.equal(revoked.response.status, 200);
    assert.equal(revoked.data.ok, true);
    const afterRevoke = await db.collection("licenses").findOne({ _id: storedByHash._id });
    assert.equal(afterRevoke.status, "revoked");
    const auditCount = await db.collection("audit_logs").countDocuments({ licenseId: license.id });
    assert.ok(auditCount >= 3, "Issue, activation, and revocation audit records should commit with their actions.");
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    if (connected) {
      const db = client.db(databaseName);
      try {
        await db.collection("device_challenges").deleteMany({ licenseKeyHash: { $in: licenseKeyHashes } });
        if (licenseIds.length) await db.collection("licenses").deleteMany({ _id: { $in: licenseIds.map(id => new ObjectId(id)) } });
        await db.collection("audit_logs").deleteMany({ $or: [
          { licenseId: { $in: licenseIds } },
          { "details.licenseKeyHash": { $in: licenseKeyHashes } },
          { "details.deviceKeyHash": { $in: deviceKeyHashes } }
        ] });
      } finally {
        await client.close();
      }
    }
  }
});
