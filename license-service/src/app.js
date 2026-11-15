import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { ObjectId } from "mongodb";
import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";

const KEY_PATTERN = /^SANA-(?:[A-HJ-NP-Z2-9]{5}-){3}[A-HJ-NP-Z2-9]{5}$/;
const DEVICE_KEY_HASH_PATTERN = /^[a-f0-9]{64}$/;
const CHALLENGE_ID_PATTERN = /^[A-Za-z0-9_-]{24}$/;
const TOKEN_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const sha256 = value => createHash("sha256").update(value).digest("hex");

export function importSigningKey(encodedPrivateKey) {
  if (typeof encodedPrivateKey !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encodedPrivateKey)) {
    throw new Error("ACTIVATION_PRIVATE_KEY_B64 must be canonical base64 PKCS#8 data.");
  }
  const der = Buffer.from(encodedPrivateKey, "base64");
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Activation signing key must be Ed25519.");
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && timingSafeEqual(left, right);
}

function makeKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const parts = [];
  while (parts.length < 4) {
    let part = "";
    while (part.length < 5) {
      const byte = randomBytes(1)[0];
      if (byte >= 256 - (256 % alphabet.length)) continue;
      part += alphabet[byte % alphabet.length];
    }
    parts.push(part);
  }
  return `SANA-${parts.join("-")}`;
}

function parseDevicePublicKey(value) {
  if (typeof value !== "string" || value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const der = Buffer.from(value, "base64url");
    if (der.toString("base64url") !== value) return null;
    const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
    if (publicKey.asymmetricKeyType !== "ed25519") return null;
    const canonical = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
    return { publicKey, encoded: canonical, fingerprint: sha256(Buffer.from(canonical, "base64url")) };
  } catch {
    return null;
  }
}

function parseDeviceProof(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value)) return null;
  const signature = Buffer.from(value, "base64url");
  return signature.length === 64 && signature.toString("base64url") === value ? signature : null;
}

function createChallenge(purpose, context, now) {
  const challengeId = randomBytes(18).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const message = `SANA-LICENSE-CHALLENGE:v1:${purpose}:${challengeId}:${nonce}`;
  return {
    document: {
      _id: challengeId, purpose, message, createdAt: now,
      expiresAt: new Date(now.getTime() + CHALLENGE_LIFETIME_MS), ...context
    },
    response: { challengeId, nonce, message, expiresAt: new Date(now.getTime() + CHALLENGE_LIFETIME_MS) }
  };
}

function verifyDeviceProof(publicKey, message, proof) {
  const signature = parseDeviceProof(proof);
  if (!signature) return false;
  try { return verify(null, Buffer.from(message, "utf8"), publicKey, signature); }
  catch { return false; }
}

function createActivationToken({ licenseId, deviceKeyHash, privateKey, now, lifetimeSeconds }) {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
  const issuedAt = Math.floor(now.getTime() / 1000);
  const payload = Buffer.from(JSON.stringify({
    sub: licenseId, dkh: deviceKeyHash, product: "SANA", v: 2,
    iss: "sana-license-service", aud: "sana", iat: issuedAt,
    exp: issuedAt + lifetimeSeconds
  })).toString("base64url");
  const input = `${header}.${payload}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString("base64url")}`;
}

export function verifyActivationToken(token, publicKey, now = new Date()) {
  if (typeof token !== "string" || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts;
  try {
    const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
    if (header.alg !== "EdDSA" || header.typ !== "JWT") return null;
    if (!verify(null, Buffer.from(`${headerPart}.${payloadPart}`), publicKey, Buffer.from(signaturePart, "base64url"))) return null;
    const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (payload.iss !== "sana-license-service" || payload.aud !== "sana" || payload.product !== "SANA" || payload.v !== 2) return null;
    if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.iat > nowSeconds + 60 || payload.exp <= nowSeconds) return null;
    if (payload.exp <= payload.iat || payload.exp - payload.iat > TOKEN_LIFETIME_SECONDS) return null;
    if (!ObjectId.isValid(payload.sub) || !DEVICE_KEY_HASH_PATTERN.test(payload.dkh || "")) return null;
    return payload;
  } catch {
    return null;
  }
}

export function createApp({ db, adminApiKey, privateKey, publicKey, runTransaction = async callback => callback(undefined), clock = () => new Date(), activationLifetimeSeconds = TOKEN_LIFETIME_SECONDS, corsOrigins = [], limits = {} }) {
  if (!db || !adminApiKey || Buffer.byteLength(adminApiKey) < 32 || !privateKey || !publicKey) {
    throw new Error("Database, 32-character admin key, and Ed25519 signing keys are required.");
  }
  if (!Number.isInteger(activationLifetimeSeconds) || activationLifetimeSeconds < 60 || activationLifetimeSeconds > TOKEN_LIFETIME_SECONDS) {
    throw new Error("Activation token lifetime must be from 60 seconds to 7 days.");
  }

  const app = express();
  const licenses = db.collection("licenses");
  const audit = db.collection("audit_logs");
  const challenges = db.collection("device_challenges");
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(express.json({ limit: "16kb", strict: true }));
  app.use(cors({
    origin(origin, callback) {
      if (!origin || corsOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS_ORIGIN_REJECTED"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"]
  }));

  const rateLimitHandler = (_req, res) => res.status(429).json({ error: "Too many requests. Try again later." });
  const deviceLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: limits.activation ?? 20, standardHeaders: true, legacyHeaders: false, handler: rateLimitHandler });
  const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: limits.admin ?? 120, standardHeaders: true, legacyHeaders: false, handler: rateLimitHandler });
  const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  const auditAction = (action, licenseId, req, details = {}, actor = "admin", session) => audit.insertOne({
    action, licenseId: licenseId || null, createdAt: clock(), actor,
    ipHash: createHmac("sha256", adminApiKey).update(String(req.ip || "unknown")).digest("hex"), details
  }, session ? { session } : undefined);
  function adminOnly(req, res, next) {
    const match = /^Bearer ([^\s]+)$/i.exec(req.get("authorization") || "");
    if (!match || !safeEqual(match[1], adminApiKey)) return res.status(401).json({ error: "Unauthorized" });
    next();
  }
  const validLicenseId = value => /^[a-f\d]{24}$/i.test(value);

  app.get("/health", asyncRoute(async (_req, res) => {
    await db.command({ ping: 1 });
    res.json({ ok: true, service: "sana-license-service", database: "connected" });
  }));

  app.get("/v1/keys/activation", (_req, res) => {
    const publicKeySpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
    res.json({ algorithm: "EdDSA", publicKey: publicKey.export({ type: "spki", format: "pem" }), publicKeySpki });
  });

  app.post("/v1/licenses/challenge", deviceLimiter, asyncRoute(async (req, res) => {
    const licenseKey = String(req.body?.licenseKey || "").trim().toUpperCase();
    const device = parseDevicePublicKey(req.body?.devicePublicKey);
    if (!KEY_PATTERN.test(licenseKey) || !device) return res.status(400).json({ error: "Invalid license key or Ed25519 device public key." });
    const now = clock();
    const { document, response } = createChallenge("activate", {
      licenseKeyHash: sha256(licenseKey), deviceKeyHash: device.fingerprint
    }, now);
    await runTransaction(async session => {
      await challenges.insertOne(document, session ? { session } : undefined);
      await auditAction("activation_challenge", null, req, { licenseKeyHash: sha256(licenseKey), deviceKeyHash: device.fingerprint }, "license-client", session);
    });
    res.status(201).json(response);
  }));

  app.post("/v1/licenses/activate", deviceLimiter, asyncRoute(async (req, res) => {
    const licenseKey = String(req.body?.licenseKey || "").trim().toUpperCase();
    const device = parseDevicePublicKey(req.body?.devicePublicKey);
    const challengeId = String(req.body?.challengeId || "");
    if (!KEY_PATTERN.test(licenseKey) || !device || !CHALLENGE_ID_PATTERN.test(challengeId)) {
      return res.status(400).json({ error: "Invalid activation request." });
    }
    const now = clock();
    const licenseKeyHash = sha256(licenseKey);
    const result = await runTransaction(async session => {
      const challenge = await challenges.findOneAndDelete({
        _id: challengeId, purpose: "activate", licenseKeyHash, deviceKeyHash: device.fingerprint,
        expiresAt: { $gt: now }
      }, session ? { session } : undefined);
      if (!challenge) return { ok: false };
      if (!verifyDeviceProof(device.publicKey, challenge.message, req.body?.proof)) {
        await auditAction("activation_proof_rejected", null, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
        return { ok: false };
      }
      const license = await licenses.findOneAndUpdate(
        {
          keyHash: licenseKeyHash, status: "active",
          $or: [{ deviceKeyHash: null }, { deviceKeyHash: { $exists: false } }, { deviceKeyHash: device.fingerprint }]
        },
        { $set: { deviceKeyHash: device.fingerprint, devicePublicKey: device.encoded, activatedAt: now, lastVerifiedAt: now } },
        { returnDocument: "after", ...(session ? { session } : {}) }
      );
      if (!license) {
        await auditAction("activation_denied", null, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
        return { ok: false };
      }
      await auditAction("activate", String(license._id), req, { deviceKeyHash: device.fingerprint }, "license-client", session);
      return { ok: true, license };
    });
    if (!result.ok) return res.status(403).json({ error: "License or device proof is invalid, expired, revoked, or bound to another device." });
    const tokenExpiresAt = new Date((Math.floor(now.getTime() / 1000) + activationLifetimeSeconds) * 1000);
    res.json({
      ok: true,
      activationToken: createActivationToken({ licenseId: String(result.license._id), deviceKeyHash: device.fingerprint, privateKey, now, lifetimeSeconds: activationLifetimeSeconds }),
      activatedAt: result.license.activatedAt,
      tokenExpiresAt
    });
  }));

  app.post("/v1/licenses/verify/challenge", deviceLimiter, asyncRoute(async (req, res) => {
    const token = String(req.body?.activationToken || "");
    const device = parseDevicePublicKey(req.body?.devicePublicKey);
    const payload = verifyActivationToken(token, publicKey, clock());
    if (!payload || !device || !safeEqual(payload.dkh, device.fingerprint)) {
      return res.status(403).json({ error: "Activation token or device key is invalid or expired." });
    }
    const license = await licenses.findOne({ _id: new ObjectId(payload.sub), status: "active", deviceKeyHash: device.fingerprint }, { projection: { _id: 1 } });
    if (!license) return res.status(403).json({ error: "License is revoked or no longer assigned to this device." });
    const now = clock();
    const tokenHash = sha256(token);
    const { document, response } = createChallenge("verify", {
      licenseId: payload.sub, tokenHash, deviceKeyHash: device.fingerprint
    }, now);
    await runTransaction(async session => {
      await challenges.insertOne(document, session ? { session } : undefined);
      await auditAction("verification_challenge", payload.sub, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
    });
    res.status(201).json(response);
  }));

  app.post("/v1/licenses/verify", deviceLimiter, asyncRoute(async (req, res) => {
    const token = String(req.body?.activationToken || "");
    const challengeId = String(req.body?.challengeId || "");
    const device = parseDevicePublicKey(req.body?.devicePublicKey);
    const payload = verifyActivationToken(token, publicKey, clock());
    if (!payload || !device || !CHALLENGE_ID_PATTERN.test(challengeId) || !safeEqual(payload.dkh, device.fingerprint)) {
      return res.status(403).json({ ok: false, error: "Activation token or device proof is invalid or expired." });
    }
    const now = clock();
    const result = await runTransaction(async session => {
      const challenge = await challenges.findOneAndDelete({
        _id: challengeId, purpose: "verify", licenseId: payload.sub,
        tokenHash: sha256(token), deviceKeyHash: device.fingerprint, expiresAt: { $gt: now }
      }, session ? { session } : undefined);
      if (!challenge) return false;
      if (!verifyDeviceProof(device.publicKey, challenge.message, req.body?.proof)) {
        await auditAction("verification_proof_rejected", payload.sub, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
        return false;
      }
      const license = await licenses.findOneAndUpdate(
        { _id: new ObjectId(payload.sub), status: "active", deviceKeyHash: device.fingerprint },
        { $set: { lastVerifiedAt: now } },
        { returnDocument: "after", projection: { _id: 1 }, ...(session ? { session } : {}) }
      );
      if (!license) {
        await auditAction("verification_denied", payload.sub, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
        return false;
      }
      await auditAction("verify", payload.sub, req, { deviceKeyHash: device.fingerprint }, "license-client", session);
      return true;
    });
    if (!result) return res.status(403).json({ ok: false, error: "License is revoked or no longer assigned to this device." });
    const tokenExpiresAt = new Date((Math.floor(now.getTime() / 1000) + activationLifetimeSeconds) * 1000);
    res.json({
      ok: true,
      activationToken: createActivationToken({ licenseId: payload.sub, deviceKeyHash: device.fingerprint, privateKey, now, lifetimeSeconds: activationLifetimeSeconds }),
      expiresAt: new Date(payload.exp * 1000),
      tokenExpiresAt
    });
  }));

  app.post("/v1/admin/licenses", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    const count = req.body?.count ?? 1;
    if (typeof count !== "number" || !Number.isInteger(count) || count < 1 || count > 50) {
      return res.status(400).json({ error: "Count must be a number from 1 to 50." });
    }
    const created = await runTransaction(async session => {
      const issued = [];
      for (let i = 0; i < count; i++) {
        const key = makeKey();
        const doc = { keyHash: sha256(key), status: "active", createdAt: clock(), deviceKeyHash: null, devicePublicKey: null, activatedAt: null };
        const result = await licenses.insertOne(doc, session ? { session } : undefined);
        const id = String(result.insertedId);
        issued.push({ id, licenseKey: key, status: doc.status, createdAt: doc.createdAt });
        await auditAction("issue", id, req, {}, "admin", session);
      }
      return issued;
    });
    res.status(201).json({ licenses: created });
  }));

  app.get("/v1/admin/licenses", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    const q = String(req.query.q || "").trim().slice(0, 100).toLowerCase();
    const status = String(req.query.status || "").trim();
    if (status && !["active", "revoked"].includes(status)) return res.status(400).json({ error: "Invalid status filter." });
    const docs = await licenses.find(status ? { status } : {}, { projection: { keyHash: 0 } }).sort({ createdAt: -1 }).limit(500).toArray();
    const items = docs.map(x => ({
      id: String(x._id), status: x.status, createdAt: x.createdAt, activatedAt: x.activatedAt,
      deviceKeyHash: x.deviceKeyHash || null, revokedAt: x.revokedAt || null, transferredAt: x.transferredAt || null
    })).filter(x => !q || [x.id, x.status, x.deviceKeyHash].some(v => String(v || "").toLowerCase().includes(q)));
    res.json({ licenses: items });
  }));

  app.post("/v1/admin/licenses/:id/revoke", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    if (!validLicenseId(req.params.id)) return res.status(400).json({ error: "Invalid license id." });
    const result = await runTransaction(async session => {
      const updated = await licenses.updateOne(
        { _id: new ObjectId(req.params.id), status: "active" },
        { $set: { status: "revoked", revokedAt: clock() } },
        session ? { session } : undefined
      );
      if (updated.modifiedCount) await auditAction("revoke", req.params.id, req, {}, "admin", session);
      return updated;
    });
    res.json({ ok: result.modifiedCount === 1 });
  }));

  app.post("/v1/admin/licenses/:id/transfer", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    if (!validLicenseId(req.params.id)) return res.status(400).json({ error: "Invalid license id." });
    const reason = String(req.body?.reason || "").trim().slice(0, 500);
    if (req.body?.approved !== true || reason.length < 3) return res.status(400).json({ error: "Administrator approval and a reason are required for transfer." });
    const result = await runTransaction(async session => {
      const updated = await licenses.updateOne(
        { _id: new ObjectId(req.params.id), status: "active", deviceKeyHash: { $exists: true, $ne: null } },
        { $unset: { deviceKeyHash: "", devicePublicKey: "", activatedAt: "" }, $set: { transferredAt: clock() } },
        session ? { session } : undefined
      );
      if (updated.modifiedCount) await auditAction("transfer", req.params.id, req, { approved: true, reason }, "admin", session);
      return updated;
    });
    res.json({ ok: result.modifiedCount === 1 });
  }));

  app.get("/v1/admin/audit", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    const requested = Number(req.query.limit || 100);
    if (!Number.isInteger(requested) || requested < 1 || requested > 500) return res.status(400).json({ error: "Limit must be from 1 to 500." });
    const docs = await audit.find({}, { projection: { ipHash: 0 } }).sort({ createdAt: -1 }).limit(requested).toArray();
    res.json({ events: docs.map(x => ({ id: String(x._id), action: x.action, licenseId: x.licenseId, createdAt: x.createdAt, actor: x.actor, details: x.details || {} })) });
  }));

  app.use((err, _req, res, _next) => {
    if (res.headersSent) return;
    if (err?.message === "CORS_ORIGIN_REJECTED") return res.status(403).json({ error: "Origin not allowed." });
    if (err?.type === "entity.parse.failed") return res.status(400).json({ error: "Malformed JSON request body." });
    if (err?.type === "entity.too.large") return res.status(413).json({ error: "Request body is too large." });
    console.error("SANA License API request failed.");
    res.status(500).json({ error: "Internal server error. Check service and database health." });
  });
  return app;
}
