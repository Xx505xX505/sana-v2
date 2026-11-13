import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { ObjectId } from "mongodb";
import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";

const KEY_PATTERN = /^SANA-(?:[A-HJ-NP-Z2-9]{5}-){3}[A-HJ-NP-Z2-9]{5}$/;
const DEVICE_PATTERN = /^[a-f0-9]{64}$/;
const sha256 = value => createHash("sha256").update(value).digest("hex");

export function importSigningKey(encodedPrivateKey) {
  if (!encodedPrivateKey) throw new Error("ACTIVATION_PRIVATE_KEY_B64 is required.");
  let der;
  try { der = Buffer.from(encodedPrivateKey, "base64"); }
  catch { throw new Error("ACTIVATION_PRIVATE_KEY_B64 must be valid base64."); }
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

function createActivationToken({ licenseId, deviceHash, privateKey, now, lifetimeSeconds }) {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
  const issuedAt = Math.floor(now.getTime() / 1000);
  const payload = Buffer.from(JSON.stringify({
    sub: licenseId, dh: deviceHash, product: "SANA", v: 1,
    iss: "sana-license-service", aud: "sana", iat: issuedAt,
    exp: issuedAt + lifetimeSeconds
  })).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = sign(null, Buffer.from(input), privateKey).toString("base64url");
  return `${input}.${signature}`;
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
    if (payload.iss !== "sana-license-service" || payload.aud !== "sana" || payload.product !== "SANA" || payload.v !== 1) return null;
    if (typeof payload.exp !== "number" || payload.exp <= nowSeconds || typeof payload.iat !== "number" || payload.iat > nowSeconds + 60) return null;
    if (!ObjectId.isValid(payload.sub) || !DEVICE_PATTERN.test(payload.dh || "")) return null;
    return payload;
  } catch {
    return null;
  }
}

export function createApp({ db, adminApiKey, privateKey, publicKey, runTransaction = async callback => callback(undefined), clock = () => new Date(), activationLifetimeSeconds = 7 * 24 * 60 * 60, corsOrigins = [], limits = {} }) {
  if (!db || !adminApiKey || Buffer.byteLength(adminApiKey) < 32 || !privateKey || !publicKey) {
    throw new Error("Database, 32-character admin key, and Ed25519 signing keys are required.");
  }
  const app = express();
  const licenses = db.collection("licenses");
  const audit = db.collection("audit_logs");
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
  const activationLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: limits.activation ?? 10, standardHeaders: true, legacyHeaders: false, handler: rateLimitHandler });
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

  app.get("/health", asyncRoute(async (_req, res) => {
    await db.command({ ping: 1 });
    res.json({ ok: true, service: "sana-license-service", database: "connected" });
  }));

  app.get("/v1/keys/activation", (_req, res) => {
    res.json({ algorithm: "EdDSA", publicKey: publicKey.export({ type: "spki", format: "pem" }) });
  });

  app.post("/v1/licenses/activate", activationLimiter, asyncRoute(async (req, res) => {
    const key = String(req.body?.licenseKey || "").trim().toUpperCase();
    const deviceId = String(req.body?.deviceId || "");
    if (!KEY_PATTERN.test(key) || !DEVICE_PATTERN.test(deviceId)) {
      return res.status(400).json({ error: "Invalid license key or device identifier." });
    }
    const deviceHash = sha256(deviceId);
    const now = clock();
    const license = await runTransaction(async session => {
      const updated = await licenses.findOneAndUpdate(
        { keyHash: sha256(key), status: "active", $or: [{ deviceHash: null }, { deviceHash: { $exists: false } }, { deviceHash }] },
        { $set: { deviceHash, activatedAt: now, lastVerifiedAt: now } },
        { returnDocument: "after", ...(session ? { session } : {}) }
      );
      if (updated) await auditAction("activate", String(updated._id), req, { deviceHash }, "license-client", session);
      return updated;
    });
    if (!license) return res.status(403).json({ error: "License is invalid, revoked, or assigned to another device." });
    const tokenExpiresAt = new Date((Math.floor(now.getTime() / 1000) + activationLifetimeSeconds) * 1000);
    res.json({
      ok: true,
      activationToken: createActivationToken({ licenseId: String(license._id), deviceHash, privateKey, now, lifetimeSeconds: activationLifetimeSeconds }),
      activatedAt: license.activatedAt,
      tokenExpiresAt
    });
  }));

  app.post("/v1/licenses/verify", activationLimiter, asyncRoute(async (req, res) => {
    const deviceId = String(req.body?.deviceId || "");
    const payload = verifyActivationToken(req.body?.activationToken, publicKey, clock());
    if (!payload || !DEVICE_PATTERN.test(deviceId) || !safeEqual(payload.dh, sha256(deviceId))) {
      return res.status(403).json({ ok: false, error: "Activation token is invalid, expired, or belongs to another device." });
    }
    const license = await licenses.findOne({ _id: new ObjectId(payload.sub), status: "active", deviceHash: payload.dh }, { projection: { _id: 1 } });
    if (!license) return res.status(403).json({ ok: false, error: "License is revoked or no longer assigned to this device." });
    res.json({ ok: true, expiresAt: new Date(payload.exp * 1000) });
  }));

  app.post("/v1/admin/licenses", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    const count = Number(req.body?.count ?? 1);
    if (!Number.isInteger(count) || count < 1 || count > 50) return res.status(400).json({ error: "Count must be an integer from 1 to 50." });
    const created = await runTransaction(async session => {
      const issued = [];
      for (let i = 0; i < count; i++) {
        const key = makeKey();
        const doc = { keyHash: sha256(key), status: "active", createdAt: clock(), deviceHash: null, activatedAt: null };
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
    const q = String(req.query.q || "").trim().slice(0, 100);
    const status = String(req.query.status || "").trim();
    if (status && !["active", "revoked"].includes(status)) return res.status(400).json({ error: "Invalid status filter." });
    const filter = status ? { status } : {};
    const docs = await licenses.find(filter, { projection: { keyHash: 0 } }).sort({ createdAt: -1 }).limit(500).toArray();
    const query = q.toLowerCase();
    const items = docs.map(x => ({
      id: String(x._id), status: x.status, createdAt: x.createdAt, activatedAt: x.activatedAt,
      deviceHash: x.deviceHash || null, revokedAt: x.revokedAt || null, transferredAt: x.transferredAt || null
    })).filter(x => !query || [x.id, x.status, x.deviceHash].some(v => String(v || "").toLowerCase().includes(query)));
    res.json({ licenses: items });
  }));

  app.post("/v1/admin/licenses/:id/revoke", adminLimiter, adminOnly, asyncRoute(async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid license id." });
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
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid license id." });
    const reason = String(req.body?.reason || "").trim().slice(0, 500);
    if (req.body?.approved !== true || reason.length < 3) return res.status(400).json({ error: "Administrator approval and a reason are required for transfer." });
    const result = await runTransaction(async session => {
      const updated = await licenses.updateOne(
        { _id: new ObjectId(req.params.id), status: "active", deviceHash: { $exists: true, $ne: null } },
        { $unset: { deviceHash: "", activatedAt: "" }, $set: { transferredAt: clock() } },
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
