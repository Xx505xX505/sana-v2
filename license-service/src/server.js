import "dotenv/config";
import { MongoClient } from "mongodb";
import { importSigningKey, createApp } from "./app.js";
import { ensureDatabaseIndexes } from "./database.js";

const required = ["MONGODB_URI", "ADMIN_API_KEY", "ACTIVATION_PRIVATE_KEY_B64"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Missing required environment variable: ${name}`);
}
if (Buffer.byteLength(process.env.ADMIN_API_KEY) < 32) throw new Error("ADMIN_API_KEY must be at least 32 characters.");

const signingKeys = importSigningKey(process.env.ACTIVATION_PRIVATE_KEY_B64);
if (!/^mongodb(?:\+srv)?:\/\//i.test(process.env.MONGODB_URI)) throw new Error("MONGODB_URI must use a MongoDB connection URI.");
const client = new MongoClient(process.env.MONGODB_URI, { tls: true, serverSelectionTimeoutMS: 10000, maxPoolSize: 20 });
await client.connect();
const db = client.db(process.env.MONGODB_DB || "sana_licenses");
await ensureDatabaseIndexes(db);

const corsOrigins = (process.env.CORS_ORIGIN || "").split(",").map(x => x.trim()).filter(Boolean);
const runTransaction = async callback => {
  const session = client.startSession();
  try { return await session.withTransaction(() => callback(session)); }
  finally { await session.endSession(); }
};
const app = createApp({ db, adminApiKey: process.env.ADMIN_API_KEY, ...signingKeys, corsOrigins, runTransaction });
const port = Number(process.env.PORT || 8080);
const server = app.listen(port, () => console.log(`SANA License API listening on ${port}`));

async function shutdown(signal) {
  console.log(`Received ${signal}; closing SANA License API.`);
  server.close(async () => {
    await client.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
