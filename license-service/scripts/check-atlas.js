import "dotenv/config";
import { MongoClient } from "mongodb";
import { ensureDatabaseIndexes } from "../src/database.js";

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("MONGODB_URI is not set. Configure it as a local process secret or in the hosting secret manager.");
  process.exit(2);
}
if (!/^mongodb(?:\+srv)?:\/\//i.test(uri)) {
  console.error("MONGODB_URI must use a MongoDB connection URI.");
  process.exit(2);
}

const dbName = process.env.MONGODB_DB || "sana_licenses";
const client = new MongoClient(uri, { tls: true, serverSelectionTimeoutMS: 10000, maxPoolSize: 2 });
try {
  await client.connect();
  const db = client.db(dbName);
  await db.command({ ping: 1 });
  const { licenseIndexes, auditIndexes } = await ensureDatabaseIndexes(db);
  console.log("Atlas TLS connection and ping: OK");
  console.log(`Database: ${dbName}`);
  console.log(`licenses indexes: ${licenseIndexes.map(index => index.name + (index.unique ? " (unique)" : "")).join(", ")}`);
  console.log(`audit_logs indexes: ${auditIndexes.map(index => index.name).join(", ")}`);
} catch (error) {
  console.error(`Atlas check failed (code: ${error.code || error.name || "unknown"}). The URI value was not printed.`);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
