import test from "node:test";
import assert from "node:assert/strict";
import { ensureDatabaseIndexes } from "../src/database.js";

test("database setup ensures the license lookup and audit history indexes", async () => {
  const created = new Map();
  const db = {
    collection(name) {
      return {
        async createIndex(keys, options = {}) {
          const index = { name: Object.entries(keys).map(([key, order]) => `${key}_${order}`).join("_"), key: keys, ...options };
          if (!created.has(name)) created.set(name, []);
          created.get(name).push(index);
          return index.name;
        },
        async indexes() { return [{ name: "_id_" }, ...(created.get(name) || [])]; }
      };
    }
  };
  const indexes = await ensureDatabaseIndexes(db);
  assert.equal(indexes.licenseIndexes.length, 4);
  assert.equal(indexes.auditIndexes.length, 3);
  assert.equal(indexes.challengeIndexes.length, 2);
  assert.equal(created.get("licenses").find(index => index.key.keyHash).unique, true);
  assert.ok(created.get("audit_logs").some(index => index.key.licenseId && index.key.createdAt === -1));
  assert.equal(created.get("device_challenges").find(index => index.key.expiresAt).expireAfterSeconds, 0);
});
