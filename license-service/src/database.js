export async function ensureDatabaseIndexes(db) {
  const licenses = db.collection("licenses");
  const audit = db.collection("audit_logs");
  const challenges = db.collection("device_challenges");
  await Promise.all([
    licenses.createIndex({ keyHash: 1 }, { unique: true }),
    licenses.createIndex({ createdAt: -1 }),
    licenses.createIndex({ status: 1, createdAt: -1 }),
    audit.createIndex({ createdAt: -1, action: 1 }),
    audit.createIndex({ licenseId: 1, createdAt: -1 }),
    challenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })
  ]);
  const [licenseIndexes, auditIndexes, challengeIndexes] = await Promise.all([licenses.indexes(), audit.indexes(), challenges.indexes()]);
  return { licenseIndexes, auditIndexes, challengeIndexes };
}
