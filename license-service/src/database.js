export async function ensureDatabaseIndexes(db) {
  const licenses = db.collection("licenses");
  const audit = db.collection("audit_logs");
  await Promise.all([
    licenses.createIndex({ keyHash: 1 }, { unique: true }),
    licenses.createIndex({ createdAt: -1 }),
    licenses.createIndex({ status: 1, createdAt: -1 }),
    audit.createIndex({ createdAt: -1, action: 1 }),
    audit.createIndex({ licenseId: 1, createdAt: -1 })
  ]);
  const [licenseIndexes, auditIndexes] = await Promise.all([licenses.indexes(), audit.indexes()]);
  return { licenseIndexes, auditIndexes };
}
