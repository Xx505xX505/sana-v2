# SANA License Service

Node.js API for one-device SANA licenses. The source tree contains no production credentials.

## Local development

Requirements: Node.js 20 or later and a reachable MongoDB deployment. Install packages with `npm ci`, copy `.env.example` to an ignored local `.env`, and configure the values below. `npm run check` validates JavaScript syntax and `npm test` runs the HTTP integration suite against an isolated in-memory MongoDB test double. Tests do not contact Atlas.

To test Atlas locally without putting its URI in the chat or a project file, run `.\scripts\check-atlas.ps1` in PowerShell. It asks for the URI in a hidden prompt, exposes it only to the child process temporarily, connects with TLS, pings the selected database, ensures the required indexes, and reports index names without printing the URI. It creates/ensures these idempotent indexes: unique `licenses.keyHash`, `licenses.createdAt`, `licenses.status + createdAt`, `audit_logs.createdAt + action`, and `audit_logs.licenseId + createdAt`. The service runs the same index check at startup.

## Required server secrets

- `MONGODB_URI`: Atlas connection string, stored only in the host secret manager or local ignored `.env`.
- `MONGODB_DB`: database name, for example `sana_licenses`.
- `ADMIN_API_KEY`: random value of at least 32 bytes. Keep it only in the manager operator's password manager/runtime session and the service secret manager.
- `ACTIVATION_PRIVATE_KEY_B64`: base64 encoded Ed25519 PKCS#8 private key. Store only in the service secret manager. The private signing key must never be distributed with the Manager or end-user application.
- `CORS_ORIGIN`: exact comma-separated origins allowed to call the service from the Manager, including the Tauri origin used by the packaged app.
- `PORT`: hosting provider port, if required.

The service exposes the matching Ed25519 public key at `GET /v1/keys/activation`. A product client can embed that public key and verify the compact EdDSA token offline until its `exp` time. Tokens last seven days; this is the maximum revocation/offline window. Online verification at `POST /v1/licenses/verify` also checks current database status and device binding. The SANA end-user client is outside this repository, so its offline token verification and license-gated startup are not implemented here.

Never put a real secret in Git, in the desktop bundle, in the API URL field, or in a chat. Rotate any credential that has ever been pasted into a chat or committed. Use a least-privilege Atlas database user and restrict Atlas network access to the backend host where possible.

## API

- `GET /health`: MongoDB readiness check.
- `GET /v1/keys/activation`: Ed25519 public key and algorithm.
- `POST /v1/licenses/activate`: `{ "licenseKey": "SANA-...", "deviceId": "<64 lowercase hex chars>" }`; returns an EdDSA JWT. An atomic update binds an unassigned key or reactivates it on the same device.
- `POST /v1/licenses/verify`: `{ "activationToken": "...", "deviceId": "..." }`; validates signature, expiry, device, and live license status.
- `POST /v1/admin/licenses`: Bearer admin key and `{ "count": 1 }`, with a count of 1–50. Raw keys are returned only once; only SHA-256 key hashes are stored.
- `GET /v1/admin/licenses?q=&status=`: latest 500 records, with status and device filters/search.
- `POST /v1/admin/licenses/:id/revoke`: revokes an active license.
- `POST /v1/admin/licenses/:id/transfer`: requires `{ "approved": true, "reason": "..." }` and clears the current binding.
- `GET /v1/admin/audit?limit=100`: most recent audited administrative and activation events.

Activation and management APIs are rate-limited. CORS is exact-origin allowlisted. Helmet security headers, strict request size limits, generic server errors, and timing-safe admin-key comparison are enabled. License changes and their audit entries use MongoDB transactions, so the service requires a transaction-capable MongoDB deployment such as an Atlas replica set. Logs do not contain request bodies or API keys. Audit records include action, license id, timestamp, actor class, and an HMAC-protected IP identifier.

## Deployment status

The root `render.yaml` prepares one Node web service rooted at this directory, uses `npm ci`/`npm start`, configures `/health`, pins the plan to `free`, disables automatic deploys, and marks `MONGODB_URI`, `ADMIN_API_KEY`, and `ACTIVATION_PRIVATE_KEY_B64` as secrets to enter in the Render Dashboard. It does not declare or create any MongoDB resource. The free plan prevents an accidental paid allocation; select a production plan only after separate approval. Before syncing the Blueprint, configure the existing Atlas cluster's network allowlist for the selected Render service. Keep the Atlas URI and signing/admin keys in Render's environment-secret settings, never in the Blueprint or Git.

This repository is prepared for deployment but is not deployed. A live HTTPS service, Atlas connection, production secrets, backups, alerting, and end-user client integration still require operator setup and approval. Do not claim production readiness until a real deployment and live Atlas end-to-end tests have passed. No production credentials are committed or included in the License Manager.
