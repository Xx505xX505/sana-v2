# SANA License Service

Node.js/Express API for one-device SANA licenses. The repository contains no production credentials. See the root `CLIENT-INTEGRATION.md` for the end-client token and device-key contract.

## Local setup and tests

Requirements: Node.js 20+ and MongoDB for running the service. Run `npm ci`, copy `.env.example` to a local ignored `.env`, and provide local test/development values. `npm run check` checks JavaScript syntax; `npm test` runs the HTTP suite against an isolated in-memory MongoDB test double. The separate MongoDB integration test runs only when both `MONGODB_TEST_URI` and `MONGODB_TEST_DB` are set. The DB name must start with `sana_licenses_test_`, the URI path must match it, and the test URI must not equal `MONGODB_URI`; when `MONGODB_URI` is present, matching credentials and database names are rejected. Use a dedicated transaction-capable replica set and a test-only database user. If these variables are absent, the integration test is reported as skipped and no MongoDB URI is inferred from the service configuration.

To test a separately authorized Atlas test database, use `.\scripts\check-atlas.ps1`. It prompts for the URI without echoing it, uses it only in the child process, pings the selected database, and ensures the idempotent indexes. Do not use a production URI for this check. Startup also creates the indexes below.

## Configuration and secrets

- `MONGODB_URI`: MongoDB URI in the host's secret manager or local ignored `.env`.
- `MONGODB_DB`: database name; defaults to `sana_licenses`.
- `ADMIN_API_KEY`: random secret of at least 32 bytes. Keep it in the API secret manager and the operator's memory-only Manager session.
- `ACTIVATION_PRIVATE_KEY_B64`: base64 PKCS#8 Ed25519 private key, held only by the API secret manager.
- `CORS_ORIGIN`: comma-separated exact allowed browser origins, including the packaged Tauri origin `http://tauri.localhost`.
- `PORT`: host-provided HTTP port; defaults to 8080.

Never put a real credential in Git, the Manager package, API URL, logs, or chat. Use a least-privilege database user and restrict Atlas network access to the backend host. Render config in the repository specifies `plan: free`, `autoDeployTrigger: off`, and secrets with `sync: false`; no deployment is performed by this repository.

## Client endpoints

- `GET /health`: MongoDB ping/readiness.
- `GET /v1/keys/activation`: EdDSA algorithm, PEM public key, and base64url SPKI public key. Pin the public key in a trusted product release; never fetch and trust an arbitrary signing key at runtime.
- `POST /v1/licenses/challenge`: `{ "licenseKey": "SANA-…", "devicePublicKey": "<base64url SPKI DER>" }`; returns a single-use challenge id, nonce, exact UTF-8 signing message, and expiration.
- `POST /v1/licenses/activate`: `{ "licenseKey": "SANA-…", "devicePublicKey": "…", "challengeId": "…", "proof": "<Ed25519 signature, base64url>" }`; binds the license to the public-key fingerprint and returns a signed activation token. The key is stored as SHA-256 only.
- `POST /v1/licenses/verify/challenge`: `{ "activationToken": "…", "devicePublicKey": "…" }`; validates current status/binding and issues a fresh proof challenge.
- `POST /v1/licenses/verify`: `{ "activationToken": "…", "devicePublicKey": "…", "challengeId": "…", "proof": "…" }`; verifies device possession, current status, and one-use challenge, then returns a refreshed token.

Challenges expire after five minutes and are one-use. The EdDSA token contains issuer, audience, product/version, license id, device-key fingerprint, issue time, and expiry; token lifetime is at most seven days. Clients may validate a pinned-key token offline only until its signed expiration. This is software-key proof, not hardware attestation; an attacker able to run as the same Windows user may invoke DPAPI/key-use operations. Reinstalling the app for the same Windows user on the same installation preserves the `%LOCALAPPDATA%` DPAPI identity when its file remains. Loss of the Windows profile/key store requires administrator-approved transfer.

## Manager/admin endpoints

- `POST /v1/admin/licenses`: Bearer admin key and `{ "count": 1 }`, integer 1–50. Raw keys are returned once; only hashes are persisted.
- `GET /v1/admin/licenses?q=&status=`: latest 500 licenses, searchable by id or device fingerprint, optionally filtered by `active`/`revoked`.
- `POST /v1/admin/licenses/:id/revoke`: revoke an active license.
- `POST /v1/admin/licenses/:id/transfer`: requires `{ "approved": true, "reason": "..." }`; clears an existing binding and writes the reason to audit.
- `GET /v1/admin/audit?limit=100`: most recent 1–500 audit events.

Admin routes require `Authorization: Bearer <ADMIN_API_KEY>`. The Manager keeps the admin key in memory for the current app session only; it stores only the validated API URL in local storage. Do not ship an admin key in the desktop bundle.

## Storage, consistency, and protections

Indexes: unique `licenses.keyHash`, `licenses.createdAt`, `licenses.status + createdAt`, `audit_logs.createdAt + action`, `audit_logs.licenseId + createdAt`, and TTL `device_challenges.expiresAt`. License binding, challenge consumption, issue/revoke/transfer, and corresponding audit writes use MongoDB transactions. A transaction-capable MongoDB deployment (such as an Atlas replica set) is required. Challenge creation is transactional with its audit event. Rate limits cover client activation/verification routes and admin routes separately. Express uses Helmet, strict JSON size limit, exact-origin CORS, generic internal errors, and timing-safe admin key comparison. Request bodies, license keys, tokens, signatures, and secrets are not logged.

The test double exercises API behavior and simulated database failures, but does not prove Atlas availability, transaction behavior in a live cluster, or Render HTTPS deployment. This service is not production-ready until an authorized isolated staging database and deployed HTTPS API pass end-to-end tests.
