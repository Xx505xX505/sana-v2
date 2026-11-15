# SANA client license integration

This document describes the client contract for a future SANA IDE integration. It does not modify or integrate with SANA IDE. The `license-client-core` crate in this repository is a Windows-only reference implementation for device identity storage, challenge signing, and Ed25519 token verification.

## Security model and limits

The client creates an Ed25519 key pair on first activation. It stores the private seed only as a Windows DPAPI-protected blob at `%LOCALAPPDATA%\SANA\License\device-key-v1.dpapi`, scoped to the current Windows user and computer, and sends only the SPKI public key and signatures. Reinstalling the app for the same Windows profile on the same installation normally retains this file and identity. A new Windows installation, lost profile, or deleted key store creates a different identity; the administrator must approve a license transfer before another key can bind.

This is proof of possession of a protected software key, not hardware attestation. Malware or an attacker able to run as the same user (or an administrator) may invoke DPAPI or the client signing functionality. A determined attacker may also patch a client binary. The service prevents ordinary key sharing and copied-token use across different device keys; it cannot prove an unforgeable physical device identity.

## First activation

1. Call `GET /v1/keys/activation` over HTTPS and pin the returned `publicKeySpki` value (base64url DER SubjectPublicKeyInfo) in the product build. Never embed `ACTIVATION_PRIVATE_KEY_B64` or `ADMIN_API_KEY` in a client.
2. Load or create `DeviceIdentity` using `DeviceIdentity::load_or_create_default()`. Send `identity.public_key()` as `devicePublicKey` to `POST /v1/licenses/challenge` with the user's `licenseKey`.
3. Sign the returned exact UTF-8 `message` with `identity.sign_challenge(message)`. Submit `licenseKey`, `devicePublicKey`, `challengeId`, and `proof` to `POST /v1/licenses/activate`.
4. Store the returned activation token using `identity.protect_local_blob(token.as_bytes())`; do not store it as plaintext. The API stores only a hash of the license key and the bound device public key/fingerprint, not the raw license key.

Both activation endpoints require HTTPS in deployment. Challenges are one-use and expire after five minutes. Activation binds one key to the device public-key fingerprint. Repeating activation with the same key on the same device is allowed; a different device is rejected.

## Token validation and startup gate

Use `verify_activation_token(token, pinned_public_key_spki, identity.fingerprint(), now_epoch_seconds)` from `license-client-core`. It verifies the Ed25519 signature, expected issuer/audience/product/version, token lifetime (at most seven days), expiration, and device fingerprint. Start the licensed SANA product only after this validation succeeds. Treat malformed, expired, wrongly signed, or wrong-device tokens as invalid.

The compact token is a signed bearer artifact, not a replacement for device binding. Keep it protected at rest and do not log it. The public key is not secret; pin it through a trusted application update. Never accept a public key fetched at runtime without comparing it to the pinned key, because that would allow a network attacker to substitute a signing key.

## Online verification and renewal

1. Before the cached token expires (schedule renewal with a safety margin, such as 24 hours), send the token and `devicePublicKey` to `POST /v1/licenses/verify/challenge`.
2. Sign the returned exact `message` with the device identity.
3. Send `activationToken`, `devicePublicKey`, `challengeId`, and `proof` to `POST /v1/licenses/verify`.
4. On success, protect and replace the cached token with the returned refreshed `activationToken`.

Online verification checks current license status and binding in MongoDB. A revoked license or transferred binding is denied. The API refreshes a token only after a fresh device proof. The current API does not renew an already expired token; if it expires before renewal, require online recovery using the original license key on the same device, or administrator-approved transfer if the device identity was lost.

## Offline behavior

Permit offline startup only while a locally protected, correctly signed token remains unexpired and matches the locally loaded device identity. The maximum offline/revocation window is seven days from the last successful activation or online renewal. If the token expires while offline, fail closed and require a successful online verification; do not extend expiration locally. If the service is unavailable before token expiry, the product may continue offline under a documented grace policy bounded by the token's signed `exp`. Do not treat a timeout as proof that a license was revoked or as permission to renew.

Use `protect_local_blob` / `unprotect_local_blob` for the cached token. If DPAPI cannot decrypt the identity or token, require online recovery and an administrator-approved transfer when the original key is lost. Do not silently generate replacement identity material and reuse a license binding.

## API and administration summary

- Public/client: `GET /health`, `GET /v1/keys/activation`, `POST /v1/licenses/challenge`, `POST /v1/licenses/activate`, `POST /v1/licenses/verify/challenge`, `POST /v1/licenses/verify`.
- Manager/admin: `POST /v1/admin/licenses` (count 1–50), `GET /v1/admin/licenses`, `POST /v1/admin/licenses/:id/revoke`, `POST /v1/admin/licenses/:id/transfer` (requires explicit `approved: true` and reason), and `GET /v1/admin/audit`.
- Admin credentials belong only in the API host secret manager and the operator's in-memory Manager session. The packaged Manager must never contain an admin key. Configure the API URL locally in the Manager; do not place secrets in the URL or project files.

All state-changing license operations and their audit records require MongoDB transactions. Production integration therefore depends on a transaction-capable MongoDB deployment and a properly configured HTTPS API. This repository's tests use an isolated in-memory database double; they do not establish that a production Atlas cluster or Render service is reachable.
