//! Windows device-key storage and Ed25519 proof helpers for SANA license clients.
//!
//! The private seed is persisted only as a Windows DPAPI-protected blob. It is
//! scoped to the current Windows user and computer; callers never receive the
//! seed through this API.

#[cfg(not(windows))]
compile_error!("sana-license-client-core currently supports Windows only");

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs, io, path::{Path, PathBuf}};
use zeroize::Zeroizing;

const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A per-Windows-user/device Ed25519 identity. It intentionally has no API to export private bytes.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    store_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationClaims {
    pub license_id: String,
    pub device_key_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenValidationError { Malformed, Unsupported, BadSignature, Expired, WrongDevice }

/// Verifies the service's compact EdDSA token with a pinned SPKI public key.
pub fn verify_activation_token(
    token: &str,
    server_public_key_spki_base64url: &str,
    expected_device_fingerprint: &str,
    now_epoch_seconds: u64,
) -> Result<ActivationClaims, TokenValidationError> {
    if token.len() > 4096 { return Err(TokenValidationError::Malformed); }
    let mut parts = token.split('.');
    let (Some(header_part), Some(payload_part), Some(signature_part), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(TokenValidationError::Malformed);
    };
    let header_bytes = URL_SAFE_NO_PAD.decode(header_part).map_err(|_| TokenValidationError::Malformed)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_part).map_err(|_| TokenValidationError::Malformed)?;
    let signature = URL_SAFE_NO_PAD.decode(signature_part).map_err(|_| TokenValidationError::Malformed)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| TokenValidationError::Malformed)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") || header.get("typ").and_then(|v| v.as_str()) != Some("JWT") {
        return Err(TokenValidationError::Unsupported);
    }
    let der = URL_SAFE_NO_PAD.decode(server_public_key_spki_base64url).map_err(|_| TokenValidationError::Malformed)?;
    if der.len() != SPKI_ED25519_PREFIX.len() + 32 || der[..SPKI_ED25519_PREFIX.len()] != SPKI_ED25519_PREFIX {
        return Err(TokenValidationError::Unsupported);
    }
    let key_bytes: [u8; 32] = der[SPKI_ED25519_PREFIX.len()..].try_into().map_err(|_| TokenValidationError::Malformed)?;
    let public_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| TokenValidationError::Malformed)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature).map_err(|_| TokenValidationError::Malformed)?;
    let signing_input = format!("{header_part}.{payload_part}");
    public_key.verify(signing_input.as_bytes(), &signature).map_err(|_| TokenValidationError::BadSignature)?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| TokenValidationError::Malformed)?;
    if payload.get("iss").and_then(|v| v.as_str()) != Some("sana-license-service")
        || payload.get("aud").and_then(|v| v.as_str()) != Some("sana")
        || payload.get("product").and_then(|v| v.as_str()) != Some("SANA")
        || payload.get("v").and_then(|v| v.as_u64()) != Some(2) {
        return Err(TokenValidationError::Unsupported);
    }
    let license_id = payload.get("sub").and_then(|v| v.as_str()).ok_or(TokenValidationError::Malformed)?;
    let device_key_hash = payload.get("dkh").and_then(|v| v.as_str()).ok_or(TokenValidationError::Malformed)?;
    let issued_at = payload.get("iat").and_then(|v| v.as_u64()).ok_or(TokenValidationError::Malformed)?;
    let expires_at = payload.get("exp").and_then(|v| v.as_u64()).ok_or(TokenValidationError::Malformed)?;
    if license_id.len() != 24 || !license_id.bytes().all(|b| b.is_ascii_hexdigit())
        || device_key_hash.len() != 64 || !device_key_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || expires_at <= issued_at || expires_at - issued_at > 7 * 24 * 60 * 60
        || issued_at > now_epoch_seconds.saturating_add(60) {
        return Err(TokenValidationError::Malformed);
    }
    if expires_at <= now_epoch_seconds { return Err(TokenValidationError::Expired); }
    if device_key_hash != expected_device_fingerprint { return Err(TokenValidationError::WrongDevice); }
    Ok(ActivationClaims { license_id: license_id.to_owned(), device_key_hash: device_key_hash.to_owned(), issued_at, expires_at })
}

impl DeviceIdentity {
    /// Loads an existing protected identity or creates it atomically at `path`.
    pub fn load_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Self::load_existing(path);
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let generated = SigningKey::generate(&mut OsRng);
        let seed = Zeroizing::new(generated.to_bytes());
        let encrypted = dpapi::protect(&seed[..])?;
        let temp = temporary_path(&path);
        let write_result = (|| {
            use io::Write;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
            match fs::hard_link(&temp, &path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
                Err(error) => Err(error),
            }
        })();
        let _ = fs::remove_file(&temp);
        match write_result? {
            true => Ok(Self { signing_key: generated, store_path: path }),
            false => Self::load_existing(path),
        }
    }

    /// Uses `%LOCALAPPDATA%\SANA\License\device-key-v1.dpapi`.
    pub fn load_or_create_default() -> io::Result<Self> {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is unavailable"))?;
        Self::load_or_create(PathBuf::from(local_app_data).join("SANA").join("License").join("device-key-v1.dpapi"))
    }

    fn load_existing(path: PathBuf) -> io::Result<Self> {
        let encrypted = fs::read(&path)?;
        let plaintext = Zeroizing::new(dpapi::unprotect(&encrypted)?);
        let seed: [u8; 32] = plaintext.as_slice().try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Protected device key has an invalid length"))?;
        Ok(Self { signing_key: SigningKey::from_bytes(&seed), store_path: path })
    }

    /// DER SubjectPublicKeyInfo encoded as unpadded base64url for the API.
    pub fn public_key(&self) -> String {
        let mut der = Vec::with_capacity(SPKI_ED25519_PREFIX.len() + 32);
        der.extend_from_slice(&SPKI_ED25519_PREFIX);
        der.extend_from_slice(&self.signing_key.verifying_key().to_bytes());
        URL_SAFE_NO_PAD.encode(der)
    }

    /// SHA-256 fingerprint of the canonical DER public key.
    pub fn fingerprint(&self) -> String {
        let mut der = Vec::with_capacity(SPKI_ED25519_PREFIX.len() + 32);
        der.extend_from_slice(&SPKI_ED25519_PREFIX);
        der.extend_from_slice(&self.signing_key.verifying_key().to_bytes());
        hex(&Sha256::digest(der))
    }

    /// Signs the exact UTF-8 challenge message returned by the API.
    pub fn sign_challenge(&self, message: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.sign(message.as_bytes()).to_bytes())
    }

    /// Protects cached activation data (such as the signed token) using the same Windows user/machine DPAPI scope.
    pub fn protect_local_blob(&self, value: &[u8]) -> io::Result<Vec<u8>> { dpapi::protect(value) }

    /// Restores a blob protected by `protect_local_blob`; it fails for a different DPAPI user/device context.
    pub fn unprotect_local_blob(&self, protected: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(dpapi::unprotect(protected)?))
    }

    /// Returns only the path to the encrypted file, never key material.
    pub fn protected_store_path(&self) -> &Path { &self.store_path }
}

fn temporary_path(path: &Path) -> PathBuf {
    let salt = URL_SAFE_NO_PAD.encode(rand_core::OsRng.next_u64().to_le_bytes());
    let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("device-key");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), salt))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(windows)]
mod dpapi {
    use std::{ffi::c_void, io, ptr};
    use zeroize::Zeroizing;

    #[repr(C)]
    struct DataBlob { cb_data: u32, pb_data: *mut u8 }

    #[link(name = "Crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(input: *const DataBlob, description: *const u16, entropy: *const DataBlob,
            reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut DataBlob) -> i32;
        fn CryptUnprotectData(input: *const DataBlob, description: *mut *mut u16, entropy: *const DataBlob,
            reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut DataBlob) -> i32;
    }

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const ENTROPY: &[u8] = b"SANA-License-DeviceKey-v1";

    pub fn protect(plaintext: &[u8]) -> io::Result<Vec<u8>> { transform(plaintext, true) }
    pub fn unprotect(ciphertext: &[u8]) -> io::Result<Vec<u8>> { transform(ciphertext, false) }

    fn transform(input_bytes: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
        if input_bytes.is_empty() || input_bytes.len() > u32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid DPAPI data size"));
        }
        let input = DataBlob { cb_data: input_bytes.len() as u32, pb_data: input_bytes.as_ptr() as *mut u8 };
        let entropy = DataBlob { cb_data: ENTROPY.len() as u32, pb_data: ENTROPY.as_ptr() as *mut u8 };
        let mut output = DataBlob { cb_data: 0, pb_data: ptr::null_mut() };
        let success = unsafe {
            if encrypt {
                CryptProtectData(&input, ptr::null(), &entropy, ptr::null_mut(), ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null_mut(), ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if success == 0 {
            let code = unsafe { GetLastError() } as i32;
            return Err(io::Error::from_raw_os_error(code));
        }
        if output.pb_data.is_null() || output.cb_data == 0 {
            if !output.pb_data.is_null() { unsafe { LocalFree(output.pb_data.cast::<c_void>()); } }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DPAPI returned empty data"));
        }
        let output_len = output.cb_data as usize;
        let bytes = unsafe { std::slice::from_raw_parts(output.pb_data, output_len) };
        let result = Zeroizing::new(bytes.to_vec());
        if !encrypt {
            for offset in 0..output_len {
                unsafe { ptr::write_volatile(output.pb_data.add(offset), 0); }
            }
        }
        unsafe { LocalFree(output.pb_data.cast::<c_void>()); }
        Ok(result.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn temp_store() -> PathBuf {
        std::env::temp_dir().join(format!("sana-device-test-{}-{}.dpapi", std::process::id(), rand_core::OsRng.next_u64()))
    }

    #[test]
    fn reinstall_loads_the_same_user_machine_protected_identity() {
        let path = temp_store();
        let first = DeviceIdentity::load_or_create(&path).unwrap();
        let public_key = first.public_key();
        let fingerprint = first.fingerprint();
        let protected = fs::read(&path).unwrap();
        assert!(!protected.is_empty());
        assert!(!protected.windows(32).any(|window| window == first.signing_key.to_bytes()));
        drop(first);

        let restored = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(restored.public_key(), public_key);
        assert_eq!(restored.fingerprint(), fingerprint);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn challenge_proof_verifies_with_the_advertised_public_key() {
        let path = temp_store();
        let identity = DeviceIdentity::load_or_create(&path).unwrap();
        let challenge = "SANA-LICENSE-CHALLENGE:v1:activate:test-nonce";
        let signature = URL_SAFE_NO_PAD.decode(identity.sign_challenge(challenge)).unwrap();
        let der = URL_SAFE_NO_PAD.decode(identity.public_key()).unwrap();
        let key_bytes: [u8; 32] = der[SPKI_ED25519_PREFIX.len()..].try_into().unwrap();
        let public_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        public_key.verify(challenge.as_bytes(), &ed25519_dalek::Signature::from_slice(&signature).unwrap()).unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn corrupted_protected_store_is_rejected() {
        let path = temp_store();
        let _identity = DeviceIdentity::load_or_create(&path).unwrap();
        let mut encrypted = fs::read(&path).unwrap();
        encrypted[0] ^= 0xff;
        fs::write(&path, encrypted).unwrap();
        assert!(DeviceIdentity::load_or_create(&path).is_err());
        let _ = fs::remove_file(path);
    }

    fn signed_token(device_hash: &str, issued_at: u64, expires_at: u64) -> (String, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::json!({
            "sub": "0123456789abcdef01234567", "dkh": device_hash,
            "product": "SANA", "v": 2, "iss": "sana-license-service",
            "aud": "sana", "iat": issued_at, "exp": expires_at
        }).to_string());
        let input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(input.as_bytes()).to_bytes());
        let token = format!("{input}.{signature}");
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&signing_key.verifying_key().to_bytes());
        (token, URL_SAFE_NO_PAD.encode(der))
    }

    #[test]
    fn activation_token_signature_expiry_and_device_binding_are_enforced() {
        let hash = "ab".repeat(32);
        let (token, public_key) = signed_token(&hash, 1_000, 2_000);
        let claims = verify_activation_token(&token, &public_key, &hash, 1_500).unwrap();
        assert_eq!(claims.license_id, "0123456789abcdef01234567");
        assert_eq!(verify_activation_token(&token, &public_key, &"cd".repeat(32), 1_500), Err(TokenValidationError::WrongDevice));
        assert_eq!(verify_activation_token(&token, &public_key, &hash, 2_000), Err(TokenValidationError::Expired));

        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        parts[1].push('A');
        assert_eq!(verify_activation_token(&parts.join("."), &public_key, &hash, 1_500), Err(TokenValidationError::BadSignature));
        let (expired, expired_key) = signed_token(&hash, 1_000, 1_100);
        assert_eq!(verify_activation_token(&expired, &expired_key, &hash, 1_500), Err(TokenValidationError::Expired));
    }

    #[test]
    fn cached_activation_token_can_be_protected_without_plaintext_storage() {
        let path = temp_store();
        let identity = DeviceIdentity::load_or_create(&path).unwrap();
        let token = b"signed-test-token-payload";
        let protected = identity.protect_local_blob(token).unwrap();
        assert!(!protected.windows(token.len()).any(|window| window == token));
        let restored = identity.unprotect_local_blob(&protected).unwrap();
        assert_eq!(&restored[..], token);
        let _ = fs::remove_file(path);
    }
}
