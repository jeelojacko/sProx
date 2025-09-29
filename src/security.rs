use std::collections::HashMap;
use std::net::IpAddr;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::form_urlencoded::{self, Serializer};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Errors that can be emitted by the security helpers.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("HMAC keys must not be empty")]
    EmptyHmacKey,

    #[error("URL `{0}` is missing a host component and cannot be signed")]
    MissingHost(String),

    #[error("URL `{0}` must be absolute to be signed")]
    RelativeUrl(String),

    #[error("Signature parameter `{0}` is missing from the URL")]
    MissingSignature(String),

    #[error("failed to decode signature: {0}")]
    SignatureDecoding(#[from] base64::DecodeError),

    #[error("encryption key must be exactly 32 bytes (256 bits)")]
    InvalidEncryptionKeyLength,

    #[error("encrypted payload is malformed")]
    MalformedEncryptedPayload,

    #[error("encryption failure")]
    EncryptionFailure,

    #[error("decryption failure")]
    DecryptionFailure,

    #[error("failed to parse IP network `{entry}`: {source}")]
    InvalidIpNetwork {
        entry: String,
        #[source]
        source: ipnet::AddrParseError,
    },
}

/// Performs a constant-time comparison between the expected and provided API passwords.
///
/// The comparison operates on raw bytes to ensure that timing side-channels do not leak
/// information about the stored password.
pub fn verify_api_password(expected: impl AsRef<[u8]>, provided: impl AsRef<[u8]>) -> bool {
    let expected = expected.as_ref();
    let provided = provided.as_ref();

    if expected.is_empty() || provided.is_empty() {
        return false;
    }

    if expected.len() != provided.len() {
        return false;
    }

    expected.ct_eq(provided).into()
}

/// Signs the provided URL using an HMAC-SHA256 signature.
///
/// The signature is attached to the URL using `signature_param`. Any pre-existing value for the
/// parameter is removed before the signature is recomputed.
pub fn sign_url(url: &Url, secret: &[u8], signature_param: &str) -> Result<Url, SecurityError> {
    if secret.is_empty() {
        return Err(SecurityError::EmptyHmacKey);
    }

    let canonical = canonicalize_url(url, signature_param)?;

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).map_err(|_| SecurityError::EmptyHmacKey)?;
    mac.update(canonical.as_bytes());
    let signature = mac.finalize().into_bytes();
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);

    let mut signed_url = url.clone();
    let mut params: Vec<(String, String)> = signed_url
        .query_pairs()
        .filter(|(k, _)| k != signature_param)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    params.push((signature_param.to_owned(), encoded_signature));
    params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut serializer = Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    signed_url.set_query(Some(&query));

    Ok(signed_url)
}

/// Verifies that the URL contains a valid HMAC-SHA256 signature.
pub fn verify_signed_url(
    url: &Url,
    secret: &[u8],
    signature_param: &str,
) -> Result<bool, SecurityError> {
    if secret.is_empty() {
        return Err(SecurityError::EmptyHmacKey);
    }

    let provided_signature = url
        .query_pairs()
        .find(|(key, _)| key == signature_param)
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| SecurityError::MissingSignature(signature_param.to_owned()))?;

    let canonical = canonicalize_url(url, signature_param)?;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).map_err(|_| SecurityError::EmptyHmacKey)?;
    mac.update(canonical.as_bytes());
    let expected_signature = mac.finalize().into_bytes();

    let provided_bytes = URL_SAFE_NO_PAD.decode(provided_signature.as_bytes())?;
    if provided_bytes.len() != expected_signature.len() {
        return Ok(false);
    }

    Ok(expected_signature.as_slice().ct_eq(&provided_bytes).into())
}

/// Encrypts query parameters using AES-256-GCM.
///
/// The parameters are encoded as a deterministic query string before encryption. The returned
/// value is a URL-safe base64 blob that concatenates the nonce and ciphertext. Callers that do
/// not wish to encrypt parameters can opt to skip this helper entirely.
pub fn encrypt_query_params(
    params: &HashMap<String, String>,
    key: &[u8],
) -> Result<String, SecurityError> {
    let cipher = build_cipher(key)?;
    let nonce = generate_nonce();
    let plaintext = canonicalize_params(params);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| SecurityError::EncryptionFailure)?;

    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(combined))
}

/// Decrypts a payload produced by [`encrypt_query_params`].
///
/// The decrypted query string is parsed back into a key-value map.
pub fn decrypt_query_params(
    payload: &str,
    key: &[u8],
) -> Result<HashMap<String, String>, SecurityError> {
    let cipher = build_cipher(key)?;
    let blob = URL_SAFE_NO_PAD.decode(payload.as_bytes())?;

    if blob.len() < 12 {
        return Err(SecurityError::MalformedEncryptedPayload);
    }

    let (nonce, ciphertext) = blob.split_at(12);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| SecurityError::DecryptionFailure)?;

    let mut map = HashMap::new();
    for (key, value) in form_urlencoded::parse(&plaintext) {
        map.insert(key.into_owned(), value.into_owned());
    }

    Ok(map)
}

/// Parses a list of CIDR strings into an allowlist representation.
pub fn parse_ip_allowlist(entries: &[String]) -> Result<Vec<IpNet>, SecurityError> {
    entries
        .iter()
        .map(|entry| {
            entry
                .parse()
                .map_err(|source| SecurityError::InvalidIpNetwork {
                    entry: entry.clone(),
                    source,
                })
        })
        .collect()
}

/// Returns `true` when the provided IP is allowed by the given allowlist.
///
/// An empty allowlist means that all clients are allowed.
pub fn ip_in_allowlist(ip: IpAddr, allowlist: &[IpNet]) -> bool {
    if allowlist.is_empty() {
        return true;
    }

    allowlist.iter().any(|network| network.contains(&ip))
}

fn canonicalize_url(url: &Url, signature_param: &str) -> Result<String, SecurityError> {
    if !url.has_host() {
        return Err(SecurityError::MissingHost(url.to_string()));
    }

    if url.cannot_be_a_base() {
        return Err(SecurityError::RelativeUrl(url.to_string()));
    }

    let mut canonical = String::new();
    canonical.push_str(url.scheme());
    canonical.push_str("://");
    canonical.push_str(url.host_str().expect("host presence validated above"));
    if let Some(port) = url.port() {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    canonical.push_str(url.path());

    let mut params: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != signature_param)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    if !params.is_empty() {
        let mut serializer = Serializer::new(String::new());
        for (key, value) in params {
            serializer.append_pair(&key, &value);
        }
        let query = serializer.finish();
        canonical.push('?');
        canonical.push_str(&query);
    }

    if let Some(fragment) = url.fragment() {
        canonical.push('#');
        canonical.push_str(fragment);
    }

    Ok(canonical)
}

fn canonicalize_params(params: &HashMap<String, String>) -> String {
    let mut sorted: Vec<_> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));

    let mut serializer = Serializer::new(String::new());
    for (key, value) in sorted {
        serializer.append_pair(key, value);
    }

    serializer.finish()
}

fn build_cipher(key: &[u8]) -> Result<Aes256Gcm, SecurityError> {
    if key.len() != 32 {
        return Err(SecurityError::InvalidEncryptionKeyLength);
    }

    Aes256Gcm::new_from_slice(key).map_err(|_| SecurityError::InvalidEncryptionKeyLength)
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_passwords_compare_in_constant_time() {
        assert!(verify_api_password("supersecret", "supersecret"));
        assert!(!verify_api_password("supersecret", "wrong"));
        assert!(!verify_api_password("", "supersecret"));
        assert!(!verify_api_password("supersecret", ""));
    }

    #[test]
    fn url_signing_round_trip() {
        let url = Url::parse("https://example.com/v1/resource?foo=bar&baz=qux").unwrap();
        let secret = b"topsecretkey";

        let signed = sign_url(&url, secret, "sig").expect("signing should succeed");
        assert!(verify_signed_url(&signed, secret, "sig").expect("verification should succeed"));

        let tampered = Url::parse(&format!("{}&foo=evil", signed)).unwrap();
        assert!(!verify_signed_url(&tampered, secret, "sig").unwrap());
    }

    #[test]
    fn parameter_encryption_round_trip() {
        let mut params = HashMap::new();
        params.insert("token".to_string(), "abc123".to_string());
        params.insert("exp".to_string(), "3600".to_string());
        let key = [42u8; 32];

        let encrypted = encrypt_query_params(&params, &key).expect("encryption should succeed");
        let decrypted = decrypt_query_params(&encrypted, &key).expect("decryption should succeed");

        assert_eq!(params, decrypted);
    }

    #[test]
    fn ip_allowlist_helpers() {
        let entries = vec!["192.168.1.0/24".to_string(), "10.0.0.1/32".to_string()];
        let allowlist = parse_ip_allowlist(&entries).expect("parsing should succeed");

        assert!(ip_in_allowlist("192.168.1.42".parse().unwrap(), &allowlist));
        assert!(ip_in_allowlist("10.0.0.1".parse().unwrap(), &allowlist));
        assert!(!ip_in_allowlist("172.16.0.1".parse().unwrap(), &allowlist));
    }
}
