use std::collections::HashSet;

#[cfg(feature = "drm")]
use axum::{
    extract::{Host, OriginalUri, Query, State},
    http::{header, HeaderValue},
    Json,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[cfg(feature = "drm")]
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
#[cfg(feature = "drm")]
use base64::Engine;
use roxmltree::Document;
use thiserror::Error;
use uuid::Uuid;

use crate::security::SecurityError;
#[cfg(feature = "drm")]
use crate::{
    security,
    state::{SecretsStore, SharedAppState},
};
#[cfg(feature = "drm")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "drm")]
use url::Url;

const CENC_NAMESPACE: &str = "urn:mpeg:cenc:2013";
#[cfg(feature = "drm")]
const CLEARKEY_SECRET_PREFIX: &str = "clearkey:";
#[cfg(feature = "drm")]
const CLEARKEY_SIGNING_SECRET: &str = "clearkey:signing_secret";
#[cfg(feature = "drm")]
const SIGNATURE_PARAM: &str = "sig";

/// Errors that can occur while processing DASH manifests or Clear Key requests.
#[derive(Debug, Error)]
pub enum DashError {
    #[error("failed to parse MPD document: {0}")]
    InvalidMpd(#[from] roxmltree::Error),

    #[error("manifest does not contain any ContentProtection@cenc:default_KID attributes")]
    MissingDefaultKids,

    #[error("found invalid default_KID value `{value}`: {source}")]
    InvalidDefaultKid {
        value: String,
        #[source]
        source: uuid::Error,
    },

    #[error("request is missing a signature parameter")]
    MissingSignature,

    #[error("failed to parse request URL: {0}")]
    InvalidRequestUrl(#[from] url::ParseError),

    #[error("failed to verify request signature: {0}")]
    SignatureValidation(#[from] SecurityError),

    #[error("request signature is invalid")]
    InvalidSignature,

    #[error("Clear Key signing secret is not configured")]
    MissingSigningSecret,

    #[error("requested key `{kid}` was not found")]
    KeyNotFound { kid: String },

    #[error("stored key for `{kid}` is not valid base64 or hexadecimal")]
    InvalidStoredKey { kid: String },

    #[error("stored key for `{kid}` is {length} bytes; expected 16 or 32 bytes")]
    InvalidKeyLength { kid: String, length: usize },

    #[error("provided KID `{kid}` could not be decoded")]
    InvalidKid { kid: String },
}

impl IntoResponse for DashError {
    fn into_response(self) -> Response {
        let status = match self {
            DashError::MissingSignature | DashError::InvalidSignature => StatusCode::UNAUTHORIZED,
            DashError::KeyNotFound { .. } => StatusCode::NOT_FOUND,
            DashError::InvalidKid { .. } => StatusCode::BAD_REQUEST,
            DashError::InvalidRequestUrl(_) | DashError::MissingSigningSecret => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            DashError::InvalidStoredKey { .. } | DashError::InvalidKeyLength { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            DashError::SignatureValidation(ref err)
                if matches!(
                    err,
                    SecurityError::MissingHost(_) | SecurityError::RelativeUrl(_)
                ) =>
            {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let message = self.to_string();
        (status, message).into_response()
    }
}

/// Extracts all `cenc:default_KID` values from a DASH MPD manifest.
///
/// The returned list is de-duplicated and preserves the discovery order.
pub fn extract_default_kids(mpd: &str) -> Result<Vec<Uuid>, DashError> {
    let document = Document::parse(mpd)?;
    let mut seen = HashSet::new();
    let mut kids = Vec::new();

    for node in document
        .descendants()
        .filter(|node| node.has_tag_name("ContentProtection"))
    {
        if let Some(attr) = node
            .attribute((CENC_NAMESPACE, "default_KID"))
            .or_else(|| node.attribute("cenc:default_KID"))
        {
            for value in attr.split(|c: char| c.is_whitespace() || c == ',') {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let parsed =
                    Uuid::parse_str(trimmed).map_err(|source| DashError::InvalidDefaultKid {
                        value: trimmed.to_string(),
                        source,
                    })?;

                if seen.insert(parsed) {
                    kids.push(parsed);
                }
            }
        }
    }

    if kids.is_empty() {
        return Err(DashError::MissingDefaultKids);
    }

    Ok(kids)
}

/// Axum handler returning a JSON Web Key Set containing the requested Clear Key.
///
/// Requests must include a `kid` query parameter identifying the key and a `sig`
/// parameter carrying the HMAC-SHA256 signature generated with the configured
/// signing secret. Only requests with valid signatures return key material.
#[cfg(feature = "drm")]
pub async fn clearkey_jwks(
    State(state): State<SharedAppState>,
    Host(host): Host,
    OriginalUri(original_uri): OriginalUri,
    Query(query): Query<ClearKeyQuery>,
) -> Result<Response, DashError> {
    if query.signature.trim().is_empty() {
        return Err(DashError::MissingSignature);
    }

    let kid_bytes = decode_kid(&query.kid)?;

    let signing_secret = {
        let secrets = state.with_current(|app| app.secrets());
        let mut secrets_guard = secrets.write().await;
        secrets_guard.purge_expired();
        let Some(secret) = secrets_guard.get(CLEARKEY_SIGNING_SECRET) else {
            return Err(DashError::MissingSigningSecret);
        };
        secret.value.clone()
    };

    let url = build_request_url(&host, &original_uri)?;
    let verified = security::verify_signed_url(&url, signing_secret.as_bytes(), SIGNATURE_PARAM)?;
    if !verified {
        return Err(DashError::InvalidSignature);
    }

    let (key_name, key_value) = {
        let secrets = state.with_current(|app| app.secrets());
        let mut secrets_guard = secrets.write().await;
        secrets_guard.purge_expired();
        find_key_entry(&mut secrets_guard, &query.kid, &kid_bytes)?
    };

    let key_bytes = decode_key_material(&key_value, &key_name)?;

    let jwk = JsonWebKey {
        kty: "oct",
        kid: URL_SAFE_NO_PAD.encode(kid_bytes),
        k: URL_SAFE_NO_PAD.encode(key_bytes.as_slice()),
    };
    let jwk_set = JsonWebKeySet { keys: vec![jwk] };

    let mut response = Json(jwk_set).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
    Ok(response)
}

#[cfg(feature = "drm")]
fn build_request_url(host: &str, original_uri: &axum::http::Uri) -> Result<Url, DashError> {
    let scheme = "https";
    let uri_str = original_uri.to_string();
    let full_url = format!("{}://{}{}", scheme, host, uri_str);
    let url = Url::parse(&full_url)?;
    Ok(url)
}

#[cfg(feature = "drm")]
#[derive(Debug, Deserialize)]
pub struct ClearKeyQuery {
    kid: String,
    #[serde(rename = "sig")]
    signature: String,
    #[serde(default)]
    _exp: Option<String>,
}

#[cfg(feature = "drm")]
fn decode_kid(kid: &str) -> Result<[u8; 16], DashError> {
    if let Ok(uuid) = Uuid::parse_str(kid) {
        return Ok(*uuid.as_bytes());
    }

    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(kid.as_bytes()) {
        return bytes.try_into().map_err(|_| DashError::InvalidKid {
            kid: kid.to_string(),
        });
    }

    if let Ok(bytes) = URL_SAFE.decode(kid.as_bytes()) {
        return bytes.try_into().map_err(|_| DashError::InvalidKid {
            kid: kid.to_string(),
        });
    }

    if let Ok(bytes) = STANDARD_NO_PAD.decode(kid.as_bytes()) {
        return bytes.try_into().map_err(|_| DashError::InvalidKid {
            kid: kid.to_string(),
        });
    }

    if let Ok(bytes) = STANDARD.decode(kid.as_bytes()) {
        return bytes.try_into().map_err(|_| DashError::InvalidKid {
            kid: kid.to_string(),
        });
    }

    if kid.len() == 32 && kid.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = [0u8; 16];
        for (i, chunk) in kid.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).map_err(|_| DashError::InvalidKid {
                kid: kid.to_string(),
            })?;
            bytes[i] = u8::from_str_radix(hex, 16).map_err(|_| DashError::InvalidKid {
                kid: kid.to_string(),
            })?;
        }
        return Ok(bytes);
    }

    Err(DashError::InvalidKid {
        kid: kid.to_string(),
    })
}

#[cfg(feature = "drm")]
fn find_key_entry(
    secrets: &mut SecretsStore,
    provided_kid: &str,
    kid_bytes: &[u8; 16],
) -> Result<(String, String), DashError> {
    let uuid = Uuid::from_bytes(*kid_bytes);
    let mut candidates = Vec::new();

    candidates.push(format!("{}{}", CLEARKEY_SECRET_PREFIX, provided_kid));
    candidates.push(format!("{}{}", CLEARKEY_SECRET_PREFIX, uuid.hyphenated()));
    candidates.push(format!("{}{}", CLEARKEY_SECRET_PREFIX, uuid.simple()));
    candidates.push(format!(
        "{}{}",
        CLEARKEY_SECRET_PREFIX,
        URL_SAFE_NO_PAD.encode(kid_bytes)
    ));

    candidates.push(format!(
        "{}{}",
        CLEARKEY_SECRET_PREFIX,
        URL_SAFE.encode(kid_bytes)
    ));

    candidates.push(format!(
        "{}{}",
        CLEARKEY_SECRET_PREFIX,
        STANDARD_NO_PAD.encode(kid_bytes)
    ));

    candidates.push(format!(
        "{}{}",
        CLEARKEY_SECRET_PREFIX,
        STANDARD.encode(kid_bytes)
    ));

    candidates.retain(|candidate| !candidate.ends_with(':'));
    candidates.dedup();

    for candidate in candidates {
        if let Some(entry) = secrets.get(&candidate) {
            return Ok((candidate, entry.value.clone()));
        }
    }

    Err(DashError::KeyNotFound {
        kid: provided_kid.to_string(),
    })
}

#[cfg(feature = "drm")]
fn decode_key_material(value: &str, key_name: &str) -> Result<Vec<u8>, DashError> {
    if matches!(value.len(), 32 | 64) && value.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for chunk in value.as_bytes().chunks(2) {
            let hex = std::str::from_utf8(chunk).map_err(|_| DashError::InvalidStoredKey {
                kid: key_name.to_string(),
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| DashError::InvalidStoredKey {
                kid: key_name.to_string(),
            })?;
            bytes.push(byte);
        }
        return Ok(bytes);
    }

    let decode_attempts = [
        URL_SAFE_NO_PAD.decode(value.as_bytes()),
        URL_SAFE.decode(value.as_bytes()),
        STANDARD_NO_PAD.decode(value.as_bytes()),
        STANDARD.decode(value.as_bytes()),
    ];

    if let Some(bytes) = decode_attempts.into_iter().flatten().next() {
        if !matches!(bytes.len(), 16 | 32) {
            return Err(DashError::InvalidKeyLength {
                kid: key_name.to_string(),
                length: bytes.len(),
            });
        }
        return Ok(bytes);
    }

    Err(DashError::InvalidStoredKey {
        kid: key_name.to_string(),
    })
}

#[cfg(feature = "drm")]
#[derive(Debug, Serialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[cfg(feature = "drm")]
#[derive(Debug, Serialize)]
struct JsonWebKey {
    kty: &'static str,
    kid: String,
    k: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_default_kids_from_manifest() {
        let mpd = "<MPD xmlns:cenc=\"urn:mpeg:cenc:2013\"><Period><AdaptationSet><ContentProtection cenc:default_KID=\"123e4567-e89b-12d3-a456-426614174000\" /><ContentProtection cenc:default_KID=\"123e4567-e89b-12d3-a456-426614174000\" /><ContentProtection cenc:default_KID=\"00000000-0000-0000-0000-000000000001 00000000-0000-0000-0000-000000000002\" /></AdaptationSet></Period></MPD>";

        let kids = extract_default_kids(mpd).expect("should extract kids");
        assert_eq!(kids.len(), 3);
        assert_eq!(
            kids[0],
            Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap()
        );
        assert_eq!(
            kids[1],
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(
            kids[2],
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()
        );
    }

    #[test]
    fn extracting_default_kids_requires_presence() {
        let mpd =
            r#"<MPD><Period><AdaptationSet><Representation /></AdaptationSet></Period></MPD>"#;
        let error = extract_default_kids(mpd).expect_err("should fail");
        assert!(matches!(error, DashError::MissingDefaultKids));
    }
}

#[cfg(all(test, feature = "drm"))]
mod drm_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::fmt::Write;
    use tower::ServiceExt;

    use crate::state::{AppState, SecretValue, SensitiveLoggingConfig};
    use std::time::Duration;

    #[tokio::test]
    async fn clearkey_handler_returns_jwk() {
        let kid_uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let kid_b64 = URL_SAFE_NO_PAD.encode(kid_uuid.as_bytes());
        let key_material = [0u8; 16];
        let key_b64 = URL_SAFE_NO_PAD.encode(key_material);
        let signing_secret = "super-secret".to_string();

        let state = SharedAppState::new(AppState::new());
        {
            let secrets_handle = state.with_current(|app| app.secrets());
            let mut secrets = secrets_handle.write().await;
            secrets.insert(
                CLEARKEY_SIGNING_SECRET.to_string(),
                SecretValue {
                    value: signing_secret.clone(),
                },
            );
            secrets.insert(
                format!("{}{}", CLEARKEY_SECRET_PREFIX, kid_uuid.hyphenated()),
                SecretValue {
                    value: key_b64.clone(),
                },
            );
        }

        let app = axum::Router::new()
            .route("/keys/clearkey", axum::routing::get(clearkey_jwks))
            .with_state(state.clone());

        let unsigned_url = Url::parse(&format!(
            "https://example.com/keys/clearkey?kid={}",
            kid_uuid.hyphenated()
        ))
        .unwrap();
        let signed_url =
            security::sign_url(&unsigned_url, signing_secret.as_bytes(), SIGNATURE_PARAM)
                .expect("signing should succeed");
        let request_uri = format!(
            "{}?{}",
            signed_url.path(),
            signed_url.query().expect("query expected")
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri(request_uri)
                    .header("host", "example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["keys"][0]["kid"], kid_b64);
        assert_eq!(parsed["keys"][0]["k"], key_b64);
    }

    #[tokio::test]
    async fn clearkey_handler_purges_expired_entries() {
        let kid_uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").unwrap();
        let signing_secret = "super-secret".to_string();
        let key_b64 = URL_SAFE_NO_PAD.encode([0u8; 16]);

        let state = SharedAppState::new(AppState::new());
        {
            let secrets_handle = state.with_current(|app| app.secrets());
            let mut secrets = secrets_handle.write().await;
            secrets.insert(
                CLEARKEY_SIGNING_SECRET.to_string(),
                SecretValue {
                    value: signing_secret.clone(),
                },
            );
            secrets.insert_with_ttl(
                format!("{}{}", CLEARKEY_SECRET_PREFIX, kid_uuid.hyphenated()),
                SecretValue {
                    value: key_b64.clone(),
                },
                Duration::from_millis(0),
            );
        }

        let app = axum::Router::new()
            .route("/keys/clearkey", axum::routing::get(clearkey_jwks))
            .with_state(state.clone());

        let unsigned_url = Url::parse(&format!(
            "https://example.com/keys/clearkey?kid={}",
            kid_uuid.hyphenated()
        ))
        .unwrap();
        let signed_url =
            security::sign_url(&unsigned_url, signing_secret.as_bytes(), SIGNATURE_PARAM)
                .expect("signing should succeed");
        let request_uri = format!(
            "{}?{}",
            signed_url.path(),
            signed_url.query().expect("query expected"),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri(request_uri)
                    .header("host", "example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let secrets_handle = state.with_current(|app| app.secrets());
        let mut secrets = secrets_handle.write().await;
        assert!(secrets
            .get(&format!(
                "{}{}",
                CLEARKEY_SECRET_PREFIX,
                kid_uuid.hyphenated()
            ))
            .is_none());
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn clearkey_logging_defaults_to_redaction() {
        use axum::http::Uri;

        let uri: Uri = "/keys/clearkey?kid=test-kid&sig=test-sig"
            .parse()
            .expect("uri should parse");
        let sanitized = crate::app::sanitize_request_uri(&uri, &SensitiveLoggingConfig::default());

        assert!(!sanitized.contains("test-kid"));
        assert!(!sanitized.contains("test-sig"));
        assert!(sanitized.contains("<redacted>"));
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn clearkey_logging_respects_redaction_toggle() {
        use axum::http::Uri;

        let uri: Uri = "/keys/clearkey?kid=test-kid&sig=test-sig"
            .parse()
            .expect("uri should parse");
        let mut config = SensitiveLoggingConfig::default();
        config = config.with_redact_sensitive_queries(true);
        let sanitized = crate::app::sanitize_request_uri(&uri, &config);

        assert!(sanitized.contains("test-kid"));
        assert!(sanitized.contains("test-sig"));
    }

    #[test]
    fn decode_key_material_accepts_hex() {
        let key_name = "test";
        let hex_16 = "00112233445566778899aabbccddeeff";
        let hex_32 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let decoded_16 = decode_key_material(hex_16, key_name).expect("hex16 should decode");
        assert_eq!(decoded_16.len(), 16);
        let mut encoded_16 = String::with_capacity(decoded_16.len() * 2);
        for byte in &decoded_16 {
            write!(&mut encoded_16, "{:02x}", byte).expect("formatting hex");
        }
        assert_eq!(encoded_16, hex_16);

        let decoded_32 = decode_key_material(hex_32, key_name).expect("hex32 should decode");
        assert_eq!(decoded_32.len(), 32);
        let mut encoded_32 = String::with_capacity(decoded_32.len() * 2);
        for byte in &decoded_32 {
            write!(&mut encoded_32, "{:02x}", byte).expect("formatting hex");
        }
        assert_eq!(encoded_32, hex_32);
    }
}
