use std::fmt;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

/// Encodes the provided bytes using the standard Base64 alphabet.
pub fn encode_base64<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}

/// Decodes a standard Base64 string into raw bytes.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
}

/// Encodes bytes using the URL-safe Base64 alphabet without padding.
pub fn encode_base64_url<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes a URL-safe Base64 string without padding.
pub fn decode_base64_url(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

/// Attempts to decode a Base64 string into UTF-8 text, returning a
/// human-readable error on failure.
pub fn decode_base64_to_string(data: &str) -> Result<String, Base64TextError> {
    let bytes = decode_base64(data).map_err(Base64TextError::InvalidEncoding)?;
    String::from_utf8(bytes).map_err(|err| Base64TextError::InvalidUtf8(err.utf8_error()))
}

/// Error returned when a Base64 string cannot be converted into UTF-8 text.
#[derive(Debug)]
pub enum Base64TextError {
    /// The provided data was not valid Base64 encoded content.
    InvalidEncoding(base64::DecodeError),
    /// The decoded bytes were not valid UTF-8 text.
    InvalidUtf8(std::str::Utf8Error),
}

impl fmt::Display for Base64TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(err) => write!(f, "invalid base64 data: {err}"),
            Self::InvalidUtf8(err) => write!(f, "decoded data is not valid UTF-8: {err}"),
        }
    }
}

impl std::error::Error for Base64TextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEncoding(err) => Some(err),
            Self::InvalidUtf8(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_standard_alphabet() {
        let input = b"hello world";
        let encoded = encode_base64(input);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trip_url_alphabet() {
        let input = b"binary\x00payload";
        let encoded = encode_base64_url(input);
        let decoded = decode_base64_url(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn decode_to_string_reports_errors() {
        let err = decode_base64_to_string("::not-valid::").unwrap_err();
        match err {
            Base64TextError::InvalidEncoding(_) => {}
            _ => panic!("unexpected variant"),
        }
    }
}
