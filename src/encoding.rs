//! Base64 encodings for the packed ciphertext format.

use base64::Engine;

/// Ciphertext encoding variant.
///
/// Selects the base64 character set used for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Standard base64 (RFC 4648 §4). Safe for files, env vars, databases.
    Standard,

    /// URL-safe base64 without padding (RFC 4648 §5). Safe for URLs, JWTs,
    /// cookies, and web applications where `+`/`/` characters are problematic.
    UrlSafeNoPad,
}

impl Encoding {
    /// Encode raw bytes into a base64 string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// let encoded = Encoding::Standard.encode(b"hello");
    /// assert_eq!(encoded, "aGVsbG8=");
    /// ```
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            Encoding::Standard => base64::engine::general_purpose::STANDARD.encode(data),
            Encoding::UrlSafeNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
        }
    }

    /// Decode a base64 string into raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64 for this encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// let bytes = Encoding::Standard.decode("aGVsbG8=").unwrap();
    /// assert_eq!(bytes, b"hello");
    /// ```
    pub fn decode(&self, data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        match self {
            Encoding::Standard => base64::engine::general_purpose::STANDARD.decode(data),
            Encoding::UrlSafeNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data),
        }
    }
}
