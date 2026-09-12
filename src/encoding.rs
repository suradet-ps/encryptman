//! Base64 encodings for the packed ciphertext format.

use base64::Engine;

use crate::CryptoError;

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
    #[must_use]
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

    /// Return the canonical name of this encoding.
    ///
    /// The name is the inverse of [`FromStr`](std::str::FromStr) and is safe
    /// to persist in settings files; `Encoding::Standard` is `"standard"` and
    /// `Encoding::UrlSafeNoPad` is `"url_safe_no_pad"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// assert_eq!(Encoding::Standard.as_str(), "standard");
    /// assert_eq!(
    ///     Encoding::UrlSafeNoPad.as_str().parse::<Encoding>().unwrap(),
    ///     Encoding::UrlSafeNoPad
    /// );
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Encoding::Standard => "standard",
            Encoding::UrlSafeNoPad => "url_safe_no_pad",
        }
    }
}

impl std::str::FromStr for Encoding {
    type Err = CryptoError;

    /// Parse an encoding from its canonical name.
    ///
    /// Recognizes `"standard"` and `"url_safe_no_pad"`; every other string
    /// returns [`CryptoError::InvalidEncoding`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// assert_eq!("standard".parse::<Encoding>().unwrap(), Encoding::Standard);
    /// assert_eq!(
    ///     "url_safe_no_pad".parse::<Encoding>().unwrap(),
    ///     Encoding::UrlSafeNoPad
    /// );
    /// assert!("utf-16".parse::<Encoding>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(Encoding::Standard),
            "url_safe_no_pad" => Ok(Encoding::UrlSafeNoPad),
            _ => Err(CryptoError::InvalidEncoding),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_vectors() {
        assert_eq!(Encoding::Standard.encode(b"hello"), "aGVsbG8=");
        assert_eq!(Encoding::UrlSafeNoPad.encode(b"hello"), "aGVsbG8");
        assert_eq!(Encoding::UrlSafeNoPad.encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(Encoding::Standard.encode(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn from_str_accepts_canonical_names() {
        assert_eq!("standard".parse::<Encoding>().unwrap(), Encoding::Standard);
        assert_eq!(
            "url_safe_no_pad".parse::<Encoding>().unwrap(),
            Encoding::UrlSafeNoPad
        );
    }

    #[test]
    fn from_str_rejects_unknown_names() {
        for name in ["", "Standard", "url-safe", "urlsafe-no-pad", "base64"] {
            assert_eq!(
                name.parse::<Encoding>().unwrap_err(),
                CryptoError::InvalidEncoding,
                "{name:?} must not parse"
            );
        }
    }

    #[test]
    fn as_str_roundtrips_through_from_str() {
        for encoding in [Encoding::Standard, Encoding::UrlSafeNoPad] {
            let parsed = encoding.as_str().parse::<Encoding>().unwrap();
            assert_eq!(parsed, encoding, "as_str/from_str must roundtrip");
        }
    }
}
