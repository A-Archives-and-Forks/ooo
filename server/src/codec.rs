//! The `ooo` codec: a URL is UTF-8 encoded, every byte written as four base-4
//! digits, and every digit rendered as one of four homoglyphs of the letter o.
//!
//! ```text
//!   digit 0 -> "o"  U+006F  6f
//!   digit 1 -> "ο"  U+03BF  ce bf
//!   digit 2 -> "о"  U+043E  d0 be
//!   digit 3 -> "ᴏ"  U+1D0F  e1 b4 8f
//! ```
//!
//! The stream is prefixed with the version marker `oooo`, which is exactly the
//! four digits of the byte `0x00`, so version handling falls out of the byte
//! loop for free.
//!
//! Decoding is a single pass over the raw request path: percent-decoding, digit
//! recognition and byte assembly all happen in one loop with one allocation,
//! and the loop stops the moment [`MAX_URL_LEN`] bytes have been produced.

use std::borrow::Cow;

/// Decoded URLs are truncated at 16 KiB.
pub const MAX_URL_LEN: usize = 16 * 1024;

/// Rendering of digits 0..=3.
const ENC: [&str; 4] = ["o", "\u{03bf}", "\u{043e}", "\u{1d0f}"];

/// Schemes we are willing to emit in a `Location` header.
const ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer than four characters: no room for the version marker.
    TooShort,
    /// The leading four characters are not a known version marker.
    UnknownVersion,
    /// Nothing followed the version marker.
    Empty,
    /// A character outside the four-o alphabet.
    InvalidCharacter,
    /// The digit count is not a multiple of four, so a byte is incomplete.
    TrailingDigits,
    /// The assembled bytes are not valid UTF-8.
    InvalidUtf8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// No `://` separator.
    NotAbsolute,
    /// Scheme outside [`ALLOWED_SCHEMES`].
    UnsupportedScheme,
    /// Empty, malformed, or non-ASCII host.
    BadHost,
    /// The authority carries `user:pass@`, the classic redirect-phishing trick.
    Userinfo,
    /// The port is empty or not a decimal number.
    BadPort,
    /// A control character or space survived decoding.
    IllegalCharacter,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::TooShort => "input shorter than the version marker",
            Self::UnknownVersion => "unknown version marker",
            Self::Empty => "no payload after the version marker",
            Self::InvalidCharacter => "character outside the o alphabet",
            Self::TrailingDigits => "digit count is not a multiple of four",
            Self::InvalidUtf8 => "decoded bytes are not valid UTF-8",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotAbsolute => "not an absolute URL",
            Self::UnsupportedScheme => "unsupported scheme",
            Self::BadHost => "missing or malformed host",
            Self::Userinfo => "credentials in the authority",
            Self::BadPort => "malformed port",
            Self::IllegalCharacter => "illegal character in URL",
        };
        f.write_str(s)
    }
}

/// A successfully decoded URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub url: String,
    /// Set when the input carried more than [`MAX_URL_LEN`] bytes and the tail
    /// was discarded.
    pub truncated: bool,
}

/// Decode a raw (still percent-encoded) request path.
///
/// A single leading `/` is ignored, matching how the path arrives off the wire.
pub fn decode(path: &[u8]) -> Result<Decoded, DecodeError> {
    let path = match path.split_first() {
        Some((b'/', rest)) => rest,
        _ => path,
    };

    let mut src = Reader::new(path);
    // Four characters per byte, and a character is at least one byte, so
    // len/4 is a tight upper bound on the output. Never over-reserve past
    // the truncation limit.
    let mut out: Vec<u8> = Vec::with_capacity((path.len() / 4).min(MAX_URL_LEN));

    let mut byte: u8 = 0;
    let mut digits = 0u8;
    let mut version_seen = false;
    let mut truncated = false;

    while let Some(b) = src.next() {
        byte = (byte << 2) | digit(b, &mut src)?;
        digits += 1;
        if digits < 4 {
            continue;
        }
        digits = 0;

        if !version_seen {
            version_seen = true;
            // The only known version marker, "oooo", is the byte 0x00.
            if byte != 0 {
                return Err(DecodeError::UnknownVersion);
            }
        } else {
            out.push(byte);
            if out.len() == MAX_URL_LEN {
                truncated = !src.is_empty();
                break;
            }
        }
        byte = 0;
    }

    if !version_seen {
        return Err(DecodeError::TooShort);
    }
    if digits != 0 {
        return Err(DecodeError::TrailingDigits);
    }
    if out.is_empty() {
        return Err(DecodeError::Empty);
    }

    // A truncated tail can cut a multi-byte character in half; drop the stub.
    if truncated {
        if let Err(e) = std::str::from_utf8(&out) {
            if e.error_len().is_none() {
                out.truncate(e.valid_up_to());
            }
        }
    }

    match String::from_utf8(out) {
        Ok(url) => Ok(Decoded { url, truncated }),
        Err(_) => Err(DecodeError::InvalidUtf8),
    }
}

/// Encode a URL into its `ooo` form, version marker included.
pub fn encode(url: &str) -> String {
    // Worst case every digit is the 3-byte U+1D0F.
    let mut out = String::with_capacity((url.len() + 1) * 4 * 3);
    for b in std::iter::once(0u8).chain(url.bytes()) {
        for shift in [6, 4, 2, 0] {
            out.push_str(ENC[usize::from((b >> shift) & 0b11)]);
        }
    }
    out
}

/// Check that a decoded string is something we may redirect a browser to.
///
/// Deliberately stricter than the original worker, which accepted any absolute
/// URL: `javascript:` and `data:` targets would turn the redirector into an
/// XSS vector, and a control character in the target would turn it into a
/// header-injection vector.
pub fn validate(url: &str) -> Result<(), UrlError> {
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(UrlError::IllegalCharacter);
    }
    let sep = url.find("://").ok_or(UrlError::NotAbsolute)?;
    let (scheme, rest) = url.split_at(sep);
    if !ALLOWED_SCHEMES.iter().any(|s| scheme.eq_ignore_ascii_case(s)) {
        return Err(UrlError::UnsupportedScheme);
    }

    let after_scheme = &rest["://".len()..];
    let authority = match after_scheme.find(['/', '?', '#']) {
        Some(end) => &after_scheme[..end],
        None => after_scheme,
    };
    // `https://trusted.com@evil.com/` reads as trusted.com to a human and
    // resolves to evil.com. A redirector has no business carrying credentials,
    // so the whole form is out.
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }

    let (host, port) = split_port(authority);
    check_host(host)?;
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(UrlError::BadPort);
        }
    }
    Ok(())
}

/// Split `host:port`, keeping an IPv6 literal's colons inside the brackets.
fn split_port(authority: &str) -> (&str, Option<&str>) {
    let search_from = match authority.rfind(']') {
        Some(i) => i + 1,
        None => 0,
    };
    match authority[search_from..].find(':') {
        Some(i) => {
            let at = search_from + i;
            (&authority[..at], Some(&authority[at + 1..]))
        }
        None => (authority, None),
    }
}

/// A host is an IPv6 literal in brackets, or a dotted name of non-empty
/// alphanumeric/hyphen labels.
///
/// ASCII only: an internationalised host has to arrive already punycoded,
/// because resolving one here would mean shipping an IDNA table and taking a
/// position on homograph attacks - in a service whose entire alphabet is
/// homographs of the letter o.
fn check_host(host: &str) -> Result<(), UrlError> {
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(UrlError::BadHost)?;
        let ok = !inner.is_empty()
            && inner.bytes().any(|b| b.is_ascii_hexdigit())
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        return if ok { Ok(()) } else { Err(UrlError::BadHost) };
    }
    if host.is_empty() || host.contains(']') {
        return Err(UrlError::BadHost);
    }
    let mut any_alnum = false;
    for label in host.split('.') {
        // Rejects the empty label, which also rejects a leading dot, a double
        // dot, and the trailing root dot of an FQDN.
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(UrlError::BadHost);
        }
        for b in label.bytes() {
            if b.is_ascii_alphanumeric() {
                any_alnum = true;
            } else if b != b'-' {
                return Err(UrlError::BadHost);
            }
        }
    }
    if any_alnum {
        Ok(())
    } else {
        Err(UrlError::BadHost)
    }
}

/// Percent-encode the bytes that may not appear literally in a `Location`
/// header. Pure-ASCII URLs — the overwhelming majority — borrow instead of
/// allocating.
pub fn header_safe(url: &str) -> Cow<'_, str> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let needs_escape = |b: u8| b <= b' ' || b >= 0x7f;

    if !url.bytes().any(needs_escape) {
        return Cow::Borrowed(url);
    }
    let mut out = String::with_capacity(url.len() + 16);
    for b in url.bytes() {
        if needs_escape(b) {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0xf)] as char);
        } else {
            out.push(b as char);
        }
    }
    Cow::Owned(out)
}

/// Map one UTF-8 sequence to its base-4 digit, pulling continuation bytes from
/// `src` as needed.
#[inline]
fn digit(b: u8, src: &mut Reader<'_>) -> Result<u8, DecodeError> {
    match b {
        0x6f => Ok(0),                                             // o    U+006F
        0xce if src.eat(0xbf) => Ok(1),                            // ο    U+03BF
        0xd0 if src.eat(0xbe) => Ok(2),                            // о    U+043E
        0xe1 if src.eat(0xb4) && src.eat(0x8f) => Ok(3),           // ᴏ    U+1D0F
        _ => Err(DecodeError::InvalidCharacter),
    }
}

/// Byte reader that percent-decodes on the fly, so no intermediate buffer is
/// materialised for the (much larger) encoded form.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    #[inline]
    #[allow(clippy::should_implement_trait)]
    fn next(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        if b == b'%' {
            if let (Some(hi), Some(lo)) = (
                self.buf.get(self.pos + 1).copied().and_then(unhex),
                self.buf.get(self.pos + 2).copied().and_then(unhex),
            ) {
                self.pos += 3;
                return Some((hi << 4) | lo);
            }
        }
        self.pos += 1;
        Some(b)
    }

    /// Consume the next byte only if it matches `want`.
    #[inline]
    fn eat(&mut self, want: u8) -> bool {
        let save = self.pos;
        match self.next() {
            Some(b) if b == want => true,
            _ => {
                self.pos = save;
                false
            }
        }
    }
}

#[inline]
fn unhex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
