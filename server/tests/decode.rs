//! Tests for the decoding half of the codec.
//!
//! The reference vectors were produced by running the original `worker.js`
//! `encodeUrl`, so a passing run means the Rust decoder still resolves every
//! link already in the wild.
//!
//! One deliberate divergence: `worker.js`'s `Utf8ArrayToStr` has no branch for
//! 4-byte UTF-8, so it silently drops astral characters (emoji, rare CJK,
//! musical symbols) on the way back out. The links encode fine; only the JS
//! decoder loses them. The Rust decoder handles the full range, so it resolves
//! a strict superset of what the worker could.

use ooo::codec::{self, DecodeError, MAX_URL_LEN};

/// The four homoglyphs, digits 0..=3.
const O: [&str; 4] = ["o", "\u{03bf}", "\u{043e}", "\u{1d0f}"];

/// Build an encoded string from base-4 digits, version marker included.
fn oooify(digits: &[u8]) -> String {
    let mut s = String::from("oooo");
    s.extend(digits.iter().map(|&d| O[usize::from(d)]));
    s
}

fn decode(s: &str) -> Result<String, DecodeError> {
    codec::decode(s.as_bytes()).map(|d| {
        assert!(!d.truncated, "unexpected truncation");
        d.url
    })
}

// ---------------------------------------------------------------- vectors --

#[test]
fn decodes_the_reference_vector() {
    // "https://a.co" as emitted by worker.js encodeUrl().
    let encoded = "ooooοооoοᴏοoοᴏοoοᴏooοᴏoᴏoᴏооoоᴏᴏoоᴏᴏοоoοoоᴏоοоoᴏοоᴏᴏ";
    assert_eq!(decode(encoded).unwrap(), "https://a.co");
}

#[test]
fn decodes_ascii() {
    // 'A' is 0x41 = 1001 in base 4.
    assert_eq!(decode(&oooify(&[1, 0, 0, 1])).unwrap(), "A");
    // The lowest and highest printable ASCII: ' ' (0x20 = 0200) and '~' (0x7e = 1332).
    assert_eq!(decode(&oooify(&[0, 2, 0, 0, 1, 3, 3, 2])).unwrap(), " ~");
}

#[test]
fn decodes_multibyte_utf8() {
    for s in [
        "https://example.com/päth",
        "https://例え.テスト/ページ?q=検索",
        "https://emoji.dev/🚀🌍",
        "https://x.dev/𝄞",
    ] {
        assert_eq!(decode(&codec::encode(s)).unwrap(), s, "round trip of {s}");
    }
}

#[test]
fn round_trips_every_scalar_value() {
    // Every Unicode scalar except NUL, which is the version marker itself and
    // cannot appear in a URL. `char` ranges skip surrogates on their own.
    // Chunked so no single input passes the truncation limit.
    let mut chunk = String::new();
    let mut checked = 0usize;
    for c in '\u{1}'..=char::MAX {
        if chunk.len() + c.len_utf8() > MAX_URL_LEN {
            assert_eq!(decode(&codec::encode(&chunk)).unwrap(), chunk);
            checked += chunk.chars().count();
            chunk.clear();
        }
        chunk.push(c);
    }
    assert_eq!(decode(&codec::encode(&chunk)).unwrap(), chunk);
    checked += chunk.chars().count();
    // 0x110000 code points, minus NUL, minus the 2048 surrogates.
    assert_eq!(checked, 0x11_0000 - 1 - 2048);
}

// ----------------------------------------------------------- path shapes --

#[test]
fn accepts_a_leading_slash() {
    let encoded = codec::encode("https://a.co");
    assert_eq!(decode(&encoded).unwrap(), "https://a.co");
    assert_eq!(decode(&format!("/{encoded}")).unwrap(), "https://a.co");
}

#[test]
fn only_one_leading_slash_is_stripped() {
    let encoded = codec::encode("https://a.co");
    assert_eq!(
        decode(&format!("//{encoded}")),
        Err(DecodeError::InvalidCharacter)
    );
}

#[test]
fn decodes_percent_encoded_paths() {
    // What a client actually sends: the non-ASCII o's percent-encoded.
    let raw = codec::encode("https://a.co");
    let mut escaped = String::new();
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() {
            escaped.push(b as char);
        } else {
            escaped.push_str(&format!("%{b:02X}"));
        }
    }
    assert_eq!(decode(&escaped).unwrap(), "https://a.co");
    // Lowercase escapes too.
    assert_eq!(decode(&escaped.to_lowercase()).unwrap(), "https://a.co");
}

#[test]
fn a_truncated_percent_escape_is_not_a_digit() {
    assert_eq!(decode("oooo%C"), Err(DecodeError::InvalidCharacter));
    assert_eq!(decode("oooo%ZZ"), Err(DecodeError::InvalidCharacter));
    assert_eq!(decode("oooo%"), Err(DecodeError::InvalidCharacter));
}

// --------------------------------------------------------------- version --

#[test]
fn rejects_a_missing_or_wrong_version_marker() {
    assert_eq!(decode(""), Err(DecodeError::TooShort));
    assert_eq!(decode("ooo"), Err(DecodeError::TooShort));
    // "ooo" + any non-zero digit is an unknown version.
    assert_eq!(decode("oooοoooo"), Err(DecodeError::UnknownVersion));
    assert_eq!(decode("ᴏooooooo"), Err(DecodeError::UnknownVersion));
}

#[test]
fn rejects_a_version_marker_with_no_payload() {
    assert_eq!(decode("oooo"), Err(DecodeError::Empty));
}

// -------------------------------------------------------------- alphabet --

#[test]
fn rejects_characters_outside_the_alphabet() {
    for bad in ["oooox", "ooooO", "oooo0", "oooo ", "oooo\u{03bd}"] {
        assert_eq!(decode(bad), Err(DecodeError::InvalidCharacter), "{bad:?}");
    }
}

#[test]
fn rejects_a_lookalike_that_shares_a_lead_byte() {
    // U+03BD "ν" is ce bd: same lead byte as U+03BF but a different digit.
    assert_eq!(decode("oooo\u{03bd}ooo"), Err(DecodeError::InvalidCharacter));
    // U+1D0E shares two lead bytes with U+1D0F.
    assert_eq!(decode("oooo\u{1d0e}ooo"), Err(DecodeError::InvalidCharacter));
}

#[test]
fn rejects_raw_utf8_continuation_bytes() {
    // The tail of U+03BF on its own must not decode to anything.
    assert!(codec::decode(b"oooo\xbf\xbf\xbf\xbf").is_err());
    assert!(codec::decode(b"oooo\xff").is_err());
}

#[test]
fn rejects_an_incomplete_final_byte() {
    // Three digits after the marker cannot form a byte.
    assert_eq!(decode(&oooify(&[1, 0, 0])), Err(DecodeError::TrailingDigits));
    assert_eq!(
        decode(&oooify(&[1, 0, 0, 1, 2])),
        Err(DecodeError::TrailingDigits)
    );
}

#[test]
fn rejects_bytes_that_are_not_valid_utf8() {
    // 0xff = 3333, a byte that can never appear in UTF-8.
    assert_eq!(decode(&oooify(&[3, 3, 3, 3])), Err(DecodeError::InvalidUtf8));
    // A lone continuation byte 0x80 = 2000.
    assert_eq!(decode(&oooify(&[2, 0, 0, 0])), Err(DecodeError::InvalidUtf8));
    // A truncated two-byte sequence: 0xc3 = 3003, then 'a'.
    assert_eq!(
        decode(&oooify(&[3, 0, 0, 3, 1, 2, 0, 1])),
        Err(DecodeError::InvalidUtf8)
    );
}

// ------------------------------------------------------------ truncation --

#[test]
fn urls_up_to_the_limit_are_untouched() {
    let url = "x".repeat(MAX_URL_LEN);
    let out = codec::decode(codec::encode(&url).as_bytes()).unwrap();
    assert!(!out.truncated);
    assert_eq!(out.url.len(), MAX_URL_LEN);
    assert_eq!(out.url, url);
}

#[test]
fn longer_urls_are_truncated_at_the_limit() {
    let url = "x".repeat(MAX_URL_LEN + 1000);
    let out = codec::decode(codec::encode(&url).as_bytes()).unwrap();
    assert!(out.truncated);
    assert_eq!(out.url.len(), MAX_URL_LEN);
    assert_eq!(out.url, url[..MAX_URL_LEN]);
}

#[test]
fn truncation_does_not_split_a_character_in_half() {
    // Pad with ASCII so the limit falls in the middle of the 4-byte emoji.
    let url = format!("{}🚀tail", "x".repeat(MAX_URL_LEN - 2));
    let out = codec::decode(codec::encode(&url).as_bytes()).unwrap();
    assert!(out.truncated);
    // The emoji cannot fit, so the stub is dropped rather than kept as
    // invalid UTF-8.
    assert_eq!(out.url.len(), MAX_URL_LEN - 2);
    assert!(out.url.bytes().all(|b| b == b'x'));
}

#[test]
fn garbage_after_the_limit_is_never_examined() {
    // The decoder stops at the limit, so an invalid tail cannot fail the
    // request or cost any work.
    let mut encoded = codec::encode(&"x".repeat(MAX_URL_LEN));
    encoded.push_str("nonsense!!");
    let out = codec::decode(encoded.as_bytes()).unwrap();
    assert!(out.truncated);
    assert_eq!(out.url.len(), MAX_URL_LEN);
}

// ------------------------------------------------------------ validation --

#[test]
fn accepts_well_formed_targets() {
    for ok in [
        "http://a.co",
        "https://a.co/",
        "HTTPS://A.CO/x?y#z",
        "https://a.co:8443/p",
        "https://sub.domain.example.com/a/b?c=d&e=f#g",
        "https://xn--exmple-cua.com/",
        "https://my-host.local",
        "https://localhost:3000",
        "https://127.0.0.1/",
        "https://[::1]:8080/",
        "https://[2001:db8::1]/",
        // Non-ASCII is fine everywhere except the host.
        "https://a.co/päth?q=🚀#ünd",
    ] {
        assert!(codec::validate(ok).is_ok(), "should accept {ok:?}");
    }
}

#[test]
fn rejects_anything_that_is_not_a_plain_http_url() {
    for bad in [
        // Not an absolute http(s) URL.
        "",
        "a.co/no-scheme",
        "/relative/path",
        "//a.co/protocol-relative",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "file:///etc/passwd",
        "ftp://a.co/x",
        "https:/a.co",
        // No host.
        "https:///no-host",
        "https://:8080/no-host",
        "https://?q=1",
        // Malformed host.
        "https://a..co/",
        "https://.a.co/",
        "https://a.co./",
        "https://-a.co/",
        "https://a-.co/",
        "https://a_b.co/",
        "https://a b.co/",
        "https://a<script>.co/",
        "https://exämple.com/",
        "https://[::1/",
        "https://:::/",
        // Credentials: the classic redirect-phishing disguise.
        "https://a.co@evil.com/",
        "https://user:pw@a.co/",
        // Malformed port.
        "https://a.co:/",
        "https://a.co:80x/",
        "https://a.co:123456/",
        // Header injection.
        "https://a.co/\nX-Injected: 1",
        "https://a.co/\r\nX-Injected: 1",
        "https://a.co/\0",
        "https://a.co/\u{7f}",
    ] {
        assert!(codec::validate(bad).is_err(), "should reject {bad:?}");
    }
}
