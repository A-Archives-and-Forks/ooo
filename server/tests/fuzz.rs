//! Randomised property tests over the codec and the full request→response path.
//!
//! No fuzzing crate and no nightly: a splitmix64 generator and a handful of
//! input strategies, run under plain `cargo test`. Deterministic by default so
//! a failure is reproducible; override with
//!
//! ```sh
//! OOO_FUZZ_ITERS=2000000 OOO_FUZZ_SEED=12345 cargo test --release --test fuzz
//! ```
//!
//! Every failure prints the seed and the offending input, so a red run in CI
//! can be replayed exactly.

use hyper::header::LOCATION;
use hyper::StatusCode;
use ooo::codec::{self, MAX_URL_LEN};
use ooo::service;

/// Iterations per strategy. Kept small enough that the default `cargo test`
/// stays quick; turn it up in CI.
fn iters() -> usize {
    std::env::var("OOO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000)
}

fn seed() -> u64 {
    std::env::var("OOO_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x00F0_0DBA_D5EE_D000)
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// The four homoglyphs plus the characters most likely to steer the decoder
/// somewhere interesting: escape syntax, near-miss lookalikes, delimiters.
const ALPHABET: [&str; 16] = [
    "o", "\u{03bf}", "\u{043e}", "\u{1d0f}", // the alphabet itself
    "%", "%2", "%CE", "%BF", // escape syntax, whole and partial
    "0", "O", "\u{03bd}", "\u{1d0e}", // lookalikes that must not decode
    "/", "?", "#", "\u{fffd}", // delimiters and a replacement char
];

const SEED_URLS: [&str; 8] = [
    "https://a.co",
    "http://example.com/path?query=1&x=2#frag",
    "https://sub.domain.example.com:8443/a/b/c",
    "https://[2001:db8::1]/v6",
    "https://a.co/päth?q=🚀",
    "https://xn--exmple-cua.com/",
    "https://user.co/a%20b",
    "https://a.co/𝄞𝄢",
];

// ------------------------------------------------------------- invariants --

/// Whatever `decode` returns, it must be self-consistent: within the length
/// limit, and stable under re-encoding.
fn check_decode(input: &[u8], ctx: &str) -> Option<String> {
    let decoded = codec::decode(input).ok()?;
    assert!(
        decoded.url.len() <= MAX_URL_LEN,
        "{ctx}: decoded {} bytes, over the {MAX_URL_LEN} limit",
        decoded.url.len()
    );

    // Re-encoding a decoded URL and decoding again must land on the same
    // string. A truncated result is a prefix, and a prefix is still a URL,
    // so this holds either way.
    let again = codec::decode(codec::encode(&decoded.url).as_bytes())
        .unwrap_or_else(|e| panic!("{ctx}: re-decode of {:?} failed: {e}", decoded.url));
    assert_eq!(again.url, decoded.url, "{ctx}: not stable under re-encoding");
    assert!(!again.truncated, "{ctx}: re-encoding introduced truncation");
    Some(decoded.url)
}

/// What `validate` promises when it says yes. Checked independently of the
/// implementation so a loosened rule shows up here rather than in production.
fn check_validate_contract(url: &str, ctx: &str) {
    if codec::validate(url).is_err() {
        return;
    }
    assert!(
        url.bytes().all(|b| b > b' ' && b != 0x7f),
        "{ctx}: control character or space passed validate: {url:?}"
    );
    let (scheme, rest) = url
        .split_once("://")
        .unwrap_or_else(|| panic!("{ctx}: no scheme separator in {url:?}"));
    assert!(
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"),
        "{ctx}: scheme {scheme:?} passed validate"
    );
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    assert!(!authority.is_empty(), "{ctx}: empty authority in {url:?}");
    assert!(
        !authority.contains('@'),
        "{ctx}: credentials passed validate: {url:?}"
    );
    assert!(
        authority.is_ascii(),
        "{ctx}: non-ASCII host passed validate: {url:?}"
    );
}

/// A validated URL must survive into a header without smuggling anything.
fn check_header_safety(url: &str, ctx: &str) {
    if codec::validate(url).is_err() {
        return;
    }
    let safe = codec::header_safe(url);
    for b in safe.bytes() {
        assert!(
            (0x21..=0x7e).contains(&b),
            "{ctx}: byte {b:#04x} escaped into a header from {url:?}"
        );
    }
    assert!(
        !safe.contains(['\r', '\n']),
        "{ctx}: header injection via {url:?}"
    );
    hyper::header::HeaderValue::from_str(&safe)
        .unwrap_or_else(|e| panic!("{ctx}: {safe:?} is not a header value: {e}"));
}

/// The service answers exactly two ways, and only one of them carries a
/// destination.
fn check_response(path: &[u8], ctx: &str) {
    let res = service::redirect(path);
    match res.status() {
        StatusCode::MOVED_PERMANENTLY => {
            let location = res
                .headers()
                .get(LOCATION)
                .unwrap_or_else(|| panic!("{ctx}: 301 without a Location"));
            let location = location
                .to_str()
                .unwrap_or_else(|e| panic!("{ctx}: unreadable Location: {e}"));
            // Schemes are case-insensitive, and `validate` accepts them that
            // way, so compare that way too.
            let scheme = location.split("://").next().unwrap_or("");
            assert!(
                scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"),
                "{ctx}: redirected to {location:?}"
            );
            assert!(
                !location.contains(['\r', '\n', ' ']),
                "{ctx}: smuggled whitespace into Location {location:?}"
            );
        }
        StatusCode::NOT_FOUND => assert!(
            res.headers().get(LOCATION).is_none(),
            "{ctx}: 404 carrying a Location"
        ),
        other => panic!("{ctx}: unexpected status {other}"),
    }
}

fn check_all(input: &[u8], ctx: &str) {
    if let Some(url) = check_decode(input, ctx) {
        check_validate_contract(&url, ctx);
        check_header_safety(&url, ctx);
    }
    check_response(input, ctx);
    // The raw input is usually not a URL, but feeding it in anyway costs
    // nothing and exercises the slicing in `validate` on ragged text.
    if let Ok(s) = std::str::from_utf8(input) {
        check_validate_contract(s, ctx);
        check_header_safety(s, ctx);
    }
}

// ------------------------------------------------------------- strategies --

#[test]
fn fuzz_arbitrary_bytes() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed);
    let mut buf = Vec::new();
    for i in 0..iters {
        buf.clear();
        let len = rng.below(64);
        buf.extend((0..len).map(|_| rng.byte()));
        check_all(&buf, &format!("seed={seed} iter={i} bytes={buf:?}"));
    }
}

#[test]
fn fuzz_biased_alphabet() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 1);
    let mut s = String::new();
    for i in 0..iters {
        s.clear();
        s.push('/');
        let len = rng.below(48);
        for _ in 0..len {
            s.push_str(rng.pick(&ALPHABET));
        }
        check_all(s.as_bytes(), &format!("seed={seed} iter={i} path={s:?}"));
    }
}

#[test]
fn fuzz_mutated_valid_links() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 2);
    for i in 0..iters {
        let url = rng.pick(&SEED_URLS);
        let mut bytes = format!("/{}", codec::encode(url)).into_bytes();

        // One to three byte-level mutations: the interesting cases are the
        // ones that leave a mostly-valid link with a hole in it.
        for _ in 0..=rng.below(3) {
            if bytes.is_empty() {
                break;
            }
            let at = rng.below(bytes.len());
            match rng.below(3) {
                0 => bytes[at] = rng.byte(),
                1 => {
                    bytes.remove(at);
                }
                _ => bytes.insert(at, rng.byte()),
            }
        }
        check_all(&bytes, &format!("seed={seed} iter={i} url={url:?}"));
    }
}

#[test]
fn fuzz_round_trip_of_arbitrary_text() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 3);
    // A tenth of the iterations: each one encodes and decodes a whole string.
    for i in 0..iters / 10 + 1 {
        let len = 1 + rng.below(200);
        let text: String = (0..len)
            .map(|_| loop {
                // Uniform over the whole scalar range, surrogates excluded.
                if let Some(c) = char::from_u32(rng.below(0x11_0000) as u32) {
                    return c;
                }
            })
            .collect();
        if text.len() > MAX_URL_LEN {
            continue;
        }
        let decoded = codec::decode(codec::encode(&text).as_bytes())
            .unwrap_or_else(|e| panic!("seed={seed} iter={i}: {text:?} failed to decode: {e}"));
        assert!(!decoded.truncated, "seed={seed} iter={i}: unexpected truncation");
        assert_eq!(decoded.url, text, "seed={seed} iter={i}: round trip changed the text");
    }
}

#[test]
fn fuzz_validate_never_panics_on_arbitrary_text() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 4);
    // Fragments that land on the slicing edges in `validate`: scheme
    // separators, brackets, colons, dots.
    const PARTS: [&str; 26] = [
        "http", "https", "://", ":", "/", "?", "#", "@", "[", "]", ".", "..", "-", "%", "a", "1",
        "::1", "8080", "ä", "🚀",
        // The characters that must never reach a header.
        "\n", "\r", "\r\n", " ", "\0", "\u{7f}",
    ];
    for i in 0..iters {
        let len = rng.below(12);
        let mut s = String::new();
        for _ in 0..len {
            s.push_str(rng.pick(&PARTS));
        }
        let ctx = format!("seed={seed} iter={i} url={s:?}");
        check_validate_contract(&s, &ctx);
        check_header_safety(&s, &ctx);
    }
}

#[test]
fn fuzz_lengths_around_the_truncation_limit() {
    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 5);
    // Each iteration encodes and decodes up to ~20 KB, so run far fewer.
    for i in 0..iters / 500 + 8 {
        // Straddle the limit: exact boundary cases plus a wide spread either
        // side of it.
        let len = match rng.below(4) {
            0 => MAX_URL_LEN - rng.below(4),
            1 => MAX_URL_LEN,
            2 => MAX_URL_LEN + rng.below(4) + 1,
            _ => MAX_URL_LEN + rng.below(4096),
        };
        // Mix byte widths so the cut can land inside a multi-byte character.
        let mut url = String::with_capacity(len + 4);
        while url.len() < len {
            let c = match rng.below(8) {
                0..=4 => 'x',
                5 => 'ä',
                6 => '€',
                _ => '🚀',
            };
            if url.len() + c.len_utf8() > len {
                break;
            }
            url.push(c);
        }

        let ctx = format!("seed={seed} iter={i} len={}", url.len());
        let decoded = codec::decode(codec::encode(&url).as_bytes())
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));

        assert!(
            decoded.url.len() <= MAX_URL_LEN,
            "{ctx}: decoded {} bytes, over the {MAX_URL_LEN} limit",
            decoded.url.len()
        );
        assert_eq!(
            decoded.truncated,
            url.len() > MAX_URL_LEN,
            "{ctx}: truncation flag disagrees with the input length"
        );
        // Truncated or not, the result is always a prefix of the original,
        // cut on a character boundary.
        assert!(
            url.starts_with(&decoded.url),
            "{ctx}: result is not a prefix of the input"
        );
        if decoded.truncated {
            // At most three bytes are given up to keep the last character whole.
            assert!(
                decoded.url.len() > MAX_URL_LEN - 4,
                "{ctx}: gave up {} bytes to the character boundary",
                MAX_URL_LEN - decoded.url.len()
            );
        }
    }
}

#[test]
fn fuzz_structured_urls() {
    // Random concatenation almost never lands on a plausible URL with one bad
    // character buried in it, which is exactly the shape that matters. Build
    // the URL from realistic parts instead, then inject.
    const SCHEMES: [&str; 6] = ["http", "https", "HTTPS", "ftp", "javascript", ""];
    const HOSTS: [&str; 11] = [
        "a.co",
        "example.com",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "[2001:db8::1]",
        "xn--exmple-cua.com",
        "",
        "a..co",
        "-a.co",
        "exämple.com",
    ];
    const PORTS: [&str; 5] = ["", ":80", ":", ":80x", ":123456"];
    const TAILS: [&str; 7] = ["", "/", "/a/b", "/a?b=c", "/a#f", "/päth?q=🚀", "/%41%2f"];
    const NASTY: [&str; 10] = [
        "\n", "\r", "\r\n", " ", "\t", "\0", "\u{7f}", "@evil.com", "%00",
        "\r\nLocation: https://evil.com",
    ];

    let (seed, iters) = (seed(), iters());
    let mut rng = Rng::new(seed ^ 6);
    for i in 0..iters {
        let mut url = format!(
            "{}://{}{}{}",
            rng.pick(&SCHEMES),
            rng.pick(&HOSTS),
            rng.pick(&PORTS),
            rng.pick(&TAILS)
        );
        // Usually inject something hostile, at a character boundary.
        if rng.below(4) != 0 {
            let mut at = rng.below(url.len() + 1);
            while !url.is_char_boundary(at) {
                at -= 1;
            }
            url.insert_str(at, rng.pick(&NASTY));
        }

        let ctx = format!("seed={seed} iter={i} url={url:?}");
        check_validate_contract(&url, &ctx);
        check_header_safety(&url, &ctx);

        // And the whole way through: if this URL is reachable as a link, the
        // response it produces must still be well formed.
        if !url.is_empty() && url.len() <= MAX_URL_LEN {
            check_response(format!("/{}", codec::encode(&url)).as_bytes(), &ctx);
        }
    }
}
