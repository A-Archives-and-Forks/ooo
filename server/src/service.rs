//! Request routing and the rejection policy.
//!
//! `GET /` serves the bundled UI, while `GET /oooοоᴏ…` redirects to the
//! decoded URL. Everything else is a `404`: a wrong method, a query string, a
//! character outside the four-o alphabet, a payload that does not decode to a
//! plain http(s) URL, or one longer than [`codec::MAX_URL_LEN`]. There is no
//! partial credit and no error detail - a request either names a URL exactly or
//! it names nothing. The other exception is [`HEALTH_PATH`].

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use hyper::{Method, Request, Response, StatusCode};

use crate::codec;

/// The mapping is pure, so a decoded redirect is immutable and cacheable.
const CACHE_HIT: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");
const CACHE_MISS: HeaderValue = HeaderValue::from_static("no-store");
const ZERO: HeaderValue = HeaderValue::from_static("0");
const HTML_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");
const INDEX_HTML: &[u8] = include_bytes!("../index.html");

/// Liveness probe.
///
/// Not a hole in the policy above: `u` and `p` are not in the o alphabet, so no
/// encoded link can ever spell `/up` and nothing real is shadowed by it.
///
/// `204` rather than the `404` every other unknown path gets, because probers
/// read 2xx as up and 404 as down - a Kubernetes `httpGet` probe counts a 404
/// as a failure - and because there is nothing to say beyond "the listener, the
/// parser and the router are alive". The process holds no state and talks to
/// nothing, so there is no deeper health to report.
pub const HEALTH_PATH: &str = "/up";

/// Generic over the body so tests can drive it without a live connection;
/// only the method and URI are ever inspected.
pub fn route<B>(req: &Request<B>) -> Response<Full<Bytes>> {
    // Only reads, and only the bare path. A query string means the request is
    // addressing something this server does not have.
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return not_found();
    }
    if req.uri().query().is_some() {
        return not_found();
    }
    if req.uri().path() == "/" {
        return index(req.method() == Method::HEAD);
    }
    if req.uri().path() == HEALTH_PATH {
        return no_content();
    }
    redirect(req.uri().path().as_bytes())
}

/// `301`, not `302`. The decoding is pure arithmetic: the path *is* the URL,
/// there is no table to look anything up in and no state that could ever make
/// the same path resolve differently. A `302` would be telling clients to come
/// back and ask again about an answer that cannot change. The only thing that
/// could change a mapping is a new version marker, and that changes the path.
///
/// `301` also outlives the server, which is the point - a cached redirect
/// resolves while this process is down.
pub fn redirect(path: &[u8]) -> Response<Full<Bytes>> {
    let Ok(decoded) = codec::decode(path) else {
        return not_found();
    };
    // A truncated URL is a different URL. Sending a browser somewhere the link
    // never pointed is worse than admitting the link does not resolve.
    if decoded.truncated || codec::validate(&decoded.url).is_err() {
        return not_found();
    }
    let Ok(location) = HeaderValue::from_str(&codec::header_safe(&decoded.url)) else {
        return not_found();
    };

    let mut res = empty(StatusCode::MOVED_PERMANENTLY);
    let h = res.headers_mut();
    h.insert(LOCATION, location);
    h.insert(CACHE_CONTROL, CACHE_HIT);
    res
}

fn index(head: bool) -> Response<Full<Bytes>> {
    let body = if head {
        Full::new(Bytes::new())
    } else {
        Full::new(Bytes::from_static(INDEX_HTML))
    };
    let mut res = Response::new(body);
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HTML_CONTENT_TYPE);
    h.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&INDEX_HTML.len().to_string())
            .expect("HTML length is a valid header"),
    );
    h.insert(CACHE_CONTROL, CACHE_MISS);
    res
}

fn not_found() -> Response<Full<Bytes>> {
    empty(StatusCode::NOT_FOUND)
}

fn no_content() -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::new()));
    *res.status_mut() = StatusCode::NO_CONTENT;
    // No Content-Length: a 204 is terminated by the end of the header block
    // and cannot carry content.
    res.headers_mut().insert(CACHE_CONTROL, CACHE_MISS);
    res
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::new()));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert(CONTENT_LENGTH, ZERO);
    h.insert(CACHE_CONTROL, CACHE_MISS);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MAX_URL_LEN;
    use http_body_util::BodyExt;

    fn request(method: Method, path_and_query: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(format!("http://ooo.test{path_and_query}"))
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn get(path_and_query: &str) -> Response<Full<Bytes>> {
        route(&request(Method::GET, path_and_query))
    }

    fn location(url: &str) -> Option<String> {
        let res = redirect(format!("/{}", codec::encode(url)).as_bytes());
        res.headers()
            .get(LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
    }

    #[test]
    fn redirects_to_the_decoded_url() {
        let url = "https://example.com/a?b=c#d";
        assert_eq!(location(url).as_deref(), Some(url));
    }

    #[test]
    fn percent_encodes_non_ascii_in_the_location_header() {
        assert_eq!(
            location("https://example.com/päth?q=🚀").as_deref(),
            Some("https://example.com/p%C3%A4th?q=%F0%9F%9A%80")
        );
    }

    #[test]
    fn a_non_ascii_host_is_a_404() {
        // Hosts must arrive already in punycode; we do not do IDNA here.
        let path = format!("/{}", codec::encode("https://exämple.com/"));
        assert_eq!(redirect(path.as_bytes()).status(), StatusCode::NOT_FOUND);

        let path = format!("/{}", codec::encode("https://xn--exmple-cua.com/"));
        assert_eq!(redirect(path.as_bytes()).status(), StatusCode::MOVED_PERMANENTLY);
    }

    #[test]
    fn everything_malformed_is_a_404() {
        for path in [
            "/",                      // empty
            "/not-ooo",               // outside the alphabet
            "/oooo",                  // version marker, no payload
            "/ooooOOOO",              // capital O is a different character
            "/oooo\u{03bd}ooo",       // a lookalike sharing a lead byte
            "/oooooooooooo",          // decodes to NUL bytes, not a URL
        ] {
            assert_eq!(
                redirect(path.as_bytes()).status(),
                StatusCode::NOT_FOUND,
                "{path:?}"
            );
        }
    }

    #[test]
    fn non_http_schemes_are_a_404() {
        for url in ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"] {
            let path = format!("/{}", codec::encode(url));
            assert_eq!(
                redirect(path.as_bytes()).status(),
                StatusCode::NOT_FOUND,
                "{url}"
            );
        }
    }

    #[test]
    fn an_over_long_url_is_a_404_not_a_truncated_redirect() {
        let long = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN));
        let path = format!("/{}", codec::encode(&long));
        let res = redirect(path.as_bytes());
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get(LOCATION).is_none());
    }

    #[test]
    fn a_query_string_is_a_404() {
        let valid = format!("/{}", codec::encode("https://example.com/"));
        assert_eq!(get(&valid).status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(get(&format!("{valid}?")).status(), StatusCode::NOT_FOUND);
        assert_eq!(get(&format!("{valid}?x=1")).status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_root_serves_the_bundled_html() {
        let res = get("/");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(CONTENT_TYPE), Some(&HTML_CONTENT_TYPE));
        assert_eq!(
            res.headers().get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
            INDEX_HTML.len().to_string()
        );
        assert_eq!(
            res.into_body().collect().await.unwrap().to_bytes(),
            INDEX_HTML
        );

        let head = route(&request(Method::HEAD, "/"));
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
            INDEX_HTML.len().to_string()
        );
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
    }

    #[test]
    fn the_health_path_answers_204() {
        let res = get(HEALTH_PATH);
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.headers().get(LOCATION).is_none());
        // A 204 must not announce content.
        assert!(res.headers().get(CONTENT_LENGTH).is_none());

        // HEAD too: probers use it to avoid bodies.
        let req = request(Method::HEAD, HEALTH_PATH);
        assert_eq!(route(&req).status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn the_health_path_is_still_subject_to_the_policy() {
        assert_eq!(get("/up?x=1").status(), StatusCode::NOT_FOUND);
        assert_eq!(get("/up/").status(), StatusCode::NOT_FOUND);
        assert_eq!(get("/UP").status(), StatusCode::NOT_FOUND);
        assert_eq!(
            route(&request(Method::POST, HEALTH_PATH)).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn the_health_path_can_never_collide_with_a_link() {
        // `u` and `p` are outside the alphabet, so this is unreachable as a
        // link no matter what anyone encodes.
        assert!(codec::decode(HEALTH_PATH.as_bytes()).is_err());
    }

    #[test]
    fn a_write_method_is_a_404() {
        let valid = format!("/{}", codec::encode("https://example.com/"));
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let req = request(method.clone(), &valid);
            assert_eq!(route(&req).status(), StatusCode::NOT_FOUND, "{method}");
        }
    }
}
