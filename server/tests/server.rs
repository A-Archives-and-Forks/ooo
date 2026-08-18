//! End-to-end tests: boot the real binary and speak HTTP/1.1 to it over a
//! socket, so hyper's own limits are part of what is under test.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ooo::codec;

struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn start() -> Self {
        Server::with_env(&[])
    }

    fn with_env(env: &[(&str, &str)]) -> Self {
        // Bind and drop to claim a port the OS says is free.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ooo-server"));
        cmd.env("OOO_ADDR", &addr);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn ooo-server");
        let server = Server { child, addr };
        server.wait_until_up();
        server
    }

    fn wait_until_up(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(&self.addr).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("server never came up on {}", self.addr);
    }

    /// Open a connection and send a deliberately unfinished request head, so
    /// it occupies a slot until the server reaps it.
    fn stall(&self) -> TcpStream {
        let mut sock = TcpStream::connect(&self.addr).unwrap();
        write!(sock, "GET /oooo HTTP/1.1\r\nHost: ooo.test\r\n").unwrap();
        sock.flush().unwrap();
        sock
    }

    /// How long the connection stays open before the server closes it.
    /// `None` if it was still open when `limit` elapsed.
    fn time_until_closed(sock: &mut TcpStream, limit: Duration) -> Option<Duration> {
        sock.set_read_timeout(Some(limit)).unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 256];
        match sock.read(&mut buf) {
            // Clean EOF, or a reset: either way the server let go.
            Ok(0) | Err(_) => Some(start.elapsed()),
            // Anything else means it answered a request it should not have.
            Ok(n) => panic!("server sent {n} bytes: {:?}", &buf[..n]),
        }
    }

    /// Send a raw request line and return `(status, location)`.
    fn request(&self, method: &str, target: &str) -> (u16, Option<String>) {
        let mut sock = TcpStream::connect(&self.addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = write!(
            sock,
            "{method} {target} HTTP/1.1\r\nHost: ooo.test\r\nConnection: close\r\n\r\n"
        );
        let _ = sock.flush();
        // No half-close: hyper treats an early read EOF as an aborted request
        // and never writes the response. `Connection: close` ends the read.

        // A rejected oversized head makes hyper answer and close at once, so
        // the tail of our write can come back as an RST. Keep whatever arrived.
        let mut raw = Vec::new();
        let _ = sock.read_to_end(&mut raw);
        let mut lines = BufReader::new(raw.as_slice()).lines().map(Result::unwrap);

        let status = lines
            .next()
            .expect("status line")
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .parse()
            .unwrap();
        let location = lines.find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("location")
                .then(|| value.trim().to_string())
        });
        (status, location)
    }
}

/// Percent-encode everything a browser would, so the request line is pure ASCII.
fn wire(encoded: &str) -> String {
    let mut out = String::new();
    for b in encoded.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[test]
fn end_to_end() {
    let server = Server::start();
    let url = "https://anthropic.com/news?x=1&y=2#z";
    let encoded = codec::encode(url);

    // The o's sent raw, and sent percent-encoded the way a browser sends them.
    for target in [format!("/{encoded}"), format!("/{}", wire(&encoded))] {
        assert_eq!(
            server.request("GET", &target),
            (301, Some(url.to_string())),
            "GET {}...",
            &target[..20]
        );
    }

    // HEAD resolves like GET.
    let (status, location) = server.request("HEAD", &format!("/{encoded}"));
    assert_eq!((status, location), (301, Some(url.to_string())));

    // The root serves the UI.
    assert_eq!(server.request("GET", "/"), (200, None));
    assert_eq!(server.request("HEAD", "/"), (200, None));

    // Everything else is a 404, with no Location to follow.
    for (method, target) in [
        ("GET", format!("/{encoded}?utm_source=x")),
        ("GET", format!("/{encoded}?")),
        ("GET", format!("/{encoded}O")),
        ("GET", "/favicon.ico".to_string()),
        ("GET", "/oooo".to_string()),
        ("POST", format!("/{encoded}")),
        ("DELETE", format!("/{encoded}")),
    ] {
        let (status, location) = server.request(method, &target);
        assert_eq!(status, 404, "{method} {target:.30}");
        assert_eq!(location, None, "{method} {target:.30}");
    }
}

#[test]
fn a_url_over_hypers_uri_ceiling_is_refused_not_followed() {
    let server = Server::start();
    // Encodes to ~80 KB: past hyper's non-configurable MAX_URI_LEN of 65534,
    // but still inside MAX_BUF_SIZE, so hyper parses the line and rejects the
    // URI rather than giving up on the head.
    let url = format!("https://a.co/{}", "x".repeat(10_000));
    let target = format!("/{}", codec::encode(&url));

    let (status, location) = server.request("GET", &target);
    // hyper rejects the request line before our handler runs: 414 if it parses
    // the line and finds the URI over MAX_URI_LEN, 431 if the line overruns the
    // read buffer first. Which one is hyper's business; what matters here is
    // that no redirect to a truncated URL is ever produced.
    assert!(status == 414 || status == 431, "unexpected status {status}");
    assert_eq!(location, None);
}


/// The one path that is not a link and not a 404.
#[test]
fn the_health_endpoint_answers_over_the_wire() {
    let server = Server::start();

    for method in ["GET", "HEAD"] {
        let (status, location) = server.request(method, "/up");
        assert_eq!(status, 204, "{method} /up");
        assert_eq!(location, None);
    }

    // Still bound by the policy: it is a probe, not an escape hatch.
    for (method, target) in [
        ("GET", "/up?x=1"),
        ("GET", "/up/"),
        ("GET", "/UP"),
        ("POST", "/up"),
    ] {
        assert_eq!(server.request(method, target).0, 404, "{method} {target}");
    }
}

// ------------------------------------------------------------ resource use --

/// The header timeout has to be real. hyper defaults it to 30s but silently
/// drops it unless a timer is installed, which is exactly the mistake this
/// guards against.
#[test]
fn a_stalled_request_head_is_reaped() {
    let server = Server::start();
    let mut sock = server.stall();
    let closed = Server::time_until_closed(&mut sock, Duration::from_secs(20))
        .expect("slowloris held the connection open");
    assert!(
        closed < Duration::from_secs(15),
        "took {closed:?} to reap a stalled head"
    );
}

/// The same timer covers a connection that made one request and then parked
/// itself to hold a slot.
#[test]
fn an_idle_keep_alive_connection_is_reaped() {
    let server = Server::start();
    let mut sock = TcpStream::connect(&server.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    // A complete request, and no `Connection: close`, so the socket stays up.
    write!(sock, "GET /not-ooo HTTP/1.1\r\nHost: ooo.test\r\n\r\n").unwrap();
    sock.flush().unwrap();
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).unwrap();
    assert!(n > 0, "no response to the first request");

    let closed = Server::time_until_closed(&mut sock, Duration::from_secs(20))
        .expect("idle connection was never reaped");
    assert!(
        closed < Duration::from_secs(15),
        "took {closed:?} to reap an idle connection"
    );
}

/// At capacity the listener stops accepting, so surplus connections wait in the
/// kernel backlog instead of consuming a descriptor here - and a freed slot has
/// to be handed straight to whoever is waiting.
#[test]
fn connections_are_capped_and_slots_are_reused() {
    let server = Server::with_env(&[("OOO_MAX_CONNECTIONS", "2")]);
    // The readiness probe's connection needs a moment to give its slot back.
    std::thread::sleep(Duration::from_millis(300));

    let held: Vec<TcpStream> = (0..2).map(|_| server.stall()).collect();

    let mut over = TcpStream::connect(&server.addr).unwrap();
    over.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write!(over, "GET /not-ooo HTTP/1.1\r\nHost: ooo.test\r\n\r\n").unwrap();
    over.flush().unwrap();
    let mut buf = [0u8; 256];
    assert!(
        over.read(&mut buf).is_err(),
        "served a connection while every slot was taken"
    );

    // Free the slots; the waiting connection must now be picked up.
    drop(held);
    over.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let n = over.read(&mut buf).expect("never served after a slot freed");
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 404"),
        "unexpected response: {:?}",
        &buf[..n]
    );
}

/// A scheduler or init system says stop with SIGTERM, and an idle keep-alive
/// connection must not hold the process open for the whole grace period.
#[cfg(unix)]
#[test]
fn sigterm_shuts_down_promptly() {
    let mut server = Server::start();
    let mut sock = TcpStream::connect(&server.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(sock, "GET /not-ooo HTTP/1.1\r\nHost: ooo.test\r\n\r\n").unwrap();
    sock.flush().unwrap();
    let n = sock.read(&mut [0u8; 256]).unwrap();
    assert!(n > 0, "no response to the first request");

    let start = Instant::now();
    Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .expect("send SIGTERM");

    let deadline = start + Duration::from_secs(15);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success(), "exited with {status}");
            let elapsed = start.elapsed();
            // Well inside SHUTDOWN_GRACE: `graceful_shutdown` closes the idle
            // connection at once rather than letting it run out the clock.
            assert!(
                elapsed < Duration::from_secs(5),
                "took {elapsed:?} to shut down"
            );
            return;
        }
        assert!(Instant::now() < deadline, "did not exit after SIGTERM");
        std::thread::sleep(Duration::from_millis(20));
    }
}
