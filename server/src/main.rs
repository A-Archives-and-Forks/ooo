//! ooo redirect server - see [`ooo::service`] for the routing and rejection
//! policy, and [`ooo::codec`] for the encoding.
//!
//! The work per request is pure arithmetic on a few hundred bytes and finishes
//! in well under a millisecond. Every limit below is sized against that fact:
//! an honest client is never anywhere near them, so they can be set tight
//! enough to make holding a slot open pointless.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use ooo::service;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};

/// Loopback by default: this is plain HTTP with no TLS of its own, so exposing
/// it should take a deliberate `OOO_ADDR` and something in front of it.
const DEFAULT_ADDR: &str = "127.0.0.1:8888";

/// Concurrent connections, overridable with `OOO_MAX_CONNECTIONS`.
///
/// This is the ceiling on file descriptors and on memory: worst case is
/// `MAX_CONNECTIONS * MAX_BUF_SIZE`, which at these defaults is 128 MB, though
/// hyper only grows a connection's buffer past its 8 KB initial size for a
/// request head that needs it, so the realistic figure is ~8 MB. Set it well
/// under `ulimit -n`.
///
/// It does not need to be large for throughput. At sub-millisecond service
/// times a single slot sustains thousands of requests per second; the number
/// exists to absorb concurrent *connections*, not concurrent work.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Read buffer ceiling: the longest request line hyper will accept
/// (`MAX_URI_LEN` is 65534 and is not configurable) plus room for headers.
///
/// That ceiling, not `codec::MAX_URL_LEN`, is what callers hit first. One URL
/// byte becomes four characters, and those characters are 1-3 UTF-8 bytes
/// each, which clients then percent-encode to three characters per non-ASCII
/// byte. For an ASCII URL that works out to ~22 wire bytes per byte of URL, so
/// hyper answers `414` on its own somewhere north of ~3 KB of original URL
/// (~8 KB if the client sends the o's unescaped).
const MAX_BUF_SIZE: usize = 1 << 17;

/// How long a client may take to deliver a request head.
///
/// hyper arms this timer on every head read, including the read that waits for
/// the next request on a kept-alive connection, so one setting covers both the
/// slowloris - a head dribbled out a byte at a time, forever - and a connection
/// parked idle to hold its slot. Five seconds is roughly five thousand times
/// what an honest request needs.
///
/// hyper defaults this to 30s but silently drops it unless a [`TokioTimer`] is
/// installed too, which is why both appear together below.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard ceiling on one connection, whatever it is doing.
///
/// The header timeout does not cover a client that sends valid requests but
/// stops reading the responses, leaving our writes blocked against a closed
/// window. Nothing legitimate here needs a minute: a browser that gets cut off
/// reconnects without the user noticing.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

/// How long in-flight connections get to finish after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = env_or("OOO_ADDR", DEFAULT_ADDR.to_string()).parse()?;
    let max_connections = env_or("OOO_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS);
    if max_connections == 0 || u32::try_from(max_connections).is_err() {
        return Err("OOO_MAX_CONNECTIONS must be between 1 and 2^32-1".into());
    }

    let listener = TcpListener::bind(addr).await?;
    eprintln!(
        "ooo listening on http://{} (max {max_connections} connections)",
        listener.local_addr()?
    );

    let limit = Arc::new(Semaphore::new(max_connections));
    // Held by `main` for the whole run, so a receiver's `changed()` never
    // resolves early on a dropped sender.
    let (shutdown, _) = watch::channel(false);

    let signal = terminate();
    tokio::pin!(signal);

    loop {
        // Take the slot *before* accepting. At capacity we stop reading the
        // listener at all, so surplus connections wait in the kernel's backlog
        // rather than costing us a file descriptor and a task here - and once
        // that backlog fills, the kernel refuses them outright, which is a
        // faster and more honest answer than a socket that goes nowhere.
        let permit = tokio::select! {
            biased;
            _ = &mut signal => break,
            permit = limit.clone().acquire_owned() => permit.expect("semaphore is never closed"),
        };

        let stream = tokio::select! {
            biased;
            _ = &mut signal => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                // Transient errors (EMFILE, ECONNABORTED) must not take the
                // listener down.
                Err(e) => {
                    eprintln!("accept: {e}");
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);

        let shutdown_rx = shutdown.subscribe();
        tokio::spawn(async move {
            // Dropped when the connection ends, returning the slot.
            let _permit = permit;
            serve(stream, shutdown_rx).await;
        });
    }

    // Stop accepting, tell live connections to finish what they are doing
    // rather than wait for another request, and give them a moment. Holding
    // every permit means every connection task has ended.
    eprintln!("shutting down");
    let _ = shutdown.send(true);
    let drained = tokio::time::timeout(
        SHUTDOWN_GRACE,
        limit.acquire_many(max_connections as u32),
    )
    .await;
    if drained.is_err() {
        eprintln!("shutdown: grace period expired with connections still open");
    }

    Ok(())
}

async fn serve(stream: TcpStream, mut shutdown: watch::Receiver<bool>) {
    let conn = http1::Builder::new()
        // The timer is what makes `header_read_timeout` real; without it hyper
        // logs a warning nobody sees and runs with no timeout at all.
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_BUF_SIZE)
        .serve_connection(TokioIo::new(stream), service_fn(handle));
    let mut conn = std::pin::pin!(conn);

    let served = tokio::time::timeout(MAX_CONNECTION_LIFETIME, async {
        loop {
            tokio::select! {
                res = conn.as_mut() => return res,
                // On a `changed()` error the sender is gone, the pattern fails
                // to match, and select drops this branch instead of spinning.
                Ok(()) = shutdown.changed() => conn.as_mut().graceful_shutdown(),
            }
        }
    })
    .await;

    match served {
        Ok(Ok(())) => {}
        // A client that hangs up mid-request, or sits on a slot until the
        // timer reaps it, is the normal weather on a public port. Logging it
        // would hand anyone a way to fill the disk from a socket.
        Ok(Err(e)) if e.is_incomplete_message() || e.is_timeout() => {}
        Ok(Err(e)) => eprintln!("connection: {e}"),
        Err(_) => {}
    }
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(service::route(&req))
}

/// SIGTERM as well as SIGINT: an init system, a container runtime or a
/// scheduler all say stop with SIGTERM, and a process that ignores it gets
/// killed outright once the grace period runs out.
async fn terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
