# ooo-server

A Rust port of `worker.js` — the redirect half of *the ultimate url lengthner*.

```
GET /ooooοооoοᴏοoοᴏοoοᴏooοᴏoᴏoᴏооoоᴏᴏoоᴏᴏοоoοoоᴏоοоoᴏοоᴏᴏ
301 Moved Permanently
location: https://a.co
```

`GET /` serves the bundled UI. Everything else is `404`, except `GET /up`,
which answers `204` for probers.

## Run

```sh
../build.sh
cargo run --release                        # 127.0.0.1:8888, 1024 connections
OOO_ADDR=0.0.0.0:8080 cargo run --release
OOO_MAX_CONNECTIONS=4096 cargo run --release
cargo test
```

Loopback by default: this is plain HTTP with no TLS of its own, so exposing it
should take a deliberate `OOO_ADDR` and something in front of it. `OOO_ADDR` and
`OOO_MAX_CONNECTIONS` are the only configuration, there is no state, and there
are no dependencies past hyper/tokio.

Idle it sits at ~3.6 MB RSS, and the release binary is ~730 KB.

## Why 301 and not 302

The decoding is pure arithmetic. The path *is* the URL — there is no table to
look anything up in, and no state that could ever make the same path resolve
differently. A `302` would be telling clients to come back and ask again about
an answer that cannot change. The only thing that could change a mapping is a
new version marker, and that changes the path.

`301` also outlives the server, which is the point: a cached redirect keeps
resolving while this process is down. The `Cache-Control: immutable` on the
response says the same thing to anything that ignores the status code.

## The codec

A URL is UTF-8 encoded, each byte is written as four base-4 digits, and each
digit is rendered as a homoglyph of the letter o:

| digit | char | code point | UTF-8      |
|-------|------|------------|------------|
| 0     | `o`  | U+006F     | `6f`       |
| 1     | `ο`  | U+03BF     | `ce bf`    |
| 2     | `о`  | U+043E     | `d0 be`    |
| 3     | `ᴏ`  | U+1D0F     | `e1 b4 8f` |

The stream is prefixed with the version marker `oooo`, which is exactly the four
digits of the byte `0x00`, so version handling falls out of the byte loop for
free.

Decoding is one pass over the raw request path — percent-decoding, digit
recognition and byte assembly in a single loop, one allocation, and an early
exit once the length limit is reached. `header_safe` borrows rather than
allocates for pure-ASCII URLs, which is nearly all of them.

### Compatibility with `worker.js`

Every link the worker ever produced still resolves; the reference vectors in
`tests/decode.rs` come from running the original `encodeUrl`.

The Rust decoder resolves a strict superset: `worker.js`'s `Utf8ArrayToStr` has
no branch for 4-byte UTF-8, so it silently drops astral characters — emoji, rare
CJK, musical symbols. Those links encode fine and only ever broke on the way
back out.

## Strictness

A request either names a URL exactly or it names nothing. There is no partial
credit and no error detail — every rejection is a bare `404`:

- anything but `GET` or `HEAD`
- any query string, including a bare `?`
- any character in the path outside the four-o alphabet, including plain ASCII
  `O` and `0`, and lookalikes that share a UTF-8 lead byte (`ν` U+03BD, `ᴎ`
  U+1D0E)
- a malformed percent-escape
- a digit count that is not a multiple of four, or bytes that are not valid UTF-8
- a target that is not an absolute `http`/`https` URL
- a target with credentials in the authority — `https://paypal.com@evil.com/` is
  a phishing disguise, not a URL we forward to
- a malformed host: empty labels, leading/trailing hyphens, a trailing root dot,
  a non-decimal port, or non-ASCII. An internationalised host has to arrive
  already punycoded; doing IDNA here would mean taking a position on homograph
  attacks, in a service whose entire alphabet is homographs of the letter o
- a control character anywhere in the target, which would otherwise be header
  injection

Non-ASCII in the path, query or fragment is fine, and is percent-encoded on the
way into the `Location` header.

### `/up`

The one path that is neither a link nor a `404`. It answers `204`, and it is not
a hole in the policy above: `u` and `p` are outside the o alphabet, so no
encoded link can ever spell `/up` and nothing real is shadowed by it. It is
still subject to everything else — `/up?x=1`, `/UP`, `/up/` and `POST /up` are
all `404`.

`204` because probers read 2xx as up and 404 as down (a Kubernetes `httpGet`
probe counts a 404 as a failure), and because there is nothing to say beyond
"the listener, the parser and the router are alive". The process holds no state
and talks to nothing, so there is no deeper health to report.

## Limits and hardening

Serving a request is pure arithmetic over a few hundred bytes and finishes in
well under a millisecond. Every limit is sized against that: an honest client is
never remotely near one, so they can be tight enough that holding a slot open
buys an attacker nothing.

| Limit | Value | What it stops |
|---|---|---|
| `HEADER_READ_TIMEOUT` | 5s | A slowloris, and connections parked idle to hold a slot |
| `MAX_CONNECTION_LIFETIME` | 60s | A client that sends valid requests but stops reading replies |
| `OOO_MAX_CONNECTIONS` | 1024 | Descriptor and memory exhaustion |
| `MAX_BUF_SIZE` | 128 KB | An oversized request head |

**The header timeout needs a timer.** hyper defaults `header_read_timeout` to
30s, but `Dur::check` silently discards it unless `Builder::timer` is set too —
it emits a `warn!` that goes nowhere without a logging backend and then runs
with no timeout at all. Both are set together in `main.rs`, and
`a_stalled_request_head_is_reaped` fails if either is removed. hyper re-arms the
timer on *every* head read, including the wait for the next request on a
kept-alive connection, so the one setting covers idle sockets as well.

**The connection permit is taken before `accept()`, not after.** At capacity the
listener is not read at all, so surplus connections wait in the kernel backlog
instead of costing a descriptor and a task here; when that backlog fills the
kernel refuses them, which is a faster and more honest answer than a socket that
goes nowhere. Acquiring after accepting would bound concurrent *serving* while
leaving resource use unbounded.

The cap is what makes the worst case finite: `MAX_CONNECTIONS × MAX_BUF_SIZE`,
or 128 MB at the defaults. hyper only grows a connection's buffer past its 8 KB
initial size for a head that needs it, so the realistic figure is ~8 MB. Set it
well under `ulimit -n`. It does not need to be large for throughput — at
sub-millisecond service times one slot sustains thousands of requests per
second, and the number exists to absorb concurrent *connections*, not concurrent
work.

Note that a cap alone would not have fixed the slowloris; it would have turned
memory exhaustion into "an attacker holds all N slots forever". The timeout is
what makes permits actually recycle. The two are one fix.

**Shutdown** handles SIGTERM as well as SIGINT, since that is what an init
system, container runtime or scheduler sends. Live connections are told to
finish the request in flight rather than wait for another, then given
`SHUTDOWN_GRACE` to drain; holding every permit again is how the server knows
they are gone. An idle keep-alive connection is closed at once instead of
running out the clock, so shutdown takes ~30ms rather than the full 5s.

**Panics unwind rather than abort**, so a panic is isolated to the one
connection whose task raised it instead of taking the process down. There is no
shared mutable state between connections, so there is nothing a surviving task
could have corrupted.

**Client-caused failures are not logged.** A reaped slowloris and a hung-up
client are the normal weather on a public port; a log line each would hand
anyone a way to fill the disk from a socket.

### Deliberately not here

- **TLS.** Needs a reverse proxy, which is why the default bind is loopback.
- **Rate limiting.** Behind a proxy every connection arrives from the proxy's
  address, so per-IP limiting *in this process* would be measuring the wrong
  thing. It belongs at the edge, where the real client address is.
- **Metrics and access logs.** Still open; see below.

## Length limits

`codec::MAX_URL_LEN` is 16 KiB. Decoding stops the moment that many bytes exist,
so a long path costs bounded work, and a truncated result never becomes a
redirect — a truncated URL is a different URL, and sending a browser somewhere
the link never pointed is worse than admitting the link does not resolve.

In practice hyper's ceiling binds first, and it is not configurable:
`MAX_URI_LEN` is 65534 bytes of request line. One URL byte becomes four
characters of 1–3 UTF-8 bytes each, which clients then percent-encode at three
characters per non-ASCII byte — about 22 wire bytes per byte of URL. So hyper
answers `414` on its own somewhere north of ~3 KB of original URL, or ~8 KB if
the client sends the o's unescaped. `MAX_URL_LEN` is the backstop behind that,
and the limit that applies to direct users of the codec.

Lifting that ceiling would mean parsing the request line ourselves instead of
using hyper's.

## Container

```sh
cp .env.example .env      # optional; the compose defaults work as-is
docker compose up --build
curl -i localhost:8888/up
```

The build is musl-static in `rust:alpine`, and the final stage is `FROM
scratch` — the binary and nothing else. No TLS out, no DNS, no files and no
clock data are needed at runtime, so there is nothing left in the image to
reach: no shell, no package manager, no libc.

The image sets `OOO_ADDR=0.0.0.0:8888` because inside a container the boundary
is the isolation, and the loopback default would be unreachable from outside.
What the *host* exposes is compose's decision, and `BIND_ADDR` defaults to
`127.0.0.1` there for the same reason it does everywhere else here: this speaks
plain HTTP and wants a proxy or a tunnel in front.

The container runs as `65534:65534`, read-only, with all capabilities dropped
and `no-new-privileges`. `mem_limit` is set above the worst case rather than the
usual case — 512 connections all sending oversized request heads is ~64 MB,
while real traffic sits near 4 MB — so if the container gets OOM-killed there,
that is a signal rather than a tuning problem. `NOFILE` has to stay above
`OOO_MAX_CONNECTIONS`.

There is no Docker `HEALTHCHECK`: a `scratch` image has no shell and no curl, so
there is nothing in it to run one with. `/up` is for a prober that lives outside
the container — a load balancer, a Kubernetes `httpGet` probe, an uptime
monitor.

## Fuzzing

`tests/fuzz.rs` is a dependency-free randomised suite that runs under plain
`cargo test` on stable — a splitmix64 generator and seven input strategies:
arbitrary bytes, a biased alphabet of homoglyphs and escape syntax, byte-level
mutations of valid links, arbitrary Unicode round trips, lengths straddling the
truncation limit, ragged text through `validate`, and structured URLs with
hostile characters injected into them.

It is deterministic by default so any failure is reproducible, and every
assertion prints the seed and the offending input:

```sh
cargo test --test fuzz
OOO_FUZZ_ITERS=5000000 cargo test --release --test fuzz
OOO_FUZZ_SEED=12345 OOO_FUZZ_ITERS=1000000 cargo test --release --test fuzz
```

The invariants are stated independently of the implementation, so a rule that
gets loosened shows up here rather than in production:

- `decode` never panics, on any bytes
- a decoded URL is within `MAX_URL_LEN` and stable under re-encoding
- a truncated result is a prefix of the original, cut on a character boundary
- anything `validate` accepts is an absolute http(s) URL, ASCII-hosted, free of
  credentials, control characters and spaces
- anything `validate` accepts survives `header_safe` as printable ASCII with no
  CR or LF — no header injection
- the service answers `301` or `404` and nothing else, and only `301` carries a
  `Location`

The suite was checked by mutation testing: bugs injected into the truncation
limit, the digit table, the scheme allowlist, the character-boundary trim, the
control-character rule and the non-ASCII host rule are each caught. Two injected
bugs survive, both equivalent mutants — the `@` check is redundant with the host
character check, and the empty-host check is redundant with the empty-label
check.

There is no `cargo-fuzz` target: it needs nightly, which is not set up here, so
adding one would mean shipping scaffolding that has never been run.

`tests/server.rs` covers the limits the same way, against the real binary over a
real socket: a stalled head, an idle keep-alive connection, a full connection
table, and SIGTERM. Each was mutation-checked — removing the timer, the cap or
`graceful_shutdown` fails exactly the test that covers it.

## Still open

Observability. There are no metrics, no access log and no request counters, so a
deployment is flying blind on traffic, status mix and latency. Nothing here
depends on it, but it is what to add next.

## Layout

```
src/codec.rs     encode, decode, validate, header_safe
src/service.rs   routing, the rejection policy, /up
src/main.rs      listener, limits, shutdown, hyper wiring
tests/decode.rs  the codec: vectors, alphabet, truncation, validation
tests/server.rs  end-to-end over a socket against the real binary
tests/fuzz.rs    randomised properties over the codec and the service
Dockerfile       musl static build -> scratch
compose.yml      the deploy; values come from .env
```
