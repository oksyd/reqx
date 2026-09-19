# reqx

[![crates.io](https://img.shields.io/crates/v/reqx.svg)](https://crates.io/crates/reqx)
[![docs.rs](https://docs.rs/reqx/badge.svg)](https://docs.rs/reqx)
[![CI](https://github.com/oksyd/reqx/actions/workflows/ci.yaml/badge.svg)](https://github.com/oksyd/reqx/actions/workflows/ci.yaml)
[![license](https://img.shields.io/crates/l/reqx.svg)](LICENSE)

HTTP transport for Rust API SDKs. `reqx` provides consistent retry, timeout,
idempotency, proxy, TLS, streaming, and observability behavior across async and
blocking clients.

## Features

- Idempotency-aware retries with `Retry-After`, retry budgets, and circuit breakers
- Per-attempt, response-body, connect, and total timeouts
- Async and blocking clients with buffered and streaming I/O
- Rate limiting, concurrency limits, and multi-endpoint routing
- Rustls or native-tls, including custom CAs and mTLS
- Fixed DNS addresses preserving Host and TLS identity
- Proxies with CIDR exclusions, redirects, size limits, and structured errors
- Metrics, observers, interceptors, and optional OpenTelemetry integration

## Installation

The default build uses the async client with rustls (`ring`) and enables gzip
response decoding:

```bash
cargo add reqx
```

To replace the default transport or TLS backend:

```bash
cargo add reqx --no-default-features --features async-tls-native,compression-gzip
```

| Feature | Transport |
| --- | --- |
| `async-tls-rustls-ring` | Async, rustls with `ring` (default) |
| `async-tls-rustls-aws-lc-rs` | Async, rustls with AWS-LC |
| `async-tls-native` | Async, platform-native TLS |
| `blocking-tls-rustls-ring` | Blocking (`ureq`), rustls with `ring` |
| `blocking-tls-rustls-aws-lc-rs` | Blocking (`ureq`), rustls with AWS-LC |
| `blocking-tls-native` | Blocking (`ureq`), platform-native TLS |

TLS backend features are additive. When several are enabled, select one with
`Client::builder(...).tls_backend(...)`; rustls with `ring` is preferred by
default. Optional capabilities include all-codec `compression`, individual
`compression-*` codecs, `resumable-upload`, and `otel`; enable `otel` before
calling `.otel_enabled(true)`.

## Quick start

```rust
use std::time::Duration;

use reqx::prelude::Client;

async fn fetch_item() -> reqx::Result<()> {
    let client = Client::builder("https://api.example.com")
        .client_name("example-sdk")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(8))
        .build()?;

    let response = client.get("/v1/items/42").send().await?;

    println!("status={} bytes={}", response.status(), response.body().len());
    Ok(())
}
```

`POST` requests are retried only when they can be sent safely; provide an
idempotency key when the API supports one.

## Fixed DNS addresses

Async and blocking clients support `resolve` and `resolve_to_addrs`, preserving
Host and TLS identity without falling back to DNS for configured hostnames:

```rust
let client = Client::builder("https://example.com")
    .resolve_to_addrs("example.com", &validated_addresses)
    .build()?;
```

Accepts 1–16 addresses per hostname; incompatible with proxies. Callers validate
addresses and each redirect destination. See the
[API reference](https://docs.rs/reqx/latest/reqx/struct.ClientBuilder.html#method.resolve_to_addrs)
for details.

## Documentation

- [API reference](https://docs.rs/reqx)
- [Examples](examples/README.md)
- [Changelog](CHANGELOG.md)

Run the async example with `cargo run --example basic_json`. For the blocking
client, run:

```bash
cargo run --example blocking_basic --no-default-features --features blocking-tls-rustls-ring
```

## License

[MIT](LICENSE)
