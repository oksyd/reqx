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
| `async-tls-rustls-graviola` | Async, rustls with Graviola |
| `async-tls-rustls-no-provider` | Async, rustls with a caller-installed provider |
| `async-tls-native` | Async, platform-native TLS |
| `blocking-tls-rustls-ring` | Blocking (`ureq`), rustls with `ring` |
| `blocking-tls-rustls-aws-lc-rs` | Blocking (`ureq`), rustls with AWS-LC |
| `blocking-tls-rustls-graviola` | Blocking, rustls with Graviola |
| `blocking-tls-rustls-no-provider` | Blocking, rustls with a caller-installed provider |
| `blocking-tls-native` | Blocking (`ureq`), platform-native TLS |

TLS backend features are additive. When several are enabled, select one with
`Client::builder(...).tls_backend(...)`; rustls with `ring` is preferred by
default. Optional capabilities include all-codec `compression`, individual
`compression-*` codecs, `resumable-upload`, and `otel`; enable `otel` before
calling `.otel_enabled(true)`.

### Graviola TLS backend

Enable Graviola for either or both transports:

```toml
[dependencies]
reqx = { version = "0.2", default-features = false, features = ["async-tls-rustls-graviola", "blocking-tls-rustls-graviola", "compression-gzip"] }
```

The Graviola backends configure their own provider for each client. They do not
require or modify the process-wide rustls provider:

```rust
fn main() -> reqx::Result<()> {
    let _async_client = reqx::Client::builder("https://example.com")
        .tls_backend(reqx::TlsBackend::RustlsGraviola)
        .build()?;
    let _blocking_client = reqx::blocking::Client::builder("https://example.com")
        .tls_backend(reqx::TlsBackend::RustlsGraviola)
        .build()?;
    Ok(())
}
```

When Graviola is the only TLS backend for a transport, the explicit
`.tls_backend(...)` call is optional. With multiple backends enabled, the default
priority is ring, AWS-LC, native TLS, Graviola, then the caller-installed provider.
Graviola is an optional dependency; the default build continues to use ring.

Graviola builds without a C toolchain. Its supported architectures are `x86_64`
and `aarch64`, with specific CPU instruction requirements; check the
[upstream platform requirements](https://docs.rs/graviola/0.4.1/graviola/#limitations)
for your deployment. Upload checksums and retry jitter remain independent of the
TLS provider.

### Caller-installed crypto provider

Both clients can use the application's process-wide rustls provider, for example
Graviola. Disable default features to avoid enabling `ring` through reqx:

```toml
[dependencies]
reqx = { version = "0.2", default-features = false, features = ["async-tls-rustls-no-provider", "blocking-tls-rustls-no-provider", "compression-gzip"] }
rustls-graviola = "0.4"
```

Install the provider once, during application startup, before building clients:

```rust
fn main() -> reqx::Result<()> {
    rustls_graviola::default_provider()
        .install_default()
        .expect("install the application's rustls provider");

    let _async_client = reqx::Client::builder("https://example.com")
        .tls_backend(reqx::TlsBackend::RustlsNoProvider)
        .build()?;
    let _blocking_client = reqx::blocking::Client::builder("https://example.com")
        .tls_backend(reqx::TlsBackend::RustlsNoProvider)
        .build()?;
    Ok(())
}
```

Enable only the transport features you need. Each no-provider backend is the
default when it is the only TLS backend enabled for that transport. If multiple
backends are enabled, explicitly select `TlsBackend::RustlsNoProvider` as above;
installing a provider does not change the priority of ring, AWS-LC, native TLS, or Graviola.
Cargo features are additive: another dependency can still enable ring or AWS-LC,
so inspect the final application's dependency graph when excluding them matters.

When using this backend, both builders return `Error::TlsBackendInit` if no
provider is installed.
Selecting this backend without its corresponding transport feature returns
`Error::TlsBackendUnavailable`. The provider is process-wide, not configurable
per client. The blocking backend retains its existing TLS-version-override
limitations.

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
