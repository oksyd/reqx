#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "_async", feature = "_blocking")), allow(dead_code))]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable
    )
)]

//! `reqx` is an HTTP transport library for Rust API SDKs. It combines async
//! Hyper and blocking ureq clients with shared retry, redirect, timeout, TLS,
//! streaming, and observability policies. Applications supply their own API
//! models, authentication headers, and service-specific upload backend.
//!
//! # Installation and runtime
//!
//! Requires Rust 1.99.0 or newer. The default transport is async and runs inside
//! an application-owned Tokio runtime with I/O and time enabled:
//!
//! ```text
//! cargo add reqx
//! cargo add tokio --features macros,rt-multi-thread
//! ```
//!
//! JSON helpers use Serde. Add `serde_json` when using JSON values and `serde`
//! with its `derive` feature when deriving request or response model traits.
//! Raw methods and headers use the `http` crate; explicit byte buffers use `bytes`.
//! Declare these as dependencies in your application when naming their types.
//!
//! # Quick start
//!
//! This complete program sends a request and reads a bounded, decoded response:
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! #[tokio::main]
//! async fn main() -> reqx::Result<()> {
//!     use std::time::Duration;
//!
//!     let client = reqx::Client::builder("https://api.example.com/v1")
//!         .request_timeout(Duration::from_secs(3))
//!         .total_timeout(Some(Duration::from_secs(8)))
//!         .build()?;
//!
//!     let response = client.get("/items/42").send().await?;
//!     println!("status={} body={}", response.status(), response.text()?);
//!     Ok(())
//! }
//! # #[cfg(not(feature = "_async"))]
//! # fn main() {}
//! ```
//!
//! For synchronous code, enable `blocking-tls-rustls-ring` and use
//! `reqx::blocking::Client`; the [blocking module](#modules) has a complete example.
//! Blocking operations occupy the calling thread. In async applications, prefer
//! the async client or run blocking operations on a dedicated blocking thread.
//!
//! # API map
//!
//! | Task | Entry point |
//! | --- | --- |
//! | Async requests | `reqx::Client`, `reqx::RequestBuilder` |
//! | Blocking requests | `reqx::blocking::Client`, `reqx::blocking::RequestBuilder` |
//! | Shared client configuration | `reqx::ClientBuilder<T>`; obtain it with `Client::builder(...)` |
//! | Buffered bytes, UTF-8, or JSON | [`Response`] |
//! | Incremental reads or downloads | `reqx::ResponseStream`, `reqx::blocking::ResponseStream` |
//! | Retry, status, and redirect policies | [`prelude::RetryPolicy`], [`prelude::StatusPolicy`], [`prelude::RedirectPolicy`] |
//! | Optional controls and extension contracts | [`advanced`] |
//! | Multipart uploads with your storage backend | `advanced::ResumableUploader` |
//! | Machine-readable failures | [`Error`], [`ErrorCode`], [`TimeoutPhase`] |
//!
//! # Feature Selection
//!
//! Transport modes are selected through concrete transport+TLS feature flags:
//!
//! - Async + `rustls` + `ring`: `async-tls-rustls-ring`
//! - Async + `rustls` + `aws-lc-rs`: `async-tls-rustls-aws-lc-rs`
//! - Async + `rustls` + Graviola: `async-tls-rustls-graviola`
//! - Async + `rustls` + a caller-installed crypto provider: `async-tls-rustls-no-provider`
//! - Async + `native-tls`: `async-tls-native`
//! - Blocking + `ureq` + `rustls` + `ring`: `blocking-tls-rustls-ring`
//! - Blocking + `ureq` + `rustls` + `aws-lc-rs`: `blocking-tls-rustls-aws-lc-rs`
//! - Blocking + `ureq` + `rustls` + Graviola: `blocking-tls-rustls-graviola`
//! - Blocking + `ureq` + `rustls` + a caller-installed crypto provider:
//!   `blocking-tls-rustls-no-provider`
//! - Blocking + `ureq` + `native-tls`: `blocking-tls-native`
//! - gzip response decoding: `compression-gzip` (default)
//! - All response compression codecs: `compression`
//! - Individual codecs: `compression-gzip`, `compression-brotli`, and
//!   `compression-zstd`
//! - Blocking resumable multipart uploads: `resumable-upload`
//! - Async resumable multipart uploads without HTTP/TLS: `resumable-upload-async`
//!
//! - OpenTelemetry metrics and traces: `otel`
//!
//! The default features are `async-tls-rustls-ring` and `compression-gzip`.
//! For a blocking-only client or a different TLS provider, use
//! `default-features = false` and choose a concrete transport feature.
//! `_async` and `_blocking` are internal and cannot be enabled alone.
//! `resumable-upload-async` includes `resumable-upload`; upload features do not
//! require an HTTP transport.
//!
//! TLS backend features are additive. If multiple backends are enabled, choose
//! one with `Client::builder(...).tls_backend(...)`; rustls with `ring` has the
//! highest default priority when available.
//!
//! The docs.rs build enables `async-tls-rustls-ring` and
//! `blocking-tls-rustls-ring`, so async and blocking entry points are both
//! visible there. This documentation build does not change the default features
//! of your application. Check the feature badges on individual APIs.
//!
//! # Defaults and configuration
//!
//! A new builder uses [`advanced::ClientProfile::StandardSdk`]:
//!
//! | Setting | Default |
//! | --- | --- |
//! | Request timeout | 10 seconds for each transport/read phase |
//! | Total deadline | Disabled (`None`) |
//! | Connection timeout | 5 seconds |
//! | Buffered response limit | 8 MiB, applied to both wire and decoded bytes |
//! | Retry attempts | At most 3, including the first attempt, subject to eligibility |
//! | Redirects | Disabled |
//! | Non-2xx statuses | [`prelude::StatusPolicy::Error`] |
//! | TLS trust roots | [`TlsRootStore::BackendDefault`] |
//! | Idle connection retention | 90 seconds, at most 8 idle connections per host |
//! | Fixed/adaptive concurrency, rate limits, retry budget, circuit breaker | Disabled |
//! | In-process metrics and OpenTelemetry emission | Disabled |
//! | Automatic `Accept-Encoding` | Enabled for buffered requests, disabled for streams |
//!
//! Builder setters apply in call order. `profile(...)` replaces the profile's
//! settings at that point. Request-level settings inherit client defaults;
//! `total_timeout(None)` explicitly disables an inherited deadline. Optional
//! controls take `Some(policy)` to enable them and `None` to disable them.
//! See `ClientBuilder` and [`advanced::ClientProfile`] for the full contracts.
//!
//! `build()` validates configuration before creating the client. Parsing helpers
//! such as `try_header`, `no_proxy`, and `resolve_to_addrs` return errors immediately.
//! Request timeout/retry overrides are validated when sending, before queueing or
//! network I/O. A builder owns its configuration; a built client's configuration
//! is immutable.
//!
//! # Execution and ownership
//!
//! Reuse clients. Cloning either client shares its connection pool, configuration,
//! metrics, and concurrency/resilience state. A request builder owns a cheap client
//! clone, so it can outlive the handle that created it. Sending consumes the request
//! builder.
//!
//! Relative request paths append to the configured base path: the quick-start URL
//! is `https://api.example.com/v1/items/42`. An absolute HTTP(S) request URL replaces
//! the base URL. Query helpers percent-encode values and retain repeated keys.
//! Request headers override client defaults. Endpoint selection happens once per
//! logical request; retries use that selected URI unless a redirect changes it.
//!
//! Each send prepares and validates a request, waits for enabled controls, performs
//! transport attempts, handles redirects/retries, and returns either a buffered
//! response or a live response stream. A total deadline includes queue waits,
//! backoff, attempts, and response consumption. Without a total deadline,
//! per-phase timeouts do not bound the entire operation or all queue waits.
//!
//! A buffered request body is replayable. A supplied reader or stream is consumed
//! once and cannot be automatically resent. The default retry eligibility accepts
//! GET, HEAD, PUT, DELETE, OPTIONS, TRACE, or an `Idempotency-Key` header, and also
//! requires a replayable body. Redirect hops have their own limit and do not
//! increment the retry attempt number. Add an idempotency key only when the server implements
//! that contract. Application-level JSON/text decoding errors are not retried.
//! See [`prelude::RetryPolicy`] and [`advanced::RetryEligibility`].
//!
//! # Responses and errors
//!
//! `send()` buffers and decodes HTTP content encodings. `send_stream()` exposes
//! wire bytes after the transport removes HTTP framing. Retryable statuses are
//! handled before applying the final status policy:
//!
//! - [`prelude::StatusPolicy::Error`] rejects a final non-2xx status as
//!   [`Error::HttpStatus`]. Transport, body, and deadline errors may occur first.
//! - [`prelude::StatusPolicy::Response`] returns the final status and body as `Ok`,
//!   including non-2xx responses. It still retries eligible failures and enforces
//!   framing, timeout, decoding, and size limits.
//!
//! Streams implement Tokio `AsyncRead` or standard `Read`, respectively:
//!
//! | Operation | Bytes and limits |
//! | --- | --- |
//! | Stream reader, `into_bytes_limited`, `copy_to_writer`, request `download_to_writer` | Original content-encoded bytes; limited variants cap wire bytes |
//! | `into_response_limited`, `into_text_limited`, `into_json_limited` | Decode supported content encodings; cap both wire and decoded bytes |
//! | `Response::text` / `into_text` | Strict UTF-8; `Content-Type` charset is not used |
//! | `Response::text_lossy` / `into_text_lossy` | Replace invalid UTF-8 sequences |
//! | `Response::json` / request `send_json` | Deserialize decoded bytes with Serde |
//!
//! An explicit limit of zero accepts only an empty body. The client's buffered
//! limit does not automatically limit a raw stream. Consume or drop each stream
//! to release its connection/body resources and concurrency permits. Once a stream
//! has been returned, later read or writer failures are returned to the consumer;
//! the HTTP request is not transparently retried. Reader-trait errors are
//! `std::io::Error` wrapping a typed [`Error`]; stream helper methods return
//! `reqx::Result` directly.
//!
//! Use [`Error::code`] / [`ErrorCode::as_str`] for decisions and telemetry instead of
//! parsing `Display`. Error enums are non-exhaustive; include a fallback when matching.
//! Request URI metadata omits user information, query strings, and fragments.
//! HTTP error body previews and application payloads may still contain sensitive
//! content. [`Error::request_uri_redacted`] is the URI accessor for diagnostics.
//!
//! # Recipes
//!
//! ## JSON request with server-supported idempotency
//!
//! Add `serde_json` to your application. For typed models, enable `serde/derive`:
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! async fn create_item(client: &reqx::Client) -> reqx::Result<serde_json::Value> {
//!     client.post("/items")
//!         .idempotency_key("create-item-42")?
//!         .json(&serde_json::json!({ "name": "example" }))?
//!         .send_json()
//!         .await
//! }
//! # fn main() {}
//! ```
//!
//! ## Inspect a non-success response
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! async fn inspect(client: &reqx::Client) -> reqx::Result<()> {
//!     use reqx::prelude::StatusPolicy;
//!
//!     let response = client.get("/items/missing")
//!         .status_policy(StatusPolicy::Response)
//!         .send().await?;
//!     println!("status={} body={}", response.status(), response.text_lossy());
//!     Ok(())
//! }
//! # fn main() {}
//! ```
//!
//! ## Download wire bytes with a bound
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! async fn download(client: &reqx::Client) -> reqx::Result<Vec<u8>> {
//!     let mut output = Vec::new();
//!     client.get("/export")
//!         .download_to_writer_limited(&mut output, 1024 * 1024).await?;
//!     Ok(output)
//! }
//! # fn main() {}
//! ```
//!
//! For a decoded buffered result, use `send_stream().await?.into_response_limited(limit)`.
//! The analogous blocking operations have the same names without `.await`.
//!
//! # Observability and extensions
//!
//! Enable `.metrics_enabled(true)` for in-process counters. Snapshots are shared
//! across client clones; stream completion is accounted at EOF, failure, or drop.
//! Enable the `otel` feature and `.otel_enabled(true)` for OpenTelemetry emission,
//! and configure your application's global meter/tracer providers and exporters.
//! `reqx` does not install an exporter. These two observability switches are
//! independent. See [`advanced::MetricsSnapshot`].
//!
//! Interceptors and observers are synchronous, inline callbacks, including in the
//! async client. Share them with `Arc<dyn Trait>` and keep callbacks short.
//! Interceptors can mutate request headers; observers receive attempt, retry, and
//! throttling events. Neither replaces checking returned results or stream errors.
//! Optional endpoint/backoff setters take `Some(Arc::new(extension))`; `None`
//! restores the built-in behavior. Contract details and examples are on
//! [`advanced::Interceptor`], [`advanced::Observer`], and [`advanced::EndpointSelector`].
//!
//! # Resumable uploads
//!
//! `resumable-upload` exposes a synchronous backend contract.
//! `resumable-upload-async` additionally exposes an asynchronous contract and
//! includes Tokio I/O independently of HTTP/TLS features. Implement the appropriate
//! backend for your storage protocol and use one `advanced::ResumableUploader`.
//! It uploads parts sequentially and applies its own per-part retry policy.
//!
//! Persist the checkpoint carried by an upload error when available. To resume,
//! reopen or rewind the entire unchanged source to byte zero, and pass the saved
//! checkpoint with the same part size and checksum settings. Only the explicit
//! current checkpoint schema version is supported. Completed chunks are read again
//! and reused when their metadata matches; the uploader does not query remote state.
//! See `advanced::ResumableUploader` and the backend trait documentation for the
//! persistence, retry, checksum, and abort contracts.
//!
//! # TLS Backend Notes
//!
//! - Async `rustls` backends support TLS version bounds via
//!   `Client::builder(...).tls_version(...)`,
//!   `Client::builder(...).tls_min_version(...)`, and
//!   `Client::builder(...).tls_max_version(...)`.
//! - `native-tls` backends do not support [`TlsRootStore::WebPki`].
//! - Async `native-tls` forwards TLS version bounds to the platform TLS stack.
//! - Blocking `ureq` transport does not expose TLS version overrides.
//! - Custom root CAs require [`TlsRootStore::WebPki`],
//!   [`TlsRootStore::System`], or [`TlsRootStore::Specific`].
//! - Rustls backends append custom root CAs to [`TlsRootStore::WebPki`]'s
//!   bundled Mozilla roots. [`TlsRootStore::Specific`] trusts only explicit
//!   custom roots.
//! - PEM root CA and certificate-chain inputs must contain only `CERTIFICATE`
//!   blocks; pass private keys through the dedicated identity key parameter.
//! - Blocking `native-tls` cannot merge custom root CAs into the system trust
//!   store; use [`TlsRootStore::Specific`] when adding explicit roots there.
//! - `async-tls-rustls-graviola` and `blocking-tls-rustls-graviola` configure
//!   Graviola directly per client, without installing a process-wide provider.
//!   Select [`TlsBackend::RustlsGraviola`] when multiple TLS backends are enabled.
//!   Graviola requires a supported `x86_64` or `aarch64` CPU; see its upstream
//!   platform requirements. Use `default-features = false` to avoid enabling ring.
//! - `async-tls-rustls-no-provider` and `blocking-tls-rustls-no-provider`
//!   use the same application-installed provider. Set `default-features = false`
//!   to avoid enabling ring through reqx. When other TLS features are enabled,
//!   explicitly select [`TlsBackend::RustlsNoProvider`]. Neither feature selects
//!   a crypto provider itself;
//!   the application must install one as the process-wide rustls default
//!   (e.g. `rustls::crypto::CryptoProvider::install_default(...)`) before
//!   building a client. If none is installed, building a client returns
//!   [`Error::TlsBackendInit`] instead of panicking.
//!
//! # Source layout and further examples
//!
//! The internal `core` module shares policies, validation, execution state, errors,
//! and metrics. `async_client` and `blocking_client` own the concrete transports;
//! `http` owns response types; `upload` is independent backend orchestration.
//!
//! The [packaged examples](https://docs.rs/crate/reqx/latest/source/examples/)
//! cover proxies, TLS identities, observers, resilience controls, and upload backends.
//! Start with the contracts above and on the linked types; the example sources
//! provide complete application scenarios.

#[cfg(all(
    feature = "_async",
    not(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    ))
))]
compile_error!("`_async` is internal; enable an `async-tls-*` feature instead");

#[cfg(all(
    feature = "_blocking",
    not(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-graviola",
        feature = "blocking-tls-rustls-no-provider",
        feature = "blocking-tls-native"
    ))
))]
compile_error!("`_blocking` is internal; enable a `blocking-tls-*` feature instead");

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

#[cfg(feature = "_async")]
mod async_client;
#[cfg(feature = "_blocking")]
mod blocking_client;
mod core;
mod http;
mod rate_limit;
mod resilience;
mod tls;
#[cfg(feature = "resumable-upload")]
mod upload;

#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
pub use crate::async_client::{Client, RequestBuilder};
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub use crate::core::client_builder::ClientBuilder;
pub use crate::core::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
pub use crate::http::response::Response;
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola",
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
pub use crate::http::response::ResponseStream;
pub use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};

#[cfg(feature = "_blocking")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-graviola",
        feature = "blocking-tls-rustls-no-provider",
        feature = "blocking-tls-native"
    )))
)]
/// Blocking transport API.
///
/// This mirrors the async surface where the underlying transport supports the
/// same behavior, but uses synchronous request execution and response streams.
/// It requires a `blocking-tls-*` feature and does not require a Tokio runtime.
/// Both clients share [`crate::Response`], [`crate::Error`], and policy types.
///
/// For a blocking-only application:
///
/// ```text
/// cargo add reqx --no-default-features --features blocking-tls-rustls-ring,compression-gzip
/// ```
///
/// ```no_run
/// # #[cfg(feature = "_blocking")]
/// fn main() -> reqx::Result<()> {
///     let client = reqx::blocking::Client::builder("https://api.example.com")
///         .total_timeout(Some(std::time::Duration::from_secs(8)))
///         .build()?;
///     let response = client.get("/items/42").send()?;
///     println!("{}", response.text()?);
///     Ok(())
/// }
/// # #[cfg(not(feature = "_blocking"))]
/// # fn main() {}
/// ```
///
/// `Client` clones share a pool and controls across threads. Operations block
/// the caller; async applications should use the async client or offload this
/// client to a blocking thread. The builder documents transport-specific limits.
pub mod blocking {
    pub use crate::blocking_client::{Client, ClientBuilder, RequestBuilder};
    pub use crate::http::response::BlockingResponseStream as ResponseStream;
}

/// Convenient result alias used by `reqx` APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Recommended imports for most SDK transport code.
///
/// Contains the async client when an async transport is enabled, shared response
/// and error types, and the usual retry/status/redirect policies. For blocking
/// requests import `reqx::blocking::Client` explicitly; policy types here work
/// with either client. Advanced controls and upload traits live in [`crate::advanced`].
pub mod prelude {
    pub use crate::Result;
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-rustls-graviola",
            feature = "async-tls-rustls-no-provider",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::async_client::Client;
    #[cfg(feature = "_blocking")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-rustls-graviola",
            feature = "blocking-tls-rustls-no-provider",
            feature = "blocking-tls-native"
        )))
    )]
    pub use crate::blocking;
    pub use crate::core::error::{Error, ErrorCode};
    pub use crate::core::policy::{RedirectPolicy, StatusPolicy};
    pub use crate::core::retry::RetryPolicy;
    pub use crate::http::response::Response;
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-rustls-graviola",
            feature = "async-tls-rustls-no-provider",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::http::response::ResponseStream;
    pub use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};
}

/// Advanced transport controls and extensibility points.
///
/// - [`crate::advanced::ClientProfile`] supplies presets; [`crate::advanced::RetryBudgetPolicy`],
///   [`crate::advanced::CircuitBreakerPolicy`], [`crate::advanced::AdaptiveConcurrencyPolicy`], and [`crate::advanced::RateLimitPolicy`]
///   configure optional controls shared across client clones.
/// - [`crate::advanced::EndpointSelector`], [`crate::advanced::BackoffSource`], [`crate::advanced::Clock`], [`crate::advanced::Interceptor`],
///   [`crate::advanced::Observer`], [`crate::advanced::RetryEligibility`], and [`crate::advanced::RetryClassifier`] define synchronous
///   extension contracts. Builder extension setters accept shared `Arc` handles.
/// - [`crate::advanced::MetricsSnapshot`] describes logical request and stream completion counters.
/// - `ResumableUploader` and backend/checkpoint types require `resumable-upload`;
///   async upload methods additionally require `resumable-upload-async`.
///
/// Concurrency, rate limits, retry budget, and circuit breaker are disabled until
/// explicitly configured with `Some(policy)`. Extension callbacks run inline
/// with requests and must be thread-safe.
pub mod advanced {
    #[cfg(feature = "_async")]
    pub use crate::async_client::builder::AsyncTransportOptions;
    #[cfg(feature = "_blocking")]
    pub use crate::blocking_client::builder::BlockingTransportOptions;
    pub use crate::core::config::ClientProfile;
    pub use crate::core::error::{TimeoutPhase, TransportErrorKind};
    pub use crate::core::extensions::{
        BackoffSource, Clock, EndpointSelector, OtelPathNormalizer, RoundRobinEndpointSelector,
        StandardOtelPathNormalizer, SystemClock,
    };
    #[cfg(feature = "resumable-upload-async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload-async")))]
    pub use crate::upload::AsyncResumableUploadBackend;
    #[cfg(feature = "resumable-upload")]
    #[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload")))]
    pub use crate::upload::{
        BlockingResumableUploadBackend, PartChecksumAlgorithm, RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
        ResumableUploadCheckpoint, ResumableUploadError, ResumableUploadOptions,
        ResumableUploadResult, ResumableUploader, UploadedPart,
    };
    pub use crate::{
        core::metrics::{
            ErrorMetrics, LatencyMetrics, MetricsSnapshot, RequestMetrics, ResponseMetrics,
            TimeoutMetrics,
        },
        core::observe::Observer,
        core::policy::{Interceptor, RedirectPolicy, RequestContext, StatusPolicy},
        core::retry::{
            PermissiveRetryEligibility, RetryClassifier, RetryDecision, RetryEligibility,
            RetryReason, StrictRetryEligibility,
        },
        rate_limit::{RateLimitPolicy, ServerThrottleScope},
        resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy},
        tls::{TlsBackend, TlsRootStore, TlsVersion},
    };
}

#[cfg(test)]
extern crate self as reqx;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
