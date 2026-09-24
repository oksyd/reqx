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

//! `reqx` is a reusable HTTP transport crate for Rust API SDKs with retry,
//! timeout, idempotency, proxy, streaming, and pluggable TLS backends.
//!
//! # Quick Start
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use reqx::prelude::{Client, RetryPolicy};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! struct CreateItemResponse {
//!     id: String,
//! }
//!
//!     let client = Client::builder("https://api.example.com")
//!         .client_name("my-sdk")
//!         .request_timeout(Duration::from_secs(3))
//!         .total_timeout(Duration::from_secs(8))
//!         .retry_policy(
//!             RetryPolicy::standard()
//!                 .max_attempts(3)
//!                 .base_backoff(Duration::from_millis(100))
//!                 .max_backoff(Duration::from_millis(800)),
//!         )
//!         .build()?;
//!
//!     let created: CreateItemResponse = client
//!         .post("/v1/items")
//!         .idempotency_key("create-item-001")?
//!         .json(&serde_json::json!({ "name": "demo" }))?
//!         .send_json()
//!         .await?;
//!
//!     println!("created id={}", created.id);
//!     Ok(())
//! # }
//! ```
//!
//! # Recommended Defaults
//!
//! - Use `RetryPolicy::standard()` for SDK traffic.
//! - Set both request timeout and total timeout.
//! - For `POST` retries, always set `idempotency_key(...)`.
//! - Reach for [`advanced`] when you need non-default transport controls.
//!
//! # Common Tasks
//!
//! Start from these entry points:
//!
//! - Build an async client: [`Client::builder`]
//! - Build a blocking client: `reqx::blocking::Client::builder(...)`
//! - Prepare requests: [`RequestBuilder`] and `reqx::blocking::RequestBuilder`
//! - Handle buffered responses: [`Response`]
//! - Handle streaming responses: [`ResponseStream`] and `reqx::blocking::ResponseStream`
//! - Tune retries: [`prelude::RetryPolicy`] and [`advanced::RetryClassifier`]
//! - Configure TLS: [`TlsBackend`], [`TlsVersion`], and [`TlsRootStore`]
//! - Add advanced hooks: [`advanced::Interceptor`], [`advanced::Observer`], and [`advanced::EndpointSelector`]
//!
//! # Feature Selection
//!
//! Transport modes are selected through concrete transport+TLS feature flags:
//!
//! - Async + `rustls` + `ring`: `async-tls-rustls-ring`
//! - Async + `rustls` + `aws-lc-rs`: `async-tls-rustls-aws-lc-rs`
//! - Async + `rustls` + a caller-installed crypto provider (e.g. the
//!   pure-Rust `rustls-graviola`): `async-tls-rustls-no-provider`
//! - Async + `native-tls`: `async-tls-native`
//! - Blocking + `ureq` + `rustls` + `ring`: `blocking-tls-rustls-ring`
//! - Blocking + `ureq` + `rustls` + `aws-lc-rs`: `blocking-tls-rustls-aws-lc-rs`
//! - Blocking + `ureq` + `rustls` + a caller-installed crypto provider:
//!   `blocking-tls-rustls-no-provider`
//! - Blocking + `ureq` + `native-tls`: `blocking-tls-native`
//! - gzip response decoding: `compression-gzip` (default)
//! - All response compression codecs: `compression`
//! - Individual codecs: `compression-gzip`, `compression-brotli`, and
//!   `compression-zstd`
//! - Resumable multipart uploads: `resumable-upload`
//!
//! TLS backend features are additive. If multiple backends are enabled, choose
//! one with `Client::builder(...).tls_backend(...)`; rustls with `ring` has the
//! highest default priority when available.
//!
//! The docs.rs build enables `async-tls-rustls-ring` and
//! `blocking-tls-rustls-ring`, so async and blocking entry points are both
//! visible there.
//!
//! # Cookbook
//!
//! Scenario-focused examples ship in `examples/`:
//!
//! - JSON request flow: `examples/basic_json.rs`
//! - Per-request overrides: `examples/request_overrides.rs`
//! - Streaming uploads/downloads: `examples/streaming.rs` and `examples/blocking_streaming.rs`
//! - Proxy and `no_proxy`: `examples/proxy_and_no_proxy.rs`
//! - TLS backend selection and mTLS: `examples/tls_backends.rs` and `examples/custom_ca_mtls.rs`
//! - Metrics and observers: `examples/metrics_snapshot.rs` and `examples/profile_and_observer.rs`
//! - Retry and resilience controls: `examples/resilience_controls.rs`, `examples/retry_classifier.rs`, and `examples/rate_limit_429.rs`
//! - Resumable uploads: `examples/resumable_upload.rs`
//!
//! The full scenario index lives in `examples/README.md`.
//!
//! # TLS Backend Notes
//!
//! - Async `rustls` backends support TLS version bounds via
//!   `Client::builder(...).tls_version(...)`,
//!   `Client::builder(...).tls_min_version(...)`, and
//!   `Client::builder(...).tls_max_version(...)`.
//! - `native-tls` backends do not support [`TlsRootStore::WebPki`].
//! - Async `native-tls` forwards TLS version bounds to the platform TLS stack.
//! - Blocking `ureq` transport currently rejects TLS version bounds at
//!   `build()` time.
//! - Custom root CAs require [`TlsRootStore::WebPki`],
//!   [`TlsRootStore::System`], or [`TlsRootStore::Specific`].
//! - Rustls backends append custom root CAs to [`TlsRootStore::WebPki`]'s
//!   bundled Mozilla roots. [`TlsRootStore::Specific`] trusts only explicit
//!   custom roots.
//! - PEM root CA and certificate-chain inputs must contain only `CERTIFICATE`
//!   blocks; pass private keys through the dedicated identity key parameter.
//! - Blocking `native-tls` cannot merge custom root CAs into the system trust
//!   store; use [`TlsRootStore::Specific`] when adding explicit roots there.
//! - `async-tls-rustls-no-provider` and `blocking-tls-rustls-no-provider`
//!   use the same application-installed provider. Set `default-features = false`
//!   to avoid enabling ring through reqx. When other TLS features are enabled,
//!   explicitly select [`TlsBackend::RustlsNoProvider`]. Neither feature selects
//!   a crypto provider itself;
//!   the application must install one as the process-wide rustls default
//!   (e.g. `rustls::crypto::CryptoProvider::install_default(...)`) before
//!   building a client. If none is installed, building a client returns
//!   [`Error::TlsBackendInit`] instead of panicking.

#[cfg(all(
    feature = "_async",
    not(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
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
        feature = "async-tls-rustls-no-provider",
        feature = "async-tls-native"
    )))
)]
pub use crate::async_client::{Client, ClientBuilder, RequestBuilder};
pub use crate::core::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
pub use crate::http::response::Response;
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
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
        feature = "blocking-tls-rustls-no-provider",
        feature = "blocking-tls-native"
    )))
)]
/// Blocking transport API.
///
/// This mirrors the async surface where the underlying transport supports the
/// same behavior, but uses synchronous request execution and response streams.
pub mod blocking {
    pub use crate::blocking_client::{Client, ClientBuilder, RequestBuilder};
    pub use crate::http::response::BlockingResponseStream as ResponseStream;
}

/// Convenient result alias used by `reqx` APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Recommended imports for most SDK transport code.
pub mod prelude {
    pub use crate::Result;
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
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
            feature = "async-tls-rustls-no-provider",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::http::response::ResponseStream;
    pub use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};
}

/// Advanced transport controls and extensibility points.
pub mod advanced {
    pub use crate::core::config::ClientProfile;
    pub use crate::core::error::{TimeoutPhase, TransportErrorKind};
    pub use crate::core::extensions::{
        BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer, PolicyBackoffSource,
        PrimaryEndpointSelector, RoundRobinEndpointSelector, StandardBodyCodec,
        StandardOtelPathNormalizer, SystemClock,
    };
    #[cfg(all(feature = "_async", feature = "resumable-upload"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "resumable-upload",
            any(
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs",
                feature = "async-tls-rustls-no-provider",
                feature = "async-tls-native"
            )
        )))
    )]
    pub use crate::upload::{AsyncResumableUploadBackend, AsyncResumableUploader};
    #[cfg(feature = "resumable-upload")]
    #[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload")))]
    pub use crate::upload::{
        BlockingResumableUploadBackend, BlockingResumableUploader, PartChecksumAlgorithm,
        RESUMABLE_UPLOAD_CHECKPOINT_VERSION, ResumableUploadCheckpoint, ResumableUploadError,
        ResumableUploadOptions, ResumableUploadResult, UploadedPart,
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
#[path = "../tests/support/mod.rs"]
mod test_support;
