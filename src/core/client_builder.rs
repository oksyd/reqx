use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Uri};

use crate::core::config::{
    ClientProfile, DEFAULT_CLIENT_NAME, DEFAULT_CONNECT_TIMEOUT, DEFAULT_POOL_IDLE_TIMEOUT,
    DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_STREAM_DEADLINE_SLACK, default_headers_with_user_agent,
    validate_timeout_config,
};
use crate::core::dns::DnsOverrides;
use crate::core::error::Error;
use crate::core::extensions::{
    BackoffSource, Clock, EndpointSelector, OtelPathNormalizer, StandardOtelPathNormalizer,
    SystemClock,
};
use crate::core::observe::Observer;
use crate::core::policy::{Interceptor, RedirectPolicy, StatusPolicy};
use crate::core::proxy::{NoProxyRule, parse_no_proxy_rule, parse_no_proxy_rules};
use crate::core::retry::{
    PermissiveRetryEligibility, RetryEligibility, RetryPolicy, StrictRetryEligibility,
};
use crate::core::util::{
    mark_sensitive_header_value, parse_header_name, parse_header_value, validate_base_url,
    validate_http_proxy_uri,
};
use crate::rate_limit::{RateLimitPolicy, ServerThrottleScope};
use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy};
use crate::tls::{TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore};

/// Shared client configuration with transport-specific settings.
///
/// Obtain a builder from the async or blocking client's `builder()` method.
/// `T` is `advanced::AsyncTransportOptions` or `advanced::BlockingTransportOptions`;
/// it is normally inferred. Blocking code also has the `blocking::ClientBuilder`
/// type alias. Each transport exposes only the settings it supports.
///
/// Common defaults are listed in the [crate documentation](crate). Setters apply
/// in call order and `build()` validates the completed configuration. `no_proxy`
/// and DNS override setters return `Result` for invalid arguments immediately.
/// After building, client clones share immutable settings and control state.
///
/// A common configuration helper needs no adapter trait:
///
/// ```
/// # #[cfg(any(feature = "_async", feature = "_blocking"))]
/// fn configure<T>(builder: reqx::ClientBuilder<T>) -> reqx::ClientBuilder<T> {
///     builder
///         .request_timeout(std::time::Duration::from_secs(3))
///         .total_timeout(Some(std::time::Duration::from_secs(8)))
///         .max_in_flight(Some(16))
/// }
/// ```
pub struct ClientBuilder<T> {
    pub(crate) base_url: String,
    pub(crate) default_headers: HeaderMap,
    pub(crate) buffered_auto_accept_encoding: bool,
    pub(crate) stream_auto_accept_encoding: bool,
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) stream_deadline_slack: Duration,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) pool_idle_timeout: Duration,
    pub(crate) pool_max_idle_per_host: usize,
    pub(crate) http_proxy: Option<Uri>,
    pub(crate) dns_overrides: crate::core::dns::DnsOverridesBuilder,
    pub(crate) no_proxy_rules: Vec<NoProxyRule>,
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) retry_eligibility: Arc<dyn RetryEligibility>,
    pub(crate) retry_budget_policy: Option<RetryBudgetPolicy>,
    pub(crate) circuit_breaker_policy: Option<CircuitBreakerPolicy>,
    pub(crate) adaptive_concurrency_policy: Option<AdaptiveConcurrencyPolicy>,
    pub(crate) global_rate_limit_policy: Option<RateLimitPolicy>,
    pub(crate) per_host_rate_limit_policy: Option<RateLimitPolicy>,
    pub(crate) server_throttle_scope: ServerThrottleScope,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) default_status_policy: StatusPolicy,
    pub(crate) tls_backend: TlsBackend,
    pub(crate) tls_options: TlsOptions,
    pub(crate) endpoint_selector: Option<Arc<dyn EndpointSelector>>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) backoff_source: Option<Arc<dyn BackoffSource>>,
    pub(crate) client_name: String,
    pub(crate) max_in_flight: Option<usize>,
    pub(crate) max_in_flight_per_host: Option<usize>,
    pub(crate) metrics_enabled: bool,
    pub(crate) otel_enabled: bool,
    pub(crate) otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    pub(crate) interceptors: Vec<Arc<dyn Interceptor>>,
    pub(crate) observers: Vec<Arc<dyn Observer>>,
    pub(crate) transport_options: T,
}

impl<T> ClientBuilder<T> {
    pub(crate) fn new(
        base_url: impl Into<String>,
        transport_options: T,
        tls_backend: TlsBackend,
    ) -> Self {
        let defaults = ClientProfile::default().defaults();
        Self {
            base_url: base_url.into(),
            default_headers: HeaderMap::new(),
            buffered_auto_accept_encoding: true,
            stream_auto_accept_encoding: false,
            request_timeout: defaults.request_timeout,
            total_timeout: defaults.total_timeout,
            stream_deadline_slack: DEFAULT_STREAM_DEADLINE_SLACK,
            max_response_body_bytes: defaults.max_response_body_bytes,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            http_proxy: None,
            dns_overrides: crate::core::dns::DnsOverridesBuilder::default(),
            no_proxy_rules: Vec::new(),
            retry_policy: defaults.retry_policy,
            retry_eligibility: Arc::new(StrictRetryEligibility),
            retry_budget_policy: None,
            circuit_breaker_policy: None,
            adaptive_concurrency_policy: None,
            global_rate_limit_policy: None,
            per_host_rate_limit_policy: None,
            server_throttle_scope: ServerThrottleScope::Auto,
            redirect_policy: defaults.redirect_policy,
            default_status_policy: defaults.status_policy,
            tls_backend,
            tls_options: TlsOptions::default(),
            endpoint_selector: None,
            clock: Arc::new(SystemClock),
            backoff_source: None,
            client_name: DEFAULT_CLIENT_NAME.to_owned(),
            max_in_flight: None,
            max_in_flight_per_host: None,
            metrics_enabled: false,
            otel_enabled: false,
            otel_path_normalizer: Arc::new(StandardOtelPathNormalizer),
            interceptors: Vec::new(),
            observers: Vec::new(),
            transport_options,
        }
    }

    /// Sets the per-attempt request timeout.
    ///
    /// Defaults to 10 seconds. The transport and buffered body-read phases each
    /// receive a timeout capped by the remaining total deadline. Streaming reads
    /// also use a per-read timeout; this value alone does not bound queue waits,
    /// all retries, or the lifetime of a response stream.
    /// A zero duration is rejected by `build()`.
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    /// Sets the overall request deadline, including retries and redirects.
    ///
    /// `None` disables the overall deadline. Per-attempt timeouts still apply.
    ///
    /// Disabled by default. Includes concurrency/rate-limit queue waits, retry
    /// backoff, redirects, transport work, and body consumption. Starts after
    /// request preparation; caller serialization and endpoint callbacks are not
    /// covered. For a returned stream the original deadline continues to apply.
    /// Blocking I/O adapters can check the deadline around caller-owned
    /// reads/writes, but cannot interrupt arbitrary user code inside those calls.
    /// A zero duration is rejected by `build()`.
    pub fn total_timeout(mut self, total_timeout: Option<Duration>) -> Self {
        self.total_timeout = total_timeout;
        self
    }

    /// Tunes near-deadline classification for streaming body reads.
    ///
    /// This only affects how ambiguous boundary cases are classified between
    /// `Timeout(ResponseBody)` and `DeadlineExceeded` when the total deadline is
    /// already the tighter bound for the current read. The default is a small
    /// 10ms jitter buffer; changing it does not shorten the actual time spent
    /// waiting on the runtime's transport timers.
    pub fn stream_deadline_slack(mut self, stream_deadline_slack: Duration) -> Self {
        self.stream_deadline_slack = stream_deadline_slack;
        self
    }

    /// Sets the default buffered response body size limit in bytes.
    ///
    /// Defaults to 8 MiB. Both received and decompressed bodies must fit the
    /// limit. Zero accepts only an empty body. This setting applies to `send()`;
    /// raw streaming reads and downloads need their own explicit limit. Use a
    /// stream's `into_response_limited` to bound wire and decoded bytes together.
    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = max_response_body_bytes;
        self
    }

    /// Sets the connect timeout used before a socket is established.
    ///
    /// A zero duration is rejected by `build()`.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Sets how long idle pooled connections may be kept alive.
    ///
    /// A zero duration disables idle connection retention.
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.pool_idle_timeout = pool_idle_timeout;
        self
    }

    /// Sets the maximum number of idle pooled connections kept per host.
    ///
    /// Zero disables per-host idle connection retention.
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.pool_max_idle_per_host = pool_max_idle_per_host;
        self
    }

    /// Overrides DNS for one hostname with a single socket address.
    ///
    /// See [`Self::resolve_to_addrs`] for validation, ports, redirects and proxy limitations.
    pub fn resolve(self, domain: &str, address: std::net::SocketAddr) -> crate::Result<Self> {
        self.resolve_to_addrs(domain, &[address])
    }

    /// Overrides DNS for a hostname with 1 to 16 IPv4 and/or IPv6 socket addresses.
    ///
    /// Only these addresses may be used for the hostname, including retries and
    /// new connections. Connection failures never fall back to system DNS.
    /// Unconfigured hostnames retain the default resolver behavior.
    ///
    /// The URL, default Host/HTTP authority, TLS SNI and certificate identity
    /// retain the original hostname. Explicit URL ports override address ports;
    /// otherwise a nonzero address port is used, or 80/443 when it is zero.
    /// Address selection order is not guaranteed.
    ///
    /// Hostnames match exactly after IDNA conversion, ASCII case folding and
    /// removal of one trailing dot. URLs, IP literals and wildcards are invalid
    /// keys. A later valid entry replaces an earlier entry for the same hostname.
    /// Invalid keys and empty or overlong lists return
    /// [`crate::Error::InvalidDnsOverrideConfig`] immediately. Combining overrides
    /// with `http_proxy` (even with `no_proxy`) is rejected by `build()`.
    ///
    /// Overrides are immutable for the lifetime of the client and its clones.
    /// Redirect policy is unchanged: each redirect uses its destination hostname's
    /// configuration. For untrusted URLs, disable automatic redirects and validate
    /// every new destination. Address access policy belongs to the caller.
    ///
    /// ```
    /// # #[cfg(feature = "_async")]
    /// # fn pinned(validated: &[std::net::SocketAddr]) -> reqx::Result<()> {
    /// let client = reqx::Client::builder("https://example.com")
    ///     .resolve_to_addrs("example.com", validated)?
    ///     .redirect_policy(reqx::prelude::RedirectPolicy::none())
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn resolve_to_addrs(
        mut self,
        domain: &str,
        addresses: &[std::net::SocketAddr],
    ) -> crate::Result<Self> {
        self.dns_overrides.insert(domain, addresses)?;
        Ok(self)
    }

    /// Routes requests through the given HTTP proxy.
    ///
    /// Async transport does not read proxy credentials from the URI; configure
    /// its `proxy_authorization` setting. Blocking transport uses credentials
    /// in the proxy URI.
    pub fn http_proxy(mut self, proxy_uri: Uri) -> Self {
        self.http_proxy = Some(proxy_uri);
        self
    }

    /// Replaces the current `no_proxy` rule set.
    ///
    /// Accepts existing hostname, IP, wildcard and port rules, plus IPv4/IPv6
    /// CIDRs such as `192.168.88.0/24` or `2001:db8::/32`. CIDRs match only URL
    /// IP literals of the same address family, on any port; no DNS lookup is
    /// performed. Host bits are normalized (e.g. `192.168.88.42/24` becomes
    /// `192.168.88.0/24`). CIDRs with ports, brackets or zone IDs are invalid.
    /// Each redirect destination is evaluated separately. Invalid rules return
    /// [`crate::Error::InvalidNoProxyRule`] immediately.
    pub fn no_proxy<I, S>(mut self, rules: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.no_proxy_rules = parse_no_proxy_rules(rules)?;
        Ok(self)
    }

    /// Appends one `no_proxy` rule, returning an error if the rule is invalid.
    pub fn add_no_proxy(mut self, rule: impl AsRef<str>) -> crate::Result<Self> {
        self.no_proxy_rules
            .push(parse_no_proxy_rule(rule.as_ref())?);
        Ok(self)
    }

    /// Sets a default header for every request, replacing any existing value with the same name.
    ///
    /// Request sending rejects explicit `Transfer-Encoding` and malformed or
    /// ambiguous `Content-Length`; body framing is otherwise transport-managed.
    pub fn default_header(mut self, name: HeaderName, mut value: HeaderValue) -> Self {
        mark_sensitive_header_value(&name, &mut value);
        self.default_headers.insert(name, value);
        self
    }

    /// Enables or disables automatic `Accept-Encoding` injection for all request modes.
    pub fn auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self.stream_auto_accept_encoding = enabled;
        self
    }

    /// Enables or disables automatic `Accept-Encoding` for buffered responses.
    ///
    /// Enabled by default. Advertises the compiled compression codecs, skips
    /// HEAD and Range requests, and preserves explicitly supplied header values.
    pub fn buffered_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self
    }

    /// Enables or disables automatic `Accept-Encoding` for streaming responses.
    ///
    /// Disabled by default because reader/download operations yield original
    /// content-encoded bytes. This does not change how stream conversions decode
    /// bodies or override an explicit `Accept-Encoding` header.
    pub fn stream_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.stream_auto_accept_encoding = enabled;
        self
    }

    /// Parses and sets a default header, replacing any existing value with the same name.
    pub fn try_default_header(self, name: &str, value: &str) -> crate::Result<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.default_header(name, value))
    }

    /// Sets the default retry policy.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Sets the predicate that decides whether a failure may be retried.
    pub fn retry_eligibility(mut self, retry_eligibility: Arc<dyn RetryEligibility>) -> Self {
        self.retry_eligibility = retry_eligibility;
        self
    }

    /// Enables retry budget enforcement.
    ///
    /// `None` disables this control, including a previously configured policy.
    pub fn retry_budget_policy(mut self, retry_budget_policy: Option<RetryBudgetPolicy>) -> Self {
        self.retry_budget_policy = retry_budget_policy;
        self
    }

    /// Enables circuit breaker protection for upstream failures.
    ///
    /// `None` disables this control, including a previously configured policy.
    pub fn circuit_breaker_policy(
        mut self,
        circuit_breaker_policy: Option<CircuitBreakerPolicy>,
    ) -> Self {
        self.circuit_breaker_policy = circuit_breaker_policy;
        self
    }

    /// Enables adaptive concurrency control.
    ///
    /// `None` disables this control, including a previously configured policy.
    pub fn adaptive_concurrency_policy(
        mut self,
        adaptive_concurrency_policy: Option<AdaptiveConcurrencyPolicy>,
    ) -> Self {
        self.adaptive_concurrency_policy = adaptive_concurrency_policy;
        self
    }

    /// Applies a client-wide rate limit policy.
    ///
    /// `None` disables this control, including a previously configured policy.
    pub fn global_rate_limit_policy(
        mut self,
        global_rate_limit_policy: Option<RateLimitPolicy>,
    ) -> Self {
        self.global_rate_limit_policy = global_rate_limit_policy;
        self
    }

    /// Applies a host-scoped rate limit policy.
    ///
    /// `None` disables this control, including a previously configured policy.
    pub fn per_host_rate_limit_policy(
        mut self,
        per_host_rate_limit_policy: Option<RateLimitPolicy>,
    ) -> Self {
        self.per_host_rate_limit_policy = per_host_rate_limit_policy;
        self
    }

    /// Chooses how server throttling hints are mapped onto configured rate limiters.
    pub fn server_throttle_scope(mut self, server_throttle_scope: ServerThrottleScope) -> Self {
        self.server_throttle_scope = server_throttle_scope;
        self
    }

    /// Sets the default redirect handling policy.
    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    /// Sets the default status handling policy for requests.
    pub fn default_status_policy(mut self, default_status_policy: StatusPolicy) -> Self {
        self.default_status_policy = default_status_policy;
        self
    }

    /// Selects the TLS backend used by this client.
    ///
    /// Async `rustls` backends support TLS version bounds. Async `native-tls`
    /// maps configured version bounds onto the platform TLS stack and rejects
    /// [`TlsRootStore::WebPki`] at build time.
    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
        self
    }

    /// Sets the endpoint selector used for multi-endpoint clients.
    ///
    /// `None` uses the configured base URL directly.
    /// Selection is made once during request preparation, before attempts.
    /// Retries do not select a new endpoint; redirects use their own target URI.
    /// The shared selector must support concurrent calls across client clones.
    /// See [`EndpointSelector`] for the borrowed-URL contract.
    pub fn endpoint_selector(
        mut self,
        endpoint_selector: Option<Arc<dyn EndpointSelector>>,
    ) -> Self {
        self.endpoint_selector = endpoint_selector;
        self
    }

    /// Sets the time source used by Retry-After parsing and internal control loops.
    ///
    /// This does not replace the runtime timers used for transport I/O.
    pub fn control_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets the backoff source used for retry sleeps and server throttle waits.
    ///
    /// `None` uses the effective retry policy directly.
    pub fn backoff_source(mut self, backoff_source: Option<Arc<dyn BackoffSource>>) -> Self {
        self.backoff_source = backoff_source;
        self
    }

    /// Selects which root trust store the TLS backend should use.
    ///
    /// Custom root CAs require [`TlsRootStore::WebPki`],
    /// [`TlsRootStore::System`], or [`TlsRootStore::Specific`]. For rustls
    /// backends, [`TlsRootStore::WebPki`] appends explicit custom roots to the
    /// bundled Mozilla roots. Async `native-tls` rejects [`TlsRootStore::WebPki`].
    pub fn tls_root_store(mut self, tls_root_store: TlsRootStore) -> Self {
        self.tls_options.root_store = tls_root_store;
        self
    }

    /// Adds a PEM-encoded root CA certificate.
    ///
    /// Pair this with [`Self::tls_root_store`] set to
    /// [`TlsRootStore::WebPki`], [`TlsRootStore::System`], or
    /// [`TlsRootStore::Specific`]. With rustls and [`TlsRootStore::WebPki`],
    /// this appends to the bundled Mozilla roots.
    pub fn tls_root_ca_pem(mut self, certificate_pem: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Pem(certificate_pem.into()));
        self
    }

    /// Adds a DER-encoded root CA certificate.
    ///
    /// Pair this with [`Self::tls_root_store`] set to
    /// [`TlsRootStore::WebPki`], [`TlsRootStore::System`], or
    /// [`TlsRootStore::Specific`]. With rustls and [`TlsRootStore::WebPki`],
    /// this appends to the bundled Mozilla roots.
    pub fn tls_root_ca_der(mut self, certificate_der: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Der(certificate_der.into()));
        self
    }

    /// Removes all explicitly configured root CA certificates.
    pub fn clear_tls_root_cas(mut self) -> Self {
        self.tls_options.root_certificates.clear();
        self
    }

    /// Sets a PEM-encoded client certificate chain and private key for mTLS.
    pub fn tls_client_identity_pem(
        mut self,
        cert_chain_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.tls_options.client_identity = Some(TlsClientIdentity::Pem {
            cert_chain_pem: cert_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        });
        self
    }

    /// Removes any configured client TLS identity.
    pub fn clear_tls_client_identity(mut self) -> Self {
        self.tls_options.client_identity = None;
        self
    }

    /// Allows retries for methods that are not normally considered idempotent.
    pub fn allow_non_idempotent_retries(mut self, allow: bool) -> Self {
        self.retry_eligibility = if allow {
            Arc::new(PermissiveRetryEligibility)
        } else {
            Arc::new(StrictRetryEligibility)
        };
        self
    }

    /// Sets the client name used in metrics, diagnostics, and default `User-Agent`.
    ///
    /// The value must be non-empty and valid as an HTTP header value.
    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = client_name.into();
        self
    }

    /// Caps the total number of in-flight requests.
    ///
    /// `Some(0)` is rejected by `build()`. `None` disables this control,
    /// including a previously configured limit. Defaults to `None`.
    /// A slot covers the logical request, including backoff and redirects. For
    /// streams it remains held until body completion, failure, or drop.
    pub fn max_in_flight(mut self, max_in_flight: Option<usize>) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Caps the number of in-flight requests per host.
    ///
    /// `Some(0)` is rejected by `build()`. `None` disables this control,
    /// including a previously configured limit. Defaults to `None`.
    /// Buckets use normalized hostnames plus effective ports. Redirects acquire
    /// the target bucket. A retry releases its host slot before backoff; a
    /// returned stream holds its current host slot until completion or drop.
    pub fn max_in_flight_per_host(mut self, max_in_flight_per_host: Option<usize>) -> Self {
        self.max_in_flight_per_host = max_in_flight_per_host;
        self
    }

    /// Enables in-process metrics collection.
    ///
    /// Disabled by default. Client clones share the counters. A returned stream
    /// remains in flight until EOF, failure, or drop. This is independent of
    /// [`Self::otel_enabled`]; see [`crate::advanced::MetricsSnapshot`].
    pub fn metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Enables OpenTelemetry observer emission.
    ///
    /// Disabled by default. Enabling emission requires the `otel` feature;
    /// otherwise `build()` returns [`crate::Error::FeatureUnavailable`].
    /// Configure application-owned global OpenTelemetry meter/tracer providers
    /// and exporters first. This crate emits telemetry but does not install an
    /// SDK/exporter. In-process snapshots use [`Self::metrics_enabled`] separately.
    pub fn otel_enabled(mut self, enabled: bool) -> Self {
        self.otel_enabled = enabled;
        self
    }

    /// Sets the path normalizer used for OpenTelemetry attributes.
    pub fn otel_path_normalizer(
        mut self,
        otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    ) -> Self {
        self.otel_path_normalizer = otel_path_normalizer;
        self
    }

    /// Registers a request/response interceptor.
    ///
    /// Multiple interceptors run in registration order, inline with each attempt.
    /// The `Arc` can be shared across clients; implementations must be thread-safe
    /// and should avoid blocking the async executor. See [`Interceptor`].
    pub fn interceptor(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    /// Registers an observer that receives lifecycle callbacks.
    ///
    /// Observers run inline, in registration order, and receive events per attempt
    /// rather than only once per logical request. See [`Observer`].
    pub fn observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Applies a bundle of profile defaults.
    ///
    /// Replaces request timeout, total deadline, retry policy, buffered size limit,
    /// redirect policy, and status policy at this point in the builder chain.
    /// Other settings are retained; later setters can override profile values.
    /// See [`ClientProfile`] for the preset values.
    pub fn profile(mut self, profile: ClientProfile) -> Self {
        let defaults = profile.defaults();
        self.request_timeout = defaults.request_timeout;
        self.total_timeout = defaults.total_timeout;
        self.retry_policy = defaults.retry_policy;
        self.max_response_body_bytes = defaults.max_response_body_bytes;
        self.redirect_policy = defaults.redirect_policy;
        self.default_status_policy = defaults.status_policy;
        self
    }

    pub(crate) fn validate(&mut self) -> crate::Result<DnsOverrides> {
        validate_base_url(&self.base_url)?;
        let dns_overrides =
            std::mem::take(&mut self.dns_overrides).build(self.http_proxy.is_some())?;
        if let Some(proxy_uri) = &self.http_proxy {
            validate_http_proxy_uri(proxy_uri)?;
        }
        validate_timeout_config(
            self.request_timeout,
            self.total_timeout,
            Some(self.connect_timeout),
        )?;
        if self.max_in_flight == Some(0) || self.max_in_flight_per_host == Some(0) {
            return Err(Error::InvalidConcurrencyLimitConfig {
                max_in_flight: self.max_in_flight,
                max_in_flight_per_host: self.max_in_flight_per_host,
                message: if self.max_in_flight == Some(0) {
                    "max_in_flight must be greater than zero"
                } else {
                    "max_in_flight_per_host must be greater than zero"
                },
            });
        }
        self.retry_policy.validate()?;
        if let Some(policy) = self.retry_budget_policy {
            policy.validate()?;
        }
        if let Some(policy) = self.circuit_breaker_policy {
            policy.validate()?;
        }
        if let Some(policy) = self.adaptive_concurrency_policy {
            policy.validate()?;
        }
        if let Some(policy) = self.global_rate_limit_policy {
            policy.validate()?;
        }
        if let Some(policy) = self.per_host_rate_limit_policy {
            policy.validate()?;
        }
        self.default_headers = default_headers_with_user_agent(
            &self.client_name,
            std::mem::take(&mut self.default_headers),
        )?;
        Ok(dns_overrides)
    }
}
