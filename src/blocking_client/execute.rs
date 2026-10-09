use std::thread::sleep;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

use crate::core::content_encoding::{
    decode_content_encoded_body_limited, should_decode_content_encoded_body,
};
use crate::core::error::{Error, TimeoutPhase, TransportErrorKind, transport_error};
use crate::core::execution::lifecycle::StreamLifecycle;
use crate::core::execution::{
    AttemptGuards, BodyReadFailure, BodyReadOutcome, BodyReadRetryContext, RequestCompletion,
    RequestExecutionPreparation, RequestExecutionState, ResponseMode, RetryAttemptState,
    RetryRequestInput, RetrySchedule, TransportFailurePlan, prepare_retry_request_input,
    server_throttle_delay,
};
use crate::core::metrics::MetricsSnapshot;
use crate::core::policy::{RequestContext, StatusPolicy};
use crate::core::request_builder::RequestExecutionOverrides;
use crate::core::retry::RetryDecision;
use crate::core::util::{
    bounded_retry_delay, deadline_exceeded_error, duration_millis_ceil, mark_sensitive_headers,
    redact_uri_for_logs, total_timeout_deadline, validate_request_framing_headers,
};
use crate::http::response::{BlockingResponseStream, BlockingResponseStreamContext, Response};
use crate::rate_limit::{resolve_server_throttle_scope, server_throttle_scope_from_headers};
use crate::tls::TlsBackend;

use super::limiters::{AcquirePermitError, BlockingSemaphorePermit};
use super::transport::{
    ReadBodyError, classify_ureq_transport_error, is_proxy_bypassed, is_timeout_io_error,
    read_all_body_limited, remove_content_encoding_headers,
};
use super::{AdaptiveConcurrencyPermit, Client, ClientBuilder, RequestBody, RequestBuilder};

enum RetryResponse {
    Buffered(Response),
    Stream(Box<BlockingResponseStream>),
}

fn response_mode_mismatch_error(method: &Method, redacted_uri: &str, expected_mode: &str) -> Error {
    transport_error(
        TransportErrorKind::Other,
        method.clone(),
        redacted_uri.to_owned(),
        std::io::Error::other(format!(
            "internal response mode mismatch: expected {expected_mode} response variant"
        )),
    )
}

struct StreamResponseBuildInput<'a> {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: ureq::Body,
    execution: &'a RequestExecutionState,
    transport_timeout: Duration,
    stream_lifecycle: StreamLifecycle,
    stream_global_permit: Option<BlockingSemaphorePermit>,
    host_permit: Option<BlockingSemaphorePermit>,
}

impl Client {
    /// Starts building a client for requests rooted at `base_url`.
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(
            base_url,
            super::builder::BlockingTransportOptions::default(),
            super::transport::default_tls_backend(),
        )
    }

    /// Starts building a request with an explicit HTTP method.
    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, path.into())
    }

    /// Starts a `GET` request.
    pub fn get(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::GET, path)
    }

    /// Starts a `POST` request.
    pub fn post(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::POST, path)
    }

    /// Starts a `PUT` request.
    pub fn put(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::PUT, path)
    }

    /// Starts a `PATCH` request.
    pub fn patch(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::PATCH, path)
    }

    /// Starts a `DELETE` request.
    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::DELETE, path)
    }

    /// Returns the current client metrics snapshot.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.inner.metrics.snapshot()
    }

    /// Returns the TLS backend chosen for this client.
    pub fn tls_backend(&self) -> TlsBackend {
        self.inner.tls_backend
    }

    /// Returns the default status policy applied to requests.
    pub fn default_status_policy(&self) -> StatusPolicy {
        self.inner.request_defaults.status_policy
    }

    fn run_request_interceptors(&self, context: &RequestContext, headers: &mut HeaderMap) {
        for interceptor in &self.inner.interceptors {
            interceptor.on_request(context, headers);
        }
    }

    fn run_response_interceptors(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
    ) {
        for interceptor in &self.inner.interceptors {
            interceptor.on_response(context, status, headers);
        }
    }

    fn run_error_interceptors(&self, context: &RequestContext, error: &Error) {
        for interceptor in &self.inner.interceptors {
            interceptor.on_error(context, error);
        }
    }

    fn run_request_start_observers(&self, context: &RequestContext) {
        for observer in &self.inner.observers {
            observer.on_request_start(context);
        }
    }

    fn run_retry_observers(
        &self,
        context: &RequestContext,
        decision: &RetryDecision,
        delay: Duration,
    ) {
        for observer in &self.inner.observers {
            observer.on_retry_scheduled(context, decision, delay);
        }
    }

    fn run_server_throttle_observers(
        &self,
        context: &RequestContext,
        scope: crate::rate_limit::ServerThrottleScope,
        delay: Duration,
    ) {
        for observer in &self.inner.observers {
            observer.on_server_throttle(context, scope, delay);
        }
    }

    fn stream_response(&self, input: StreamResponseBuildInput<'_>) -> RetryResponse {
        let StreamResponseBuildInput {
            status,
            response_headers,
            response_body,
            execution,
            transport_timeout,
            stream_lifecycle,
            stream_global_permit,
            host_permit,
        } = input;
        let timing = execution.stream_timing();
        RetryResponse::Stream(Box::new(BlockingResponseStream::new(
            status,
            response_headers,
            response_body,
            BlockingResponseStreamContext {
                method: execution.current_method().clone(),
                uri_raw: execution.current_uri().to_string(),
                uri_redacted: execution.current_redacted_uri().to_owned(),
                timeout_ms: duration_millis_ceil(transport_timeout),
                total_timeout_ms: timing.total_timeout_ms,
                deadline_at: timing.deadline_at,
                deadline_slack: self.inner.stream_deadline_slack,
                lifecycle: stream_lifecycle,
                global_permit: stream_global_permit,
                host_permit,
            },
        )))
    }

    fn try_consume_retry_budget(&self, method: &Method, uri: &str) -> Result<(), Error> {
        let Some(retry_budget) = &self.inner.retry_budget else {
            return Ok(());
        };
        if retry_budget.try_consume_retry() {
            Ok(())
        } else {
            Err(Error::RetryBudgetExhausted {
                method: method.clone(),
                uri: uri.to_owned(),
            })
        }
    }

    fn begin_circuit_attempt(
        &self,
        method: &Method,
        uri: &str,
    ) -> Result<Option<crate::resilience::CircuitAttempt>, Error> {
        let Some(circuit_breaker) = &self.inner.circuit_breaker else {
            return Ok(None);
        };

        match circuit_breaker.begin() {
            Ok(attempt) => Ok(Some(attempt)),
            Err(retry_after) => Err(Error::CircuitOpen {
                method: method.clone(),
                uri: uri.to_owned(),
                retry_after_ms: duration_millis_ceil(retry_after),
            }),
        }
    }

    fn begin_adaptive_attempt(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<AdaptiveConcurrencyPermit>, Error> {
        let Some(controller) = self.inner.adaptive_concurrency.as_ref() else {
            return Ok(None);
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        match controller.acquire(deadline_at) {
            Some(permit) => Ok(Some(permit)),
            None => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    fn acquire_global_request_permit(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<BlockingSemaphorePermit>, Error> {
        let Some(limiters) = &self.inner.request_limiters else {
            return Ok(None);
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        limiters
            .acquire_global(deadline_at)
            .map_err(|AcquirePermitError::Timeout| {
                deadline_exceeded_error(total_timeout, method, uri)
            })
    }

    fn acquire_host_request_permit(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<BlockingSemaphorePermit>, Error> {
        let Some(limiters) = &self.inner.request_limiters else {
            return Ok(None);
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        limiters
            .acquire_host(host, deadline_at)
            .map_err(|AcquirePermitError::Timeout| {
                deadline_exceeded_error(total_timeout, method, uri)
            })
    }

    fn acquire_rate_limit_slot(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<(), Error> {
        let Some(rate_limiter) = &self.inner.rate_limiter else {
            return Ok(());
        };

        loop {
            let wait = rate_limiter.acquire_delay(host);
            if wait.is_zero() {
                return Ok(());
            }
            let Some(wait) = bounded_retry_delay(wait, total_timeout, request_started_at) else {
                return Err(deadline_exceeded_error(total_timeout, method, uri));
            };
            sleep(wait);
        }
    }

    fn observe_server_throttle(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
        host: Option<&str>,
        fallback_delay: Duration,
    ) {
        if status != http::StatusCode::TOO_MANY_REQUESTS {
            return;
        }
        let throttle_delay =
            server_throttle_delay(self.inner.clock.as_ref(), headers, fallback_delay);
        let header_scope_hint = server_throttle_scope_from_headers(headers);
        let resolved_scope = match &self.inner.rate_limiter {
            Some(rate_limiter) => rate_limiter.observe_server_throttle(
                host,
                throttle_delay,
                self.inner.server_throttle_scope,
                header_scope_hint,
            ),
            None => resolve_server_throttle_scope(
                self.inner.server_throttle_scope,
                header_scope_hint,
                host.is_some(),
                false,
                false,
            ),
        };
        self.run_server_throttle_observers(context, resolved_scope, throttle_delay);
    }

    fn prepare_retry(
        &self,
        retry_attempt: RetryAttemptState<'_>,
        context: &RequestContext,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
    ) -> Result<RetrySchedule, Error> {
        let retry_schedule = match retry_attempt.prepare_retry_schedule(
            retry_decision,
            requested_delay,
            |method, uri| self.try_consume_retry_budget(method, uri),
        ) {
            Ok(schedule) => schedule,
            Err(error) => {
                self.run_error_interceptors(context, &error);
                return Err(error);
            }
        };
        let RetrySchedule::Scheduled { delay: retry_delay } = retry_schedule else {
            return Ok(RetrySchedule::NotScheduled);
        };

        self.inner.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        Ok(RetrySchedule::Scheduled { delay: retry_delay })
    }

    fn prepare_status_retry(
        &self,
        state: &mut RequestExecutionState,
        context: &RequestContext,
        status: http::StatusCode,
        response_headers: &HeaderMap,
    ) -> Result<RetrySchedule, Error> {
        let retry_plan = state.status_retry_plan(
            status,
            response_headers,
            self.inner.clock.as_ref(),
            self.inner.backoff_source.as_deref(),
        );
        self.prepare_retry(
            state.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
        )
    }

    fn decode_response_body_limited(
        &self,
        body: Bytes,
        headers: &HeaderMap,
        max_response_body_bytes: usize,
        status: http::StatusCode,
        context: &RequestContext,
    ) -> Result<Bytes, Error> {
        let method = context.method();
        let redacted_uri = context.uri();
        if !should_decode_content_encoded_body(method, status, body.len()) {
            return Ok(body);
        }
        decode_content_encoded_body_limited(body, headers, max_response_body_bytes)
            .map_err(|error| error.into_error(method, redacted_uri, max_response_body_bytes))
            .inspect_err(|error| self.run_error_interceptors(context, error))
    }

    fn handle_body_read_failure(
        &self,
        retry_context: &mut BodyReadRetryContext<'_>,
        failure: BodyReadFailure,
    ) -> Result<BodyReadOutcome, Error> {
        let (error, retry_plan) = match failure {
            BodyReadFailure::Terminal { error } => {
                self.run_error_interceptors(retry_context.context(), &error);
                return Err(error);
            }
            BodyReadFailure::Retryable { error, retry_plan } => (error, retry_plan),
        };

        let context = retry_context.context();
        match self.prepare_retry(
            retry_context.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
        )? {
            RetrySchedule::Scheduled { delay } => return Ok(BodyReadOutcome::Retry(delay)),
            RetrySchedule::NotScheduled => {}
        }
        self.run_error_interceptors(context, &error);
        Err(error)
    }

    fn read_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        mut retry_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        match read_all_body_limited(response, retry_context.max_response_body_bytes()) {
            Ok(body) => Ok(BodyReadOutcome::Body(body)),
            Err(ReadBodyError::TooLarge { actual_bytes }) => {
                let error = retry_context.response_body_too_large_error(actual_bytes);
                self.run_error_interceptors(retry_context.context(), &error);
                Err(error)
            }
            Err(ReadBodyError::Read(source)) => {
                if is_timeout_io_error(&source) {
                    let failure = retry_context
                        .response_body_timeout_failure(self.inner.backoff_source.as_deref());
                    return self.handle_body_read_failure(&mut retry_context, failure);
                }

                let failure = retry_context
                    .response_body_read_failure(source, self.inner.backoff_source.as_deref());
                self.handle_body_read_failure(&mut retry_context, failure)
            }
        }
    }

    fn read_decoded_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        retry_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        let max_response_body_bytes = retry_context.max_response_body_bytes();
        let context = retry_context.context();
        let deadline = retry_context.deadline();
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let response_body = match self.read_response_body_with_retry(response, retry_context)? {
            BodyReadOutcome::Body(body) => body,
            BodyReadOutcome::Retry(delay) => return Ok(BodyReadOutcome::Retry(delay)),
        };
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let should_decode_response_body =
            should_decode_content_encoded_body(context.method(), status, response_body.len());
        let response_body = self.decode_response_body_limited(
            response_body,
            response_headers,
            max_response_body_bytes,
            status,
            context,
        )?;
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        if should_decode_response_body
            && response_headers.contains_key(http::header::CONTENT_ENCODING)
        {
            remove_content_encoding_headers(response_headers);
        }
        Ok(BodyReadOutcome::Body(response_body))
    }

    fn select_agent(&self, uri: &Uri) -> (&ureq::Agent, bool) {
        if let Some(proxy_config) = &self.inner.proxy_config
            && !is_proxy_bypassed(proxy_config, uri)
            && let Some(proxy) = &self.inner.transport.proxy
        {
            return (proxy, true);
        }
        (&self.inner.transport.direct, false)
    }

    fn run_once(
        &self,
        method: Method,
        uri: &Uri,
        uri_text: &str,
        headers: &HeaderMap,
        request_body: RequestBody,
        timeout_value: Duration,
    ) -> Result<ureq::http::Response<ureq::Body>, Error> {
        let (agent, using_proxy) = self.select_agent(uri);
        match request_body {
            RequestBody::Buffered(body) => {
                let mut builder = ureq::http::Request::builder()
                    .method(method.clone())
                    .uri(uri_text);
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                let request = builder
                    .body(body.as_ref())
                    .map_err(|source| Error::RequestBuild { source })?;
                self.run_configured_request(
                    agent,
                    using_proxy,
                    request,
                    timeout_value,
                    method,
                    uri_text,
                )
            }
            RequestBody::Streaming(reader) => {
                let mut builder = ureq::http::Request::builder()
                    .method(method.clone())
                    .uri(uri_text);
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                let request = builder
                    .body(ureq::SendBody::from_owned_reader(reader))
                    .map_err(|source| Error::RequestBuild { source })?;
                self.run_configured_request(
                    agent,
                    using_proxy,
                    request,
                    timeout_value,
                    method,
                    uri_text,
                )
            }
        }
    }

    fn run_configured_request<S: ureq::AsSendBody>(
        &self,
        agent: &ureq::Agent,
        using_proxy: bool,
        request: ureq::http::Request<S>,
        timeout_value: Duration,
        method: Method,
        uri_text: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, Error> {
        let configured_request = agent
            .configure_request(request)
            .timeout_global(Some(timeout_value))
            .timeout_per_call(Some(timeout_value))
            .timeout_connect(Some(self.inner.connect_timeout))
            .timeout_recv_response(Some(timeout_value))
            .timeout_recv_body(Some(timeout_value))
            .build();
        self.validate_proxy_authorization(using_proxy)?;

        agent
            .run(configured_request)
            .map_err(|source| match source {
                ureq::Error::Timeout(_) => Error::Timeout {
                    phase: TimeoutPhase::Transport,
                    timeout_ms: duration_millis_ceil(timeout_value),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                },
                other => transport_error(
                    classify_ureq_transport_error(&other),
                    method,
                    redact_uri_for_logs(uri_text),
                    other,
                ),
            })
    }

    fn validate_proxy_authorization(&self, using_proxy: bool) -> Result<(), Error> {
        if !using_proxy {
            return Ok(());
        }
        let Some(proxy_config) = &self.inner.proxy_config else {
            return Ok(());
        };
        if proxy_config.authorization.is_none() {
            return Ok(());
        }
        Err(Error::InvalidProxyConfig {
            proxy_uri: redact_uri_for_logs(&proxy_config.uri.to_string()),
            message: "blocking proxy_authorization(...) is unsupported for ureq transport; set credentials in http_proxy URI (e.g. http://user:pass@proxy:port)".to_owned(),
        })
    }

    pub(super) fn send_request(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOverrides,
    ) -> Result<Response, Error> {
        let request_input = prepare_retry_request_input(RequestExecutionPreparation {
            endpoint_selector: self.inner.endpoint_selector.as_deref(),
            configured_base_url: &self.inner.base_url,
            method,
            path,
            default_headers: &self.inner.default_headers,
            headers,
            body,
            execution_options,
            defaults: &self.inner.request_defaults,
            default_auto_accept_encoding: self.inner.buffered_auto_accept_encoding,
        })?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let request_started_at = Instant::now();
        let completion = self.inner.metrics.pending_request(
            &method,
            &redacted_uri_text,
            false,
            request_started_at,
        );
        let _global_permit = match self.acquire_global_request_permit(
            total_timeout,
            request_started_at,
            &method,
            &redacted_uri_text,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                completion.complete_error(&error);
                return Err(error);
            }
        };

        let result = self
            .send_request_with_retry_mode(
                request_input,
                ResponseMode::Buffered,
                None,
                request_started_at,
            )
            .and_then(|response| match response {
                RetryResponse::Buffered(response) => Ok(response),
                RetryResponse::Stream(_) => Err(response_mode_mismatch_error(
                    &method,
                    &redacted_uri_text,
                    "buffered",
                )),
            });

        match &result {
            Ok(response) => completion.complete_success(response.status().as_u16()),
            Err(error) => completion.complete_error(error),
        }
        result
    }

    pub(super) fn send_request_stream(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOverrides,
    ) -> Result<BlockingResponseStream, Error> {
        let request_input = prepare_retry_request_input(RequestExecutionPreparation {
            endpoint_selector: self.inner.endpoint_selector.as_deref(),
            configured_base_url: &self.inner.base_url,
            method,
            path,
            default_headers: &self.inner.default_headers,
            headers,
            body,
            execution_options,
            defaults: &self.inner.request_defaults,
            default_auto_accept_encoding: self.inner.stream_auto_accept_encoding,
        })?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let request_started_at = Instant::now();
        let completion = self.inner.metrics.pending_request(
            &method,
            &redacted_uri_text,
            true,
            request_started_at,
        );
        let global_permit = match self.acquire_global_request_permit(
            total_timeout,
            request_started_at,
            &method,
            &redacted_uri_text,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                completion.complete_error(&error);
                return Err(error);
            }
        };
        match self.send_request_with_retry_mode(
            request_input,
            ResponseMode::Stream,
            global_permit,
            request_started_at,
        ) {
            Ok(RetryResponse::Stream(response)) => {
                let mut response = *response;
                let completion = completion.into_stream(response.status().as_u16());
                response.attach_completion(completion);
                Ok(response)
            }
            Ok(RetryResponse::Buffered(_)) => {
                let error = response_mode_mismatch_error(&method, &redacted_uri_text, "stream");
                completion.complete_error(&error);
                Err(error)
            }
            Err(error) => {
                completion.complete_error(&error);
                Err(error)
            }
        }
    }

    fn send_request_with_retry_mode(
        &self,
        input: RetryRequestInput<RequestBody>,
        response_mode: ResponseMode,
        stream_global_permit: Option<BlockingSemaphorePermit>,
        request_started_at: Instant,
    ) -> Result<RetryResponse, Error> {
        let (mut execution, mut body) = RequestExecutionState::from_request(
            input,
            request_started_at,
            self.inner.retry_eligibility.as_ref(),
        );

        let mut stream_global_permit = stream_global_permit;

        while execution.can_attempt() {
            let mut context = execution.context();
            self.run_request_start_observers(&context);
            let rate_limit_host = execution.rate_limit_host();
            if let Err(error) = self.acquire_rate_limit_slot(
                rate_limit_host.as_deref(),
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            let host_permit = match self.acquire_host_request_permit(
                rate_limit_host.as_deref(),
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                Ok(permit) => permit,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let circuit_attempt = match self
                .begin_circuit_attempt(execution.current_method(), execution.current_redacted_uri())
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let mut attempts: AttemptGuards<
                crate::resilience::CircuitAttempt,
                AdaptiveConcurrencyPermit,
            > = AttemptGuards::new(circuit_attempt, None);
            let adaptive_attempt = match self.begin_adaptive_attempt(
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                Ok(attempt) => attempt,
                Err(error) => {
                    attempts.cancel();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            attempts.set_adaptive(adaptive_attempt);

            let mut attempt_headers = execution.current_headers().clone();
            self.run_request_interceptors(&context, &mut attempt_headers);
            execution
                .tighten_retry_eligibility(&attempt_headers, self.inner.retry_eligibility.as_ref());
            context = execution.context();
            if let Err(error) = validate_request_framing_headers(
                &attempt_headers,
                body.known_length(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            mark_sensitive_headers(&mut attempt_headers);
            // Never forward hop-by-hop proxy credentials to origin servers.
            attempt_headers.remove(http::header::PROXY_AUTHORIZATION);
            let current_uri_text = execution.current_uri().to_string();
            let Some(transport_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };

            let request_body = body.take_for_attempt();

            let mut response = match self.run_once(
                execution.current_method().clone(),
                execution.current_uri(),
                &current_uri_text,
                &attempt_headers,
                request_body,
                transport_timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    let error = if matches!(
                        error,
                        Error::Timeout {
                            phase: TimeoutPhase::Transport,
                            ..
                        }
                    ) {
                        execution.transport_timeout_error(duration_millis_ceil(transport_timeout))
                    } else {
                        error
                    };
                    match execution
                        .transport_failure_plan(&error, self.inner.backoff_source.as_deref())
                    {
                        TransportFailurePlan::Retry(retry_plan) => {
                            match attempts.record_failure_for_retry_schedule(self.prepare_retry(
                                execution.retry_attempt(),
                                &context,
                                &retry_plan.decision,
                                retry_plan.delay,
                            ))? {
                                RetrySchedule::Scheduled { delay: retry_delay } => {
                                    drop(host_permit);
                                    if !retry_delay.is_zero() {
                                        sleep(retry_delay);
                                    }
                                    continue;
                                }
                                RetrySchedule::NotScheduled => {
                                    attempts.mark_failure();
                                }
                            }
                        }
                        TransportFailurePlan::Terminal {
                            attempt_disposition,
                        } => {
                            attempt_disposition.apply(&mut attempts);
                        }
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            let status = response.status();
            let mut response_headers = response.headers().clone();
            let redirect_action = match execution.next_redirect_action(status, &response_headers) {
                Ok(action) => action,
                Err(error) => {
                    attempts.mark_failure();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            if let Some(redirect_action) = redirect_action {
                self.run_response_interceptors(&context, status, &response_headers);
                attempts.mark_success();
                let drops_body = execution
                    .apply_redirect(redirect_action, self.inner.retry_eligibility.as_ref());
                if drops_body {
                    body = RequestBody::default();
                }
                continue;
            }

            self.run_response_interceptors(&context, status, &response_headers);

            if response_mode.is_stream() && status.is_success() {
                let stream_lifecycle = RequestCompletion::Success
                    .into_stream_lifecycle(&mut attempts, self.inner.retry_budget.clone());
                return Ok(self.stream_response(StreamResponseBuildInput {
                    status,
                    response_headers,
                    response_body: response.into_body(),
                    execution: &execution,
                    transport_timeout,
                    stream_lifecycle,
                    stream_global_permit: stream_global_permit.take(),
                    host_permit,
                }));
            }

            if !status.is_success() {
                let server_throttle_fallback_delay =
                    execution.retry_backoff(self.inner.backoff_source.as_deref());
                self.observe_server_throttle(
                    &context,
                    status,
                    &response_headers,
                    rate_limit_host.as_deref(),
                    server_throttle_fallback_delay,
                );
                match attempts.record_failure_for_retry_schedule(self.prepare_status_retry(
                    &mut execution,
                    &context,
                    status,
                    &response_headers,
                ))? {
                    RetrySchedule::Scheduled { delay: retry_delay } => {
                        drop(response);
                        drop(host_permit);
                        if !retry_delay.is_zero() {
                            sleep(retry_delay);
                        }
                        continue;
                    }
                    RetrySchedule::NotScheduled => {
                        // Keep the attempt open so terminal non-success handling can record the
                        // correct success/failure disposition.
                    }
                }
                if response_mode.is_stream() && execution.should_return_non_success_response() {
                    let stream_lifecycle = execution
                        .non_success_completion(status)
                        .into_stream_lifecycle(&mut attempts, self.inner.retry_budget.clone());
                    return Ok(self.stream_response(StreamResponseBuildInput {
                        status,
                        response_headers,
                        response_body: response.into_body(),
                        execution: &execution,
                        transport_timeout,
                        stream_lifecycle,
                        stream_global_permit: stream_global_permit.take(),
                        host_permit,
                    }));
                }
            }

            let Some(read_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.mark_failure();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };

            let response_body = match attempts.record_failure_on_error(
                self.read_decoded_response_body_with_retry(
                    &mut response,
                    &mut response_headers,
                    status,
                    execution.body_read_retry_context(&context, read_timeout),
                ),
            )? {
                BodyReadOutcome::Body(body) => body,
                BodyReadOutcome::Retry(retry_delay) => {
                    attempts.mark_failure();
                    drop(response);
                    drop(host_permit);
                    if !retry_delay.is_zero() {
                        sleep(retry_delay);
                    }
                    continue;
                }
            };

            if !status.is_success() {
                if execution.should_return_non_success_response() && response_mode.is_buffered() {
                    let completion = execution.non_success_completion(status);
                    completion.record_completed(&mut attempts, self.inner.retry_budget.as_ref());
                    return Ok(RetryResponse::Buffered(Response::new(
                        status,
                        response_headers,
                        response_body,
                    )));
                }

                let terminal =
                    execution.terminal_non_success(status, &response_headers, &response_body);
                terminal
                    .completion
                    .record_completed(&mut attempts, self.inner.retry_budget.as_ref());
                self.run_error_interceptors(&context, &terminal.error);
                return Err(terminal.error);
            }

            RequestCompletion::Success
                .record_completed(&mut attempts, self.inner.retry_budget.as_ref());
            return Ok(RetryResponse::Buffered(Response::new(
                status,
                response_headers,
                response_body,
            )));
        }

        let error = execution.deadline_error();
        let context = execution.context();
        self.run_error_interceptors(&context, &error);
        Err(error)
    }
}
