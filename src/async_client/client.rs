use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, PROXY_AUTHORIZATION};
use http::{HeaderMap, Method, Request, Response as HttpResponse, Uri};
use hyper::body::Incoming;
use tokio::time::{sleep, timeout, timeout_at};
use tracing::{Instrument, debug, info_span, warn};

use crate::body::{
    ReadBodyError, ReqBody, RequestBody, buffered_req_body, build_http_request, empty_req_body,
    read_all_body_limited,
};
use crate::content_encoding::should_decode_content_encoded_body;
use crate::core::request_builder::{RequestExecutionDefaults, RequestExecutionOptions};
use crate::error::{Error, TransportErrorKind, transport_error};
use crate::execution::{
    AttemptGuards, BodyReadFailure, BodyReadOutcome, BodyReadRetryContext, RequestCompletion,
    RequestExecutionPreparation, RequestExecutionState, RequestExecutionStateInput, ResponseMode,
    ResponseProgress, RetryAttemptState, RetryRequestInput, RetrySchedule, TransportFailurePlan,
    prepare_retry_request_input, server_throttle_delay,
};
use crate::extensions::decode_response_body_with_codec_limited;
use crate::limiters::{GlobalRequestPermit, HostRequestPermit};
use crate::metrics::MetricsSnapshot;
use crate::policy::{RequestContext, StatusPolicy};
use crate::proxy::should_bypass_proxy_uri;
use crate::rate_limit::{
    ServerThrottleScope, resolve_server_throttle_scope, server_throttle_scope_from_headers,
};
use crate::request::RequestBuilder;
use crate::response::{
    Response, ResponseStream, ResponseStreamContext, StreamLifecycle, StreamPermits,
};
use crate::retry::{RetryDecision, RetryReason};
use crate::tls::TlsBackend;
use crate::util::{
    bounded_retry_delay, deadline_exceeded_error, duration_millis_ceil,
    duration_millis_u64_saturating, ensure_accept_encoding_async, mark_sensitive_headers,
    total_timeout_deadline, validate_request_framing_headers,
};

use super::adaptive::AdaptiveConcurrencyPermit;
use super::transport::TransportRequestError;
pub use super::{Client, ClientBuilder};

enum RetryResponse {
    Buffered(Response),
    Stream(Box<ResponseStream>),
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

fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

struct StreamResponseInput {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: Incoming,
    method: Method,
    uri: Uri,
    redacted_uri: String,
    transport_timeout: Duration,
    stream_total_timeout_ms: Option<u128>,
    stream_deadline_at: Option<Instant>,
    stream_deadline_slack: Duration,
    stream_lifecycle: Option<StreamLifecycle>,
    stream_global_permit: Option<GlobalRequestPermit>,
    host_permit: HostRequestPermit,
}

struct StreamResponseBuildInput<'a> {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: Incoming,
    execution: &'a RequestExecutionState,
    transport_timeout: Duration,
    stream_total_timeout_ms: Option<u128>,
    stream_deadline_at: Option<Instant>,
    stream_lifecycle: Option<StreamLifecycle>,
    stream_global_permit: &'a mut Option<GlobalRequestPermit>,
    host_permit: HostRequestPermit,
}

fn stream_retry_response(input: StreamResponseInput) -> RetryResponse {
    let StreamResponseInput {
        status,
        response_headers,
        response_body,
        method,
        uri,
        redacted_uri,
        transport_timeout,
        stream_total_timeout_ms,
        stream_deadline_at,
        stream_deadline_slack,
        stream_lifecycle,
        stream_global_permit,
        host_permit,
    } = input;
    RetryResponse::Stream(Box::new(ResponseStream::new(
        status,
        response_headers,
        response_body,
        ResponseStreamContext {
            method,
            uri_raw: uri.to_string(),
            uri_redacted: redacted_uri,
            timeout_ms: duration_millis_ceil(transport_timeout),
            total_timeout_ms: stream_total_timeout_ms,
            deadline_at: stream_deadline_at,
            deadline_slack: stream_deadline_slack,
            lifecycle: stream_lifecycle,
            permits: StreamPermits::new(stream_global_permit, Some(host_permit)),
        },
    )))
}

impl Client {
    /// Starts building a client for requests rooted at `base_url`.
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Starts building a request with an explicit HTTP method.
    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, path.into())
    }

    /// Starts a `GET` request.
    pub fn get(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::GET, path)
    }

    /// Starts a `POST` request.
    pub fn post(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::POST, path)
    }

    /// Starts a `PUT` request.
    pub fn put(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PUT, path)
    }

    /// Starts a `PATCH` request.
    pub fn patch(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PATCH, path)
    }

    /// Starts a `DELETE` request.
    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::DELETE, path)
    }

    /// Returns the current client metrics snapshot.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Returns the TLS backend chosen for this client.
    pub fn tls_backend(&self) -> TlsBackend {
        self.tls_backend
    }

    /// Returns the default status policy applied to requests.
    pub fn default_status_policy(&self) -> StatusPolicy {
        self.default_status_policy
    }

    fn run_request_interceptors(&self, context: &RequestContext, headers: &mut HeaderMap) {
        for interceptor in &self.interceptors {
            interceptor.on_request(context, headers);
        }
    }

    fn should_apply_http_proxy_auth_header(&self, uri: &Uri) -> bool {
        let Some(proxy_config) = &self.proxy_config else {
            return false;
        };
        let Some(scheme) = uri.scheme_str() else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("http") {
            return false;
        }
        !should_bypass_proxy_uri(&proxy_config.no_proxy_rules, uri)
    }

    fn apply_http_proxy_auth_header(&self, uri: &Uri, headers: &mut HeaderMap) {
        if !self.should_apply_http_proxy_auth_header(uri)
            || headers.contains_key(PROXY_AUTHORIZATION)
        {
            return;
        }
        if let Some(proxy_config) = &self.proxy_config
            && let Some(proxy_authorization) = &proxy_config.authorization
        {
            headers.insert(PROXY_AUTHORIZATION, proxy_authorization.clone());
        }
    }

    fn run_response_interceptors(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
    ) {
        for interceptor in &self.interceptors {
            interceptor.on_response(context, status, headers);
        }
    }

    fn run_error_interceptors(&self, context: &RequestContext, error: &Error) {
        for interceptor in &self.interceptors {
            interceptor.on_error(context, error);
        }
    }

    fn run_request_start_observers(&self, context: &RequestContext) {
        for observer in &self.observers {
            observer.on_request_start(context);
        }
    }

    fn run_retry_observers(
        &self,
        context: &RequestContext,
        decision: &RetryDecision,
        delay: Duration,
    ) {
        for observer in &self.observers {
            observer.on_retry_scheduled(context, decision, delay);
        }
    }

    fn run_server_throttle_observers(
        &self,
        context: &RequestContext,
        scope: ServerThrottleScope,
        delay: Duration,
    ) {
        for observer in &self.observers {
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
            stream_total_timeout_ms,
            stream_deadline_at,
            stream_lifecycle,
            stream_global_permit,
            host_permit,
        } = input;
        stream_retry_response(StreamResponseInput {
            status,
            response_headers,
            response_body,
            method: execution.current_method().clone(),
            uri: execution.current_uri().clone(),
            redacted_uri: execution.current_redacted_uri().to_owned(),
            transport_timeout,
            stream_total_timeout_ms,
            stream_deadline_at,
            stream_deadline_slack: self.stream_deadline_slack,
            stream_lifecycle,
            stream_global_permit: stream_global_permit.take(),
            host_permit,
        })
    }

    fn try_consume_retry_budget(&self, method: &Method, uri: &str) -> Result<(), Error> {
        let Some(retry_budget) = &self.retry_budget else {
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
        let Some(circuit_breaker) = &self.circuit_breaker else {
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

    async fn begin_adaptive_attempt(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<AdaptiveConcurrencyPermit>, Error> {
        let Some(controller) = self.adaptive_concurrency.as_ref() else {
            return Ok(None);
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return Ok(Some(controller.acquire().await));
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            controller.acquire(),
        )
        .await
        {
            Ok(permit) => Ok(Some(permit)),
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn acquire_rate_limit_slot(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<(), Error> {
        let Some(rate_limiter) = &self.rate_limiter else {
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
            sleep(wait).await;
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
        let throttle_delay = server_throttle_delay(self.clock.as_ref(), headers, fallback_delay);
        let header_scope_hint = server_throttle_scope_from_headers(headers);
        let resolved_scope = match &self.rate_limiter {
            Some(rate_limiter) => rate_limiter.observe_server_throttle(
                host,
                throttle_delay,
                self.server_throttle_scope,
                header_scope_hint,
            ),
            None => resolve_server_throttle_scope(
                self.server_throttle_scope,
                header_scope_hint,
                host.is_some(),
                false,
                false,
            ),
        };
        self.run_server_throttle_observers(context, resolved_scope, throttle_delay);
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
        decode_response_body_with_codec_limited(
            self.body_codec.as_ref(),
            body,
            headers,
            max_response_body_bytes,
            method,
            redacted_uri,
        )
        .inspect_err(|error| self.run_error_interceptors(context, error))
    }

    fn prepare_retry(
        &self,
        retry_attempt: RetryAttemptState<'_>,
        context: &RequestContext,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
        error: &Error,
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

        let delay_ms = duration_millis_u64_saturating(retry_delay);
        match retry_decision.reason() {
            RetryReason::Status(status) => {
                warn!(
                    status = status.as_u16(),
                    delay_ms,
                    error = %error,
                    "retrying request after retryable status"
                );
            }
            RetryReason::ResponseBodyRead => {
                warn!(
                    delay_ms,
                    error = %error,
                    "retrying request after response body read error"
                );
            }
            RetryReason::Timeout(_) => {
                warn!(delay_ms, error = %error, "retrying request after timeout");
            }
            RetryReason::Transport(_) => {
                warn!(delay_ms, error = %error, "retrying request after transport error");
            }
        }

        self.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        Ok(RetrySchedule::Scheduled { delay: retry_delay })
    }

    fn prepare_status_retry(
        &self,
        state: &mut RequestExecutionState,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
    ) -> Result<RetrySchedule, Error> {
        let retry_plan = state.status_retry_plan(
            status,
            headers,
            self.clock.as_ref(),
            self.backoff_source.as_ref(),
        );
        let retry_error = state.status_retry_error(status, headers);
        self.prepare_retry(
            state.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
            &retry_error,
        )
    }

    fn handle_body_read_failure(
        &self,
        read_context: &mut BodyReadRetryContext<'_>,
        failure: BodyReadFailure,
    ) -> Result<BodyReadOutcome, Error> {
        let (error, retry_plan) = match failure {
            BodyReadFailure::Terminal { error } => {
                self.run_error_interceptors(read_context.context(), &error);
                return Err(error);
            }
            BodyReadFailure::Retryable { error, retry_plan } => (error, retry_plan),
        };

        let context = read_context.context();
        match self.prepare_retry(
            read_context.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
            &error,
        )? {
            RetrySchedule::Scheduled { delay } => return Ok(BodyReadOutcome::Retry(delay)),
            RetrySchedule::NotScheduled => {}
        }
        self.run_error_interceptors(context, &error);
        Err(error)
    }

    async fn read_response_body_with_retry(
        &self,
        body: Incoming,
        mut read_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        match timeout(
            read_context.read_timeout(),
            read_all_body_limited(body, read_context.max_response_body_bytes()),
        )
        .await
        {
            Ok(Ok(body)) => Ok(BodyReadOutcome::Body(body)),
            Ok(Err(ReadBodyError::Read(source))) => {
                let failure =
                    read_context.response_body_read_failure(source, self.backoff_source.as_ref());
                self.handle_body_read_failure(&mut read_context, failure)
            }
            Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                let error = read_context.response_body_too_large_error(actual_bytes);
                self.run_error_interceptors(read_context.context(), &error);
                Err(error)
            }
            Err(_) => {
                let failure =
                    read_context.response_body_timeout_failure(self.backoff_source.as_ref());
                self.handle_body_read_failure(&mut read_context, failure)
            }
        }
    }

    async fn read_decoded_response_body_with_retry(
        &self,
        body: Incoming,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        read_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        let max_response_body_bytes = read_context.max_response_body_bytes();
        let context = read_context.context();
        let deadline = read_context.deadline();
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let response_body = match self
            .read_response_body_with_retry(body, read_context)
            .await?
        {
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
        if should_decode_response_body && response_headers.contains_key(CONTENT_ENCODING) {
            remove_content_encoding_headers(response_headers);
        }
        Ok(BodyReadOutcome::Body(response_body))
    }

    async fn acquire_global_request_permit(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<GlobalRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(GlobalRequestPermit { _permit: None });
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return limiters.acquire_global().await;
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            limiters.acquire_global(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn acquire_host_request_permit(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<HostRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(HostRequestPermit { _permit: None });
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return limiters.acquire_host(host).await;
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            limiters.acquire_host(host),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn send_transport_request(
        &self,
        transport_timeout: Duration,
        request: Request<ReqBody>,
    ) -> Result<HttpResponse<Incoming>, TransportRequestError> {
        match timeout(transport_timeout, self.transport.request(request)).await {
            Ok(result) => result,
            Err(_) => Err(TransportRequestError::Timeout),
        }
    }

    pub(crate) async fn send_request(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOptions,
    ) -> Result<Response, Error> {
        let request_input = prepare_retry_request_input(
            RequestExecutionPreparation {
                endpoint_selector: self.endpoint_selector.as_ref(),
                configured_base_url: &self.base_url,
                method,
                path,
                default_headers: &self.default_headers,
                headers,
                body,
                execution_options,
                defaults: RequestExecutionDefaults {
                    request_timeout: self.request_timeout,
                    total_timeout: self.total_timeout,
                    retry_policy: &self.retry_policy,
                    max_response_body_bytes: self.max_response_body_bytes,
                    redirect_policy: self.redirect_policy,
                    status_policy: self.default_status_policy,
                    auto_accept_encoding: self.buffered_auto_accept_encoding,
                },
            },
            RequestBody::empty,
            ensure_accept_encoding_async,
        )?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, false);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let _global_permit = match self
            .acquire_global_request_permit(
                total_timeout,
                request_started_at,
                &method,
                &redacted_uri_text,
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                self.metrics
                    .finish_otel_request_span_error(otel_span, &error);
                return Err(error);
            }
        };

        let result = self
            .send_request_with_retry(request_input, request_started_at)
            .await;
        self.metrics
            .record_request_completed(&result, request_started_at.elapsed());
        match &result {
            Ok(response) => self
                .metrics
                .finish_otel_request_span_success(otel_span, response.status().as_u16()),
            Err(error) => self
                .metrics
                .finish_otel_request_span_error(otel_span, error),
        }
        result
    }

    pub(crate) async fn send_request_stream(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOptions,
    ) -> Result<ResponseStream, Error> {
        let request_input = prepare_retry_request_input(
            RequestExecutionPreparation {
                endpoint_selector: self.endpoint_selector.as_ref(),
                configured_base_url: &self.base_url,
                method,
                path,
                default_headers: &self.default_headers,
                headers,
                body,
                execution_options,
                defaults: RequestExecutionDefaults {
                    request_timeout: self.request_timeout,
                    total_timeout: self.total_timeout,
                    retry_policy: &self.retry_policy,
                    max_response_body_bytes: self.max_response_body_bytes,
                    redirect_policy: self.redirect_policy,
                    status_policy: self.default_status_policy,
                    auto_accept_encoding: self.stream_auto_accept_encoding,
                },
            },
            RequestBody::empty,
            ensure_accept_encoding_async,
        )?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let mut otel_span = Some(self.metrics.start_otel_request_span(
            &method,
            &redacted_uri_text,
            true,
        ));
        self.metrics.record_request_started();
        let in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let global_permit = match self
            .acquire_global_request_permit(
                total_timeout,
                request_started_at,
                &method,
                &redacted_uri_text,
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                return Err(error);
            }
        };
        let expected_method = method.clone();
        let expected_redacted_uri = redacted_uri_text.clone();

        match self
            .send_request_with_retry_mode(
                request_input,
                ResponseMode::Stream,
                Some(global_permit),
                request_started_at,
            )
            .await
        {
            Ok(RetryResponse::Stream(response)) => {
                let mut response = *response;
                let completion = self.metrics.stream_completion(
                    otel_span.take(),
                    request_started_at,
                    response.status().as_u16(),
                    in_flight,
                );
                response.attach_completion(completion);
                Ok(response)
            }
            Ok(RetryResponse::Buffered(_)) => {
                let error = response_mode_mismatch_error(
                    &expected_method,
                    &expected_redacted_uri,
                    "stream",
                );
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                Err(error)
            }
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                Err(error)
            }
        }
    }

    async fn send_request_with_retry(
        &self,
        input: RetryRequestInput<RequestBody>,
        request_started_at: Instant,
    ) -> Result<Response, Error> {
        let expected_method = input.method.clone();
        let expected_redacted_uri = input.redacted_uri_text.clone();
        match self
            .send_request_with_retry_mode(input, ResponseMode::Buffered, None, request_started_at)
            .await?
        {
            RetryResponse::Buffered(response) => Ok(response),
            RetryResponse::Stream(_) => Err(response_mode_mismatch_error(
                &expected_method,
                &expected_redacted_uri,
                "buffered",
            )),
        }
    }

    async fn send_request_with_retry_mode(
        &self,
        input: RetryRequestInput<RequestBody>,
        response_mode: ResponseMode,
        stream_global_permit: Option<GlobalRequestPermit>,
        request_started_at: Instant,
    ) -> Result<RetryResponse, Error> {
        let RetryRequestInput {
            method,
            uri,
            redacted_uri_text,
            merged_headers,
            body,
            execution_options,
        } = input;
        let timeout_value = execution_options.request_timeout;
        let total_timeout = execution_options.total_timeout;
        let max_response_body_bytes = execution_options.max_response_body_bytes;
        let (mut buffered_body, mut streaming_body) = match body {
            RequestBody::Buffered(body) => (Some(body), None),
            RequestBody::Streaming(body) => (None, Some(body)),
        };
        let body_replayable = buffered_body.is_some();
        let retry_policy = execution_options.retry_policy;
        let redirect_policy = execution_options.redirect_policy;
        let status_policy = execution_options.status_policy;
        let mut execution = RequestExecutionState::new(
            RequestExecutionStateInput {
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body_replayable,
                retry_policy,
                redirect_policy,
                status_policy,
                timeout_value,
                total_timeout,
                max_response_body_bytes,
                request_started_at,
            },
            self.retry_eligibility.as_ref(),
        );

        let stream_timing = execution.stream_timing();
        let stream_total_timeout_ms = stream_timing.total_timeout_ms;
        let stream_deadline_at = stream_timing.deadline_at;
        let mut stream_global_permit = stream_global_permit;

        while execution.can_attempt() {
            let span = if response_mode.is_stream() {
                info_span!(
                    "reqx.request.stream",
                    client = %self.client_name,
                    method = %execution.current_method(),
                    uri = %execution.current_redacted_uri(),
                    attempt = execution.attempt(),
                    max_attempts = execution.max_attempts()
                )
            } else {
                info_span!(
                    "reqx.request",
                    client = %self.client_name,
                    method = %execution.current_method(),
                    uri = %execution.current_redacted_uri(),
                    attempt = execution.attempt(),
                    max_attempts = execution.max_attempts()
                )
            };
            let started = Instant::now();
            let mut context = execution.context();
            span.in_scope(|| self.run_request_start_observers(&context));
            debug!(parent: &span, "sending request");
            let rate_limit_host = execution.rate_limit_host();
            if let Err(error) = self
                .acquire_rate_limit_slot(
                    rate_limit_host.as_deref(),
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            let host_permit = match self
                .acquire_host_request_permit(
                    rate_limit_host.as_deref(),
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
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
            let adaptive_attempt = match self
                .begin_adaptive_attempt(
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
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
            execution.tighten_retry_eligibility(&attempt_headers, self.retry_eligibility.as_ref());
            context = execution.context();
            let expected_body_len = buffered_body
                .as_ref()
                .map(Bytes::len)
                .or_else(|| streaming_body.is_none().then_some(0));
            if let Err(error) = validate_request_framing_headers(
                &attempt_headers,
                expected_body_len,
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            mark_sensitive_headers(&mut attempt_headers);
            // Never forward hop-by-hop proxy credentials to origin servers.
            attempt_headers.remove(PROXY_AUTHORIZATION);
            self.apply_http_proxy_auth_header(execution.current_uri(), &mut attempt_headers);
            let Some(transport_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };
            let request_body = if let Some(body) = &buffered_body {
                buffered_req_body(body.clone())
            } else {
                streaming_body.take().unwrap_or_else(empty_req_body)
            };
            let request = build_http_request(
                execution.current_method().clone(),
                execution.current_uri().clone(),
                &attempt_headers,
                request_body,
            );
            let request = match request {
                Ok(request) => request,
                Err(error) => {
                    attempts.cancel();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let response = match self
                .send_transport_request(transport_timeout, request)
                .instrument(span.clone())
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let error = error.into_error(&execution, transport_timeout);
                    match execution.transport_failure_plan(&error, self.backoff_source.as_ref()) {
                        TransportFailurePlan::Retry(retry_plan) => {
                            match attempts.record_failure_for_retry_schedule(self.prepare_retry(
                                execution.retry_attempt(),
                                &context,
                                &retry_plan.decision,
                                retry_plan.delay,
                                &error,
                            ))? {
                                RetrySchedule::Scheduled { delay: retry_delay } => {
                                    drop(host_permit);
                                    if !retry_delay.is_zero() {
                                        sleep(retry_delay).instrument(span.clone()).await;
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
                let drops_body =
                    execution.apply_redirect(redirect_action, self.retry_eligibility.as_ref());
                if drops_body {
                    buffered_body = None;
                    streaming_body = None;
                }
                continue;
            }

            let mut response_progress = ResponseProgress::default();

            if response_mode.is_stream() {
                response_progress.run_response_interceptors_if_needed(|| {
                    self.run_response_interceptors(&context, status, &response_headers);
                });

                if status.is_success() {
                    let stream_lifecycle = RequestCompletion::success()
                        .into_stream_lifecycle(&mut attempts, self.retry_budget.clone());
                    return Ok(self.stream_response(StreamResponseBuildInput {
                        status,
                        response_headers,
                        response_body: response.into_body(),
                        execution: &execution,
                        transport_timeout,
                        stream_total_timeout_ms,
                        stream_deadline_at,
                        stream_lifecycle,
                        stream_global_permit: &mut stream_global_permit,
                        host_permit,
                    }));
                }
            }

            if !status.is_success() {
                let server_throttle_fallback_delay =
                    execution.retry_backoff(self.backoff_source.as_ref());
                match attempts.record_failure_for_retry_schedule(
                    response_progress.prepare_non_success_before_body(
                        || self.run_response_interceptors(&context, status, &response_headers),
                        || {
                            self.observe_server_throttle(
                                &context,
                                status,
                                &response_headers,
                                rate_limit_host.as_deref(),
                                server_throttle_fallback_delay,
                            );
                        },
                        || {
                            self.prepare_status_retry(
                                &mut execution,
                                &context,
                                status,
                                &response_headers,
                            )
                        },
                    ),
                )? {
                    RetrySchedule::Scheduled { delay: retry_delay } => {
                        drop(response);
                        drop(host_permit);
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).instrument(span.clone()).await;
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
                        .into_stream_lifecycle(&mut attempts, self.retry_budget.clone());
                    return Ok(self.stream_response(StreamResponseBuildInput {
                        status,
                        response_headers,
                        response_body: response.into_body(),
                        execution: &execution,
                        transport_timeout,
                        stream_total_timeout_ms,
                        stream_deadline_at,
                        stream_lifecycle,
                        stream_global_permit: &mut stream_global_permit,
                        host_permit,
                    }));
                }
            }

            response_progress.run_response_interceptors_if_needed(|| {
                self.run_response_interceptors(&context, status, &response_headers);
            });

            let Some(read_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.mark_failure();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };

            let response_body = match attempts.record_failure_on_error(
                self.read_decoded_response_body_with_retry(
                    response.into_body(),
                    &mut response_headers,
                    status,
                    execution.body_read_retry_context(&context, read_timeout),
                )
                .instrument(span.clone())
                .await,
            )? {
                BodyReadOutcome::Body(body) => body,
                BodyReadOutcome::Retry(retry_delay) => {
                    attempts.mark_failure();
                    drop(host_permit);
                    if !retry_delay.is_zero() {
                        sleep(retry_delay).instrument(span.clone()).await;
                    }
                    continue;
                }
            };

            if response_mode.is_buffered() {
                debug!(
                    parent: &span,
                    status = status.as_u16(),
                    elapsed_ms = duration_millis_u64_saturating(started.elapsed()),
                    "request completed"
                );
            }

            if !status.is_success() {
                if execution.should_return_non_success_response() && response_mode.is_buffered() {
                    let completion = execution.non_success_completion(status);
                    completion.record_completed(&mut attempts, self.retry_budget.as_ref());
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
                    .record_completed(&mut attempts, self.retry_budget.as_ref());
                self.run_error_interceptors(&context, &terminal.error);
                return Err(terminal.error);
            }

            RequestCompletion::success()
                .record_completed(&mut attempts, self.retry_budget.as_ref());
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
