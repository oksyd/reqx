use std::io::Read;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::IDEMPOTENCY_KEY_HEADER;
use crate::core::policy::{RedirectPolicy, StatusPolicy};
use crate::core::request_builder::RequestExecutionOverrides;
use crate::core::retry::RetryPolicy;
use crate::core::util::{
    append_query, mark_sensitive_header_value, parse_header_name, parse_header_value,
};
use crate::http::response::{BlockingResponseStream, Response};

use super::{Client, RequestBody};

/// Builds and executes a single request against an existing [`Client`].
///
/// Owns a cheap client clone, so a prepared request can outlive the client
/// handle that created it and can be moved into another thread.
///
/// Create a builder from [`Client::request`] or the verb helpers such as
/// [`Client::get`] and [`Client::post`].
///
/// See also:
///
/// - `examples/blocking_basic.rs`
/// - `examples/blocking_streaming.rs`
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
#[must_use = "request builders do nothing until you call a send method"]
pub struct RequestBuilder {
    client: Client,
    method: Method,
    path: String,
    query: String,
    headers: HeaderMap,
    body: Option<RequestBody>,
    helper_content_length: bool,
    execution_overrides: RequestExecutionOverrides,
}

impl RequestBuilder {
    pub(crate) fn new(client: Client, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            query: String::new(),
            headers: HeaderMap::new(),
            body: None,
            helper_content_length: false,
            execution_overrides: RequestExecutionOverrides::default(),
        }
    }

    /// Sets a request header, replacing any existing value with the same name.
    ///
    /// Request sending rejects explicit `Transfer-Encoding` and malformed or
    /// ambiguous `Content-Length`; body framing is otherwise transport-managed.
    pub fn header(mut self, name: HeaderName, mut value: HeaderValue) -> Self {
        mark_sensitive_header_value(&name, &mut value);
        if name == CONTENT_LENGTH {
            self.helper_content_length = false;
        }
        self.headers.insert(name, value);
        self
    }

    /// Parses and sets a request header, replacing any existing value with the same name.
    pub fn try_header(self, name: &str, value: &str) -> crate::Result<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.header(name, value))
    }

    /// Sets the `Idempotency-Key` header for retry-safe mutations.
    pub fn idempotency_key(self, key: &str) -> crate::Result<Self> {
        self.try_header(IDEMPOTENCY_KEY_HEADER, key)
    }

    /// Appends one query parameter pair.
    pub fn query_pair(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        url::form_urlencoded::Serializer::new(&mut self.query)
            .append_pair(name.as_ref(), value.as_ref());
        self
    }

    /// Appends multiple query parameter pairs.
    pub fn query_pairs<K, V, I>(mut self, pairs: I) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
        I: IntoIterator<Item = (K, V)>,
    {
        url::form_urlencoded::Serializer::new(&mut self.query).extend_pairs(pairs);
        self
    }

    /// Serializes and appends query parameters from `params`.
    pub fn query<T>(mut self, params: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let mut serializer = url::form_urlencoded::Serializer::new(&mut self.query);
        params
            .serialize(serde_urlencoded::Serializer::new(&mut serializer))
            .map_err(|source| crate::core::error::Error::SerializeQuery { source })?;
        Ok(self)
    }

    /// Sets a fully buffered request body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.clear_content_length();
        self.body = Some(RequestBody::Buffered(body.into()));
        self
    }

    /// Streams a blocking reader as the request body.
    ///
    /// Preserves an explicitly supplied `Content-Length`, but clears a length
    /// set by an earlier `body_reader_with_length` call.
    pub fn body_reader<R>(mut self, reader: R) -> Self
    where
        R: Read + Send + 'static,
    {
        if self.helper_content_length {
            self.clear_content_length();
        }
        self.body = Some(RequestBody::Streaming(Box::new(reader)));
        self
    }

    /// Streams a blocking reader as the request body and sets `Content-Length`.
    pub fn body_reader_with_length<R>(self, reader: R, content_length: u64) -> Self
    where
        R: Read + Send + 'static,
    {
        let mut builder = self.body_reader(reader);
        builder
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(content_length));
        builder.helper_content_length = true;
        builder
    }

    fn clear_content_length(&mut self) {
        self.headers.remove(CONTENT_LENGTH);
        self.helper_content_length = false;
    }

    /// Serializes `payload` as JSON and sets `Content-Type: application/json`.
    pub fn json<T>(self, payload: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let body = serde_json::to_vec(payload)
            .map_err(|source| crate::core::error::Error::SerializeJson { source })?;
        let with_body = self.body(Bytes::from(body));
        Ok(with_body.header(CONTENT_TYPE, HeaderValue::from_static("application/json")))
    }

    /// Serializes `payload` as form data and sets the form content type.
    pub fn form<T>(self, payload: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(payload)
            .map_err(|source| crate::core::error::Error::SerializeForm { source })?;
        let with_body = self.body(Bytes::from(encoded));
        Ok(with_body.header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ))
    }

    /// Overrides the per-attempt request timeout for this request.
    ///
    /// A zero duration is rejected by `send` or `send_stream`.
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.execution_overrides.request_timeout = Some(request_timeout);
        self
    }

    /// Overrides the overall deadline for this request.
    ///
    /// `None` disables the client deadline for this request. Omitting this call
    /// inherits the client setting.
    ///
    /// A zero duration is rejected by `send` or `send_stream`.
    pub fn total_timeout(mut self, total_timeout: Option<Duration>) -> Self {
        self.execution_overrides.total_timeout = Some(total_timeout);
        self
    }

    /// Overrides the buffered response body size limit for this request.
    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.execution_overrides.max_response_body_bytes = Some(max_response_body_bytes);
        self
    }

    /// Overrides the retry policy for this request.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.execution_overrides.retry_policy = Some(retry_policy);
        self
    }

    /// Overrides redirect handling for this request.
    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.execution_overrides.redirect_policy = Some(redirect_policy);
        self
    }

    /// Overrides status handling for this request.
    pub fn status_policy(mut self, status_policy: StatusPolicy) -> Self {
        self.execution_overrides.status_policy = Some(status_policy);
        self
    }

    /// Overrides automatic `Accept-Encoding` injection for this request.
    ///
    /// Automatic injection skips HEAD and Range requests and preserves an
    /// explicitly supplied `Accept-Encoding` header.
    pub fn auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.execution_overrides.auto_accept_encoding = Some(enabled);
        self
    }

    /// Executes the request and applies the effective [`StatusPolicy`].
    pub fn send(self) -> crate::Result<Response> {
        self.client.send_request(
            self.method,
            append_query(self.path, &self.query),
            self.headers,
            self.body,
            self.execution_overrides,
        )
    }

    /// Executes the request and returns a streaming response body.
    ///
    /// Non-success HTTP statuses still follow the effective [`StatusPolicy`].
    pub fn send_stream(self) -> crate::Result<BlockingResponseStream> {
        self.client.send_request_stream(
            self.method,
            append_query(self.path, &self.query),
            self.headers,
            self.body,
            self.execution_overrides,
        )
    }

    /// Streams the response body into `writer`.
    pub fn download_to_writer<W>(self, writer: &mut W) -> crate::Result<u64>
    where
        W: std::io::Write + ?Sized,
    {
        self.send_stream()?.copy_to_writer(writer)
    }

    /// Streams the response body into `writer`, enforcing `max_bytes`.
    pub fn download_to_writer_limited<W>(
        self,
        writer: &mut W,
        max_bytes: usize,
    ) -> crate::Result<u64>
    where
        W: std::io::Write + ?Sized,
    {
        self.send_stream()?
            .copy_to_writer_limited(writer, max_bytes)
    }

    /// Executes the request, buffers the body, and deserializes it as JSON.
    pub fn send_json<T>(self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send()?;
        response.json()
    }
}
