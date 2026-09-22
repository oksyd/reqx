#[cfg(any(
    feature = "_blocking",
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use std::io;

#[cfg(any(
    feature = "_blocking",
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use crate::error::TransportErrorKind;

#[cfg(feature = "_blocking")]
pub(crate) fn is_timeout_io_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
        .is_some_and(|source| matches!(source, ureq::Error::Timeout(_)))
}

#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
pub(crate) fn classify_transport_error(
    error: &hyper_util::client::legacy::Error,
) -> TransportErrorKind {
    if let Some(kind) = classify_transport_error_source_chain(error, error.is_connect()) {
        return kind;
    }

    let mut text = error.to_string().to_ascii_lowercase();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push(' ');
        text.push_str(&cause.to_string().to_ascii_lowercase());
        source = cause.source();
    }
    classify_transport_error_text(&text, error.is_connect())
}

#[cfg(any(
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn classify_transport_error_source_chain(
    error: &(dyn std::error::Error + 'static),
    is_connect_path: bool,
) -> Option<TransportErrorKind> {
    if is_tls_error(error) {
        return Some(TransportErrorKind::Tls);
    }
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(kind) = classify_transport_error_source(source, is_connect_path) {
            return Some(kind);
        }
        current = source.source();
    }
    None
}

#[cfg(any(
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn classify_transport_error_source(
    error: &(dyn std::error::Error + 'static),
    is_connect_path: bool,
) -> Option<TransportErrorKind> {
    if let Some(error) = error.downcast_ref::<io::Error>() {
        return classify_io_transport_error_kind(error.kind(), is_connect_path);
    }

    if let Some(error) = error.downcast_ref::<hyper::Error>() {
        if error.is_timeout() {
            return Some(if is_connect_path {
                TransportErrorKind::Connect
            } else {
                TransportErrorKind::Read
            });
        }
        if error.is_incomplete_message() || error.is_body_write_aborted() {
            return Some(TransportErrorKind::Read);
        }
        if !is_connect_path && (error.is_closed() || error.is_shutdown()) {
            return Some(TransportErrorKind::Read);
        }
    }

    None
}

#[cfg(any(
    feature = "_blocking",
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
pub(crate) fn classify_io_transport_error_kind(
    kind: io::ErrorKind,
    is_connect_path: bool,
) -> Option<TransportErrorKind> {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Some(if is_connect_path {
            TransportErrorKind::Connect
        } else {
            TransportErrorKind::Read
        }),
        io::ErrorKind::NotFound => Some(TransportErrorKind::Dns),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown => Some(TransportErrorKind::Connect),
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => Some(TransportErrorKind::Read),
        _ => None,
    }
}

#[cfg(any(
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn classify_transport_error_text(text: &str, is_connect_path: bool) -> TransportErrorKind {
    const DNS_MARKERS: &[&str] = &[
        "name or service not known",
        "failed to lookup address",
        "no such host",
        "temporary failure in name resolution",
        "nodename nor servname provided",
        "dns lookup failed",
    ];
    const TLS_MARKERS: &[&str] = &[
        "tls handshake",
        "certificate verify",
        "certificate unknown",
        "invalid certificate",
        "self signed certificate",
        "received fatal alert",
        "alertreceived",
        "protocolversion",
        "protocol version",
        "x509",
        "pkix",
        "peer certificate",
    ];
    const CONNECT_MARKERS: &[&str] = &[
        "connection refused",
        "connection aborted",
        "not connected",
        "network unreachable",
        "host unreachable",
        "connect error",
        "proxy connect",
        "tunnel error: unexpected end of file",
        "tunnel error: io error establishing tunnel",
        "tunnel error: failed to create underlying connection",
        "timed out while connecting",
        "connection timeout",
        "connect timeout",
    ];
    const READ_MARKERS: &[&str] = &[
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "incomplete message",
        "connection closed before message completed",
        "body write aborted",
    ];

    if contains_marker(text, DNS_MARKERS) || contains_word(text, "dns") {
        return TransportErrorKind::Dns;
    }
    if contains_marker(text, TLS_MARKERS)
        || contains_word(text, "tls")
        || contains_word(text, "ssl")
        || contains_word(text, "certificate")
    {
        return TransportErrorKind::Tls;
    }
    if contains_marker(text, CONNECT_MARKERS) {
        return TransportErrorKind::Connect;
    }
    if contains_marker(text, READ_MARKERS) {
        return TransportErrorKind::Read;
    }
    if is_connect_path && contains_marker(text, &["timed out", "timeout"]) {
        return TransportErrorKind::Connect;
    }
    if is_connect_path {
        // Unknown connect-path failures stay conservative to avoid retrying
        // configuration, policy, or handshake-class problems by mistake.
        return TransportErrorKind::Other;
    }
    TransportErrorKind::Other
}

#[cfg(any(
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn contains_marker(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

#[cfg(any(
    all(test, feature = "_async"),
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn contains_word(text: &str, word: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| token == word)
}

#[cfg(all(test, feature = "_async"))]
pub(crate) fn classify_transport_error_text_for_test(
    text: &str,
    is_connect_path: bool,
) -> TransportErrorKind {
    classify_transport_error_text(text, is_connect_path)
}

#[cfg(all(test, feature = "_async"))]
pub(crate) fn classify_transport_error_source_for_test(
    error: &(dyn std::error::Error + 'static),
    is_connect_path: bool,
) -> Option<TransportErrorKind> {
    classify_transport_error_source_chain(error, is_connect_path)
}

/// Inspect concrete causes rather than error text; io::Error::source() can skip
/// the wrapped error itself, so use get_ref() to retain its TLS type.
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn is_tls_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(cause) = current {
        #[cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-rustls-no-provider",
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs"
        ))]
        if cause.is::<rustls::Error>() {
            return true;
        }
        #[cfg(feature = "async-tls-native")]
        if cause.is::<hyper_tls::native_tls::Error>() {
            return true;
        }
        #[cfg(all(feature = "blocking-tls-native", not(feature = "async-tls-native")))]
        if cause.is::<native_tls::Error>() {
            return true;
        }
        current = if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            io.get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static))
        } else {
            cause.source()
        };
    }
    false
}
