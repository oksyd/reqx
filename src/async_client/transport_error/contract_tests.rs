use std::error::Error as StdError;
use std::{fmt, io};

use super::{classify_transport_error_source_chain, classify_transport_error_text};

use crate::core::error::TransportErrorKind;

#[test]
fn classify_transport_error_text_detects_dns_tls_and_connect() {
    assert_eq!(
        classify_transport_error_text("failed to lookup address", true),
        TransportErrorKind::Dns
    );
    assert_eq!(
        classify_transport_error_text("tls handshake eof", true),
        TransportErrorKind::Tls
    );
    assert_eq!(
        classify_transport_error_text("connection refused", true),
        TransportErrorKind::Connect
    );
    assert_eq!(
        classify_transport_error_text("received fatal alert: ProtocolVersion", true),
        TransportErrorKind::Tls
    );
}

#[test]
fn classify_transport_error_text_avoids_over_broad_read_matches() {
    assert_eq!(
        classify_transport_error_text("request already sent", false),
        TransportErrorKind::Other
    );
    assert_eq!(
        classify_transport_error_text("connection reset by peer", false),
        TransportErrorKind::Read
    );
}

#[cfg(feature = "_async")]
#[derive(Debug)]
struct WrappedSourceError {
    source: Box<dyn StdError + Send + Sync>,
}

#[cfg(feature = "_async")]
impl fmt::Display for WrappedSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wrapped source error")
    }
}

#[cfg(feature = "_async")]
impl StdError for WrappedSourceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(feature = "_async")]
#[test]
fn classify_transport_error_source_chain_prefers_structured_io_errors() {
    let dns = io::Error::new(io::ErrorKind::NotFound, "resolver failed");
    assert_eq!(
        classify_transport_error_source_chain(&dns, true),
        Some(TransportErrorKind::Dns)
    );

    let connect = WrappedSourceError {
        source: Box::new(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        )),
    };
    assert_eq!(
        classify_transport_error_source_chain(&connect, true),
        Some(TransportErrorKind::Connect)
    );

    let read = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
    assert_eq!(
        classify_transport_error_source_chain(&read, false),
        Some(TransportErrorKind::Read)
    );

    let host_unreachable = io::Error::new(io::ErrorKind::HostUnreachable, "host unreachable");
    assert_eq!(
        classify_transport_error_source_chain(&host_unreachable, true),
        Some(TransportErrorKind::Connect)
    );

    let network_down = io::Error::new(io::ErrorKind::NetworkDown, "network down");
    assert_eq!(
        classify_transport_error_source_chain(&network_down, true),
        Some(TransportErrorKind::Connect)
    );
}

#[cfg(all(
    feature = "_async",
    any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola"
    )
))]
#[test]
fn classify_transport_error_source_chain_detects_rustls_errors() {
    let tls_error = WrappedSourceError {
        source: Box::new(rustls::Error::General("handshake failed".into())),
    };
    assert_eq!(
        classify_transport_error_source_chain(&tls_error, true),
        Some(TransportErrorKind::Tls)
    );
}

#[cfg(all(
    feature = "_async",
    any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-graviola"
    )
))]
#[test]
fn classify_transport_error_source_chain_prefers_nested_tls_over_io_kind() {
    let tls_io = io::Error::new(
        io::ErrorKind::UnexpectedEof,
        rustls::Error::General("handshake failed".into()),
    );

    assert_eq!(
        classify_transport_error_source_chain(&tls_io, true),
        Some(TransportErrorKind::Tls)
    );
}

#[test]
fn classify_transport_error_text_maps_proxy_tunnel_connect_failures() {
    assert_eq!(
        classify_transport_error_text("tunnel error: unexpected end of file", true),
        TransportErrorKind::Connect
    );
    assert_eq!(
        classify_transport_error_text("tunnel error: io error establishing tunnel", true),
        TransportErrorKind::Connect
    );
    assert_eq!(
        classify_transport_error_text("tunnel error: failed to create underlying connection", true),
        TransportErrorKind::Connect
    );
    assert_eq!(
        classify_transport_error_text("tunnel error: proxy authorization required", true),
        TransportErrorKind::Other
    );
}
