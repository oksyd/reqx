//! I/O and TLS cause classification shared by both transports.
#[cfg(any(feature = "_async", feature = "_blocking"))]
use std::io;

#[cfg(any(feature = "_async", feature = "_blocking"))]
use crate::core::error::TransportErrorKind;

#[cfg(any(feature = "_async", feature = "_blocking"))]
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
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-rustls-no-provider"
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
