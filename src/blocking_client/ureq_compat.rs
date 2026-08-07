use std::sync::Arc;

use crate::tls::TlsBackend;

/// Isolates ureq's explicitly unstable rustls provider API.
///
/// `Cargo.toml` pins the exact ureq release while this adapter is needed. Any
/// ureq upgrade must compile and exercise this module's provider test.
pub(super) fn pin_rustls_crypto_provider(
    mut builder: ureq::tls::TlsConfigBuilder,
    backend: TlsBackend,
) -> ureq::tls::TlsConfigBuilder {
    #[cfg(feature = "blocking-tls-rustls-ring")]
    if backend == TlsBackend::RustlsRing {
        builder = builder
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));
    }

    #[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
    if backend == TlsBackend::RustlsAwsLcRs {
        builder = builder.unversioned_rustls_crypto_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ));
    }

    builder
}

#[cfg(test)]
pub(super) fn configured_rustls_crypto_provider(
    config: &ureq::tls::TlsConfig,
) -> Option<&rustls::crypto::CryptoProvider> {
    config.unversioned_rustls_crypto_provider().as_deref()
}
