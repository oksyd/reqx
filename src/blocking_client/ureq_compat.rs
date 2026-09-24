#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-graviola"
))]
use std::sync::Arc;

use crate::tls::TlsBackend;

/// Isolates ureq's explicitly unstable rustls provider API.
///
/// Any ureq upgrade must compile and exercise this module's provider tests.
pub(super) fn pin_rustls_crypto_provider(
    mut builder: ureq::tls::TlsConfigBuilder,
    backend: TlsBackend,
) -> crate::Result<ureq::tls::TlsConfigBuilder> {
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

    #[cfg(feature = "blocking-tls-rustls-graviola")]
    if backend == TlsBackend::RustlsGraviola {
        builder = builder
            .unversioned_rustls_crypto_provider(Arc::new(rustls_graviola::default_provider()));
    }

    #[cfg(feature = "blocking-tls-rustls-no-provider")]
    if backend == TlsBackend::RustlsNoProvider {
        let provider = crate::tls::installed_crypto_provider()?;
        // ureq builds its rustls config lazily and expects valid protocol settings.
        // Validate caller-supplied providers here so errors stay in Client::build().
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .map_err(|error| crate::Error::TlsBackendInit {
                backend: backend.as_str(),
                message: error.to_string(),
            })?;
        builder = builder.unversioned_rustls_crypto_provider(provider);
    }

    Ok(builder)
}

#[cfg(test)]
pub(super) fn configured_rustls_crypto_provider(
    config: &ureq::tls::TlsConfig,
) -> Option<&rustls::crypto::CryptoProvider> {
    config.unversioned_rustls_crypto_provider().as_deref()
}
