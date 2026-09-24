#![cfg(any(
    feature = "async-tls-rustls-no-provider",
    feature = "blocking-tls-rustls-no-provider"
))]

// Separate executable because rustls only allows installing a provider once.
#[test]
fn invalid_provider_is_rejected_at_build_time() {
    let mut provider = rustls_graviola::default_provider();
    provider.cipher_suites.clear();
    provider.install_default().unwrap();

    #[cfg(feature = "async-tls-rustls-no-provider")]
    assert!(matches!(
        reqx::Client::builder("https://localhost")
            .tls_backend(reqx::TlsBackend::RustlsNoProvider)
            .build(),
        Err(reqx::Error::TlsBackendInit { .. })
    ));
    #[cfg(feature = "blocking-tls-rustls-no-provider")]
    assert!(matches!(
        reqx::blocking::Client::builder("https://localhost")
            .tls_backend(reqx::TlsBackend::RustlsNoProvider)
            .build(),
        Err(reqx::Error::TlsBackendInit { .. })
    ));
}
