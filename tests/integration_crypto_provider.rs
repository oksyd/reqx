#![cfg(any(feature = "_async", feature = "_blocking"))]

#[cfg(any(
    feature = "async-tls-rustls-no-provider",
    feature = "blocking-tls-rustls-no-provider"
))]
#[path = "support/tls.rs"]
mod tls;

use reqx::{Error, TlsBackend};

fn assert_provider_error(error: Error, available: bool) {
    match error {
        Error::TlsBackendInit { backend, message } if available => {
            assert_eq!(backend, "rustls-no-provider");
            assert!(message.contains("install_default"));
        }
        Error::TlsBackendUnavailable { backend } if !available => {
            assert_eq!(backend, "rustls-no-provider");
        }
        other => panic!("unexpected provider error: {other:?}"),
    }
}

// One test in its own executable: no other test can install a global provider
// before the missing-provider assertions, even under nextest or --all-features.
#[test]
fn caller_installed_crypto_provider_contract() {
    #[cfg(feature = "_async")]
    assert_provider_error(
        reqx::Client::builder("https://localhost")
            .tls_backend(TlsBackend::RustlsNoProvider)
            .build()
            .err()
            .expect("uninstalled or disabled provider must fail during build"),
        cfg!(feature = "async-tls-rustls-no-provider"),
    );
    #[cfg(feature = "_blocking")]
    assert_provider_error(
        reqx::blocking::Client::builder("https://localhost")
            .tls_backend(TlsBackend::RustlsNoProvider)
            .build()
            .err()
            .expect("uninstalled or disabled provider must fail during build"),
        cfg!(feature = "blocking-tls-rustls-no-provider"),
    );

    #[cfg(any(
        feature = "async-tls-rustls-no-provider",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    handshake::exercise();
}

#[cfg(any(
    feature = "async-tls-rustls-no-provider",
    feature = "blocking-tls-rustls-no-provider"
))]
mod handshake {
    use crate::tls::server;
    use std::time::Duration;

    use reqx::prelude::RetryPolicy;
    use reqx::{TlsBackend, TlsRootStore};

    pub(super) fn exercise() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        rustls_graviola::default_provider()
            .install_default()
            .unwrap();

        #[cfg(feature = "async-tls-rustls-no-provider")]
        {
            let (url, pem, server) = server();
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let client = reqx::Client::builder(url)
                    .tls_backend(TlsBackend::RustlsNoProvider)
                    .tls_root_store(TlsRootStore::Specific)
                    .tls_root_ca_pem(pem)
                    .retry_policy(RetryPolicy::disabled())
                    .request_timeout(Duration::from_secs(5))
                    .build()
                    .expect("async custom provider client");
                assert_eq!(client.tls_backend(), TlsBackend::RustlsNoProvider);
                let response = client
                    .get("/provider")
                    .send()
                    .await
                    .expect("async TLS request");
                assert_eq!(response.body().as_ref(), b"ok");
            });
            server.join().unwrap();
        }
        #[cfg(feature = "blocking-tls-rustls-no-provider")]
        {
            let (url, pem, server) = server();
            let client = reqx::blocking::Client::builder(url)
                .tls_backend(TlsBackend::RustlsNoProvider)
                .tls_root_store(TlsRootStore::Specific)
                .tls_root_ca_pem(pem)
                .retry_policy(RetryPolicy::disabled())
                .request_timeout(Duration::from_secs(5))
                .build()
                .expect("blocking custom provider client");
            assert_eq!(client.tls_backend(), TlsBackend::RustlsNoProvider);
            let response = client
                .get("/provider")
                .send()
                .expect("blocking TLS request");
            assert_eq!(response.body().as_ref(), b"ok");
            server.join().unwrap();
        }
    }
}
