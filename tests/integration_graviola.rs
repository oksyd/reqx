#![cfg(any(feature = "_async", feature = "_blocking"))]

use reqx::TlsBackend;

#[cfg(any(
    feature = "async-tls-rustls-graviola",
    feature = "blocking-tls-rustls-graviola"
))]
#[path = "support/tls.rs"]
mod tls;

// Keep the global provider assertions in one test and a separate executable.
#[test]
fn graviola_is_configured_per_client() {
    #[cfg(all(feature = "_async", not(feature = "async-tls-rustls-graviola")))]
    assert!(matches!(
        reqx::Client::builder("https://localhost")
            .tls_backend(TlsBackend::RustlsGraviola)
            .build(),
        Err(reqx::Error::TlsBackendUnavailable {
            backend: "rustls-graviola"
        })
    ));
    #[cfg(all(feature = "_blocking", not(feature = "blocking-tls-rustls-graviola")))]
    assert!(matches!(
        reqx::blocking::Client::builder("https://localhost")
            .tls_backend(TlsBackend::RustlsGraviola)
            .build(),
        Err(reqx::Error::TlsBackendUnavailable {
            backend: "rustls-graviola"
        })
    ));

    #[cfg(any(
        feature = "async-tls-rustls-graviola",
        feature = "blocking-tls-rustls-graviola"
    ))]
    {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        exercise_requests();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());

        // An unusable global provider makes accidental reliance on it observable.
        let mut global = rustls_graviola::default_provider();
        global.cipher_suites.clear();
        global.install_default().unwrap();
        exercise_requests();
        assert!(
            rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .cipher_suites
                .is_empty()
        );
    }
}

#[cfg(any(
    feature = "async-tls-rustls-graviola",
    feature = "blocking-tls-rustls-graviola"
))]
fn exercise_requests() {
    use reqx::TlsRootStore;
    use reqx::prelude::RetryPolicy;
    use std::time::Duration;

    #[cfg(feature = "async-tls-rustls-graviola")]
    {
        let (url, pem, server) = tls::server();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let client = reqx::Client::builder(&url)
                .tls_backend(TlsBackend::RustlsGraviola)
                .tls_root_store(TlsRootStore::Specific)
                .tls_root_ca_pem(pem)
                .retry_policy(RetryPolicy::disabled())
                .request_timeout(Duration::from_secs(5))
                .build()
                .expect("async Graviola client");
            assert_eq!(client.tls_backend(), TlsBackend::RustlsGraviola);
            let response = client
                .get("/provider")
                .send()
                .await
                .expect("async Graviola TLS request");
            assert_eq!(response.body().as_ref(), b"ok");

            #[cfg(not(any(
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs",
                feature = "async-tls-native"
            )))]
            assert_eq!(
                reqx::Client::builder(&url).build().unwrap().tls_backend(),
                TlsBackend::RustlsGraviola
            );
        });
        server.join().unwrap();
    }

    #[cfg(feature = "blocking-tls-rustls-graviola")]
    {
        let (url, pem, server) = tls::server();
        let client = reqx::blocking::Client::builder(&url)
            .tls_backend(TlsBackend::RustlsGraviola)
            .tls_root_store(TlsRootStore::Specific)
            .tls_root_ca_pem(pem)
            .retry_policy(RetryPolicy::disabled())
            .request_timeout(Duration::from_secs(5))
            .build()
            .expect("blocking Graviola client");
        assert_eq!(client.tls_backend(), TlsBackend::RustlsGraviola);
        let response = client
            .get("/provider")
            .send()
            .expect("blocking Graviola TLS request");
        assert_eq!(response.body().as_ref(), b"ok");
        server.join().unwrap();

        #[cfg(not(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-native"
        )))]
        assert_eq!(
            reqx::blocking::Client::builder(&url)
                .build()
                .unwrap()
                .tls_backend(),
            TlsBackend::RustlsGraviola
        );
    }
}
