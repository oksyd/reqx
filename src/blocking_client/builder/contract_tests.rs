use crate::core::error::{Error, ErrorCode};
use crate::tls::{TlsBackend, TlsRootStore};

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
#[test]
fn blocking_rustls_root_ca_pem_rejects_non_certificate_blocks() {
    #[cfg(feature = "blocking-tls-rustls-ring")]
    let backend = TlsBackend::RustlsRing;
    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        feature = "blocking-tls-rustls-aws-lc-rs"
    ))]
    let backend = TlsBackend::RustlsAwsLcRs;

    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .tls_backend(backend)
        .tls_root_store(TlsRootStore::WebPki)
        .tls_root_ca_pem(
            b"-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n".to_vec(),
        )
        .build();

    let error = match result {
        Ok(_) => panic!("root CA PEM should reject non-certificate PEM blocks"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("non-certificate block"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "blocking-tls-native")]
#[test]
fn blocking_native_tls_webpki_root_store_is_rejected() {
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_root_store(TlsRootStore::WebPki)
        .build();
    let error = match result {
        Ok(_) => panic!("blocking native tls should reject webpki root store"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::WebPki"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_try_add_no_proxy_rejects_invalid_rule() {
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .try_add_no_proxy("[::1]not-a-port");
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_no_proxy_records_invalid_rule_and_build_fails() {
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .no_proxy(["example.com", "[::1]not-a-port"])
        .build();
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail at build time"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_no_proxy_build_error_redacts_sensitive_url_shaped_rule() {
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .no_proxy(["https://user:pass@api.example.com/v1?token=secret"])
        .build();
    let error = match result {
        Ok(_) => panic!("sensitive invalid no_proxy rule should fail at build time"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "https://api.example.com/v1"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_build_rejects_non_http_proxy_scheme() {
    let proxy_uri: http::Uri = "https://proxy.example.com:8443"
        .parse()
        .expect("proxy uri should parse");
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("non-http proxy scheme should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "https://proxy.example.com:8443/");
            assert!(message.contains("http scheme"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_build_rejects_http_proxy_uri_with_invalid_authority() {
    let proxy_uri: http::Uri = "http://proxy.example.com:invalid"
        .parse()
        .expect("proxy uri should parse");
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("http_proxy URI with invalid authority should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "http://proxy.example.com:invalid/");
            assert!(message.contains("valid authority"));
            assert!(message.contains("numeric port"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_build_rejects_http_proxy_uri_with_empty_port() {
    let proxy_uri: http::Uri = "http://proxy.example.com:/"
        .parse()
        .expect("proxy uri should parse");
    let result = crate::blocking_client::Client::builder("https://api.example.com")
        .http_proxy(proxy_uri)
        .build();
    let error = match result {
        Ok(_) => panic!("http_proxy URI with empty port should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidProxyConfig { proxy_uri, message } => {
            assert_eq!(proxy_uri, "http://proxy.example.com:/");
            assert!(message.contains("valid authority"));
            assert!(message.contains("numeric port"));
        }
        other => panic!("unexpected error: {other}"),
    }
}
