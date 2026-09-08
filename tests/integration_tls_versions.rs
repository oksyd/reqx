#![cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use reqx::prelude::{Client, RetryPolicy, TlsRootStore, TlsVersion};
use reqx::{Error, TlsBackend, TransportErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

struct TestTlsMaterial {
    ca_cert_pem: String,
    server_cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[cfg(feature = "async-tls-rustls-ring")]
fn test_tls_backend() -> TlsBackend {
    TlsBackend::RustlsRing
}

#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    feature = "async-tls-rustls-aws-lc-rs"
))]
fn test_tls_backend() -> TlsBackend {
    TlsBackend::RustlsAwsLcRs
}

#[cfg(feature = "async-tls-rustls-ring")]
fn test_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    feature = "async-tls-rustls-aws-lc-rs"
))]
fn test_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn rustls_protocol_versions(
    versions: &[TlsVersion],
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    versions
        .iter()
        .copied()
        .map(|version| match version {
            TlsVersion::V1_2 => &rustls::version::TLS12,
            TlsVersion::V1_3 => &rustls::version::TLS13,
            _ => panic!("unexpected TLS version in integration test"),
        })
        .collect()
}

fn test_tls_material() -> TestTlsMaterial {
    test_tls_material_for_names(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
}

fn test_tls_material_for_names(names: Vec<String>) -> TestTlsMaterial {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("build test CA certificate parameters");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "reqx test localhost CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let ca_key = KeyPair::generate().expect("generate test CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("self-sign test CA certificate");
    let ca_cert_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut server_params =
        CertificateParams::new(names).expect("build test server certificate parameters");
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.use_authority_key_identifier_extension = true;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let server_key = KeyPair::generate().expect("generate test server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("sign test server certificate with test CA");

    TestTlsMaterial {
        ca_cert_pem,
        server_cert_chain: vec![server_cert.der().clone(), ca_cert.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::from(server_key),
    }
}

fn server_config(versions: &[TlsVersion], tls_material: &TestTlsMaterial) -> rustls::ServerConfig {
    let cert_chain = tls_material.server_cert_chain.clone();
    let private_key = tls_material.server_key.clone_key();

    rustls::ServerConfig::builder_with_provider(test_crypto_provider())
        .with_protocol_versions(&rustls_protocol_versions(versions))
        .expect("configure server protocol versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .expect("configure test certificate")
}

async fn start_tls_server(
    versions: &[TlsVersion],
    tls_material: &TestTlsMaterial,
) -> (String, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls test server");
    let port = listener
        .local_addr()
        .expect("read tls test server address")
        .port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(versions, tls_material)));
    let join = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tls test connection");
        let Ok(mut tls_stream) = acceptor.accept(stream).await else {
            return false;
        };

        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = tls_stream
                .read(&mut chunk)
                .await
                .expect("read tls test request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        tls_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("write tls test response");
        let _ = tls_stream.shutdown().await;
        true
    });

    (format!("https://localhost:{port}"), join)
}

fn tls_test_client(base_url: &str, ca_cert_pem: &str, version: TlsVersion) -> Client {
    Client::builder(base_url)
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .tls_backend(test_tls_backend())
        .tls_root_store(TlsRootStore::Specific)
        .tls_root_ca_pem(ca_cert_pem)
        .tls_version(version)
        .build()
        .expect("build tls test client")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rustls_webpki_root_store_appends_custom_ca() {
    let tls_material = test_tls_material();
    let (base_url, server) = start_tls_server(&[TlsVersion::V1_3], &tls_material).await;

    let client = Client::builder(&base_url)
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .tls_backend(test_tls_backend())
        .tls_root_store(TlsRootStore::WebPki)
        .tls_root_ca_pem(tls_material.ca_cert_pem.as_str())
        .tls_version(TlsVersion::V1_3)
        .build()
        .expect("build webpki plus custom CA client");

    let response = client
        .get("/webpki-plus-custom-ca")
        .send()
        .await
        .expect("custom CA should be appended to bundled webpki roots");

    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(server.await.expect("join webpki custom CA server"));
}

#[test]
fn rustls_webpki_root_store_rejects_mixed_valid_and_invalid_custom_pem_roots() {
    let tls_material = test_tls_material();
    let mixed_pem = format!(
        "{}\n-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n",
        tls_material.ca_cert_pem
    );

    let result = Client::builder("https://api.example.com")
        .tls_backend(test_tls_backend())
        .tls_root_store(TlsRootStore::WebPki)
        .tls_root_ca_pem(mixed_pem)
        .build();
    let error = match result {
        Ok(_) => panic!("invalid custom PEM root should not be silently ignored"),
        Err(error) => error,
    };

    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("failed to add PEM root certificate"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rustls_tls_version_constraints_restrict_handshake_versions() {
    let tls_material = test_tls_material();

    let (base_url, success_server) = start_tls_server(&[TlsVersion::V1_3], &tls_material).await;
    let success_client = tls_test_client(&base_url, &tls_material.ca_cert_pem, TlsVersion::V1_3);
    let response = success_client
        .get("/version-check")
        .send()
        .await
        .expect("tls 1.3 client should succeed against tls 1.3 server");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(success_server.await.expect("join success server"));

    let (base_url, failure_server) = start_tls_server(&[TlsVersion::V1_3], &tls_material).await;
    let failure_client = Client::builder(&base_url)
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .tls_backend(test_tls_backend())
        .tls_root_store(TlsRootStore::Specific)
        .tls_root_ca_pem(tls_material.ca_cert_pem.as_str())
        .tls_max_version(TlsVersion::V1_2)
        .build()
        .expect("build tls 1.2-capped test client");
    let error = failure_client
        .get("/version-check")
        .send()
        .await
        .expect_err("tls 1.2-only client should fail against tls 1.3-only server");

    match error {
        Error::Transport { kind, .. } => assert_eq!(kind, TransportErrorKind::Tls),
        other => panic!("unexpected error: {other}"),
    }
    assert!(!failure_server.await.expect("join failure server"));
}

#[cfg(feature = "async-tls-native")]
#[tokio::test]
async fn native_tls_negotiates_http_protocol_with_alpn() {
    let tls_material = test_tls_material();
    for (http2_only, protocol) in [
        (true, b"h2".as_slice()),
        (false, b"h2"),
        (false, b"http/1.1"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let base_url = format!(
            "https://localhost:{}",
            listener.local_addr().expect("address").port()
        );
        let mut config = server_config(&[TlsVersion::V1_2], &tls_material);
        config.alpn_protocols = vec![protocol.to_vec()];
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("connection");
            let tls = TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .expect("TLS handshake");
            tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
        });
        let client = Client::builder(&base_url)
            .tls_backend(TlsBackend::NativeTls)
            .tls_root_store(TlsRootStore::Specific)
            .tls_root_ca_pem(tls_material.ca_cert_pem.as_str())
            .http2_only(http2_only)
            .request_timeout(Duration::from_secs(2))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("native client");
        // The server closes after the handshake; only protocol negotiation is under test.
        let _ = client.get("/").send().await;
        let negotiated = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("handshake completed")
            .expect("server task");
        assert_eq!(
            negotiated.as_deref(),
            Some(protocol),
            "http2_only={http2_only}"
        );
    }
}

async fn start_dns_identity_server(
    material: &TestTlsMaterial,
) -> (std::net::SocketAddr, JoinHandle<Option<(String, String)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let acceptor = TlsAcceptor::from(Arc::new(server_config(
        &[TlsVersion::V1_2, TlsVersion::V1_3],
        material,
    )));
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(4), async move {
            let (socket, _) = listener.accept().await.expect("connection");
            let Ok(mut tls) = acceptor.accept(socket).await else {
                return None;
            };
            let name = tls.get_ref().1.server_name().unwrap_or_default().to_owned();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                match tls.read_u8().await {
                    Ok(byte) => header.push(byte),
                    Err(_) => return None,
                }
                assert!(header.len() < 8192);
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("response");
            let _ = tls.shutdown().await;
            Some((name, String::from_utf8(header).expect("header")))
        })
        .await
        .expect("TLS server deadline")
    });
    (address, server)
}

#[tokio::test]
async fn dns_overrides_preserve_async_tls_identity() {
    let mut backends = Vec::new();
    #[cfg(feature = "async-tls-rustls-ring")]
    backends.push(TlsBackend::RustlsRing);
    #[cfg(feature = "async-tls-rustls-aws-lc-rs")]
    backends.push(TlsBackend::RustlsAwsLcRs);
    #[cfg(feature = "async-tls-native")]
    backends.push(TlsBackend::NativeTls);
    for backend in backends {
        for valid in [true, false] {
            let material = test_tls_material_for_names(vec![
                if valid {
                    "pinned.invalid"
                } else {
                    "wrong.invalid"
                }
                .to_owned(),
            ]);
            let (address, server) = start_dns_identity_server(&material).await;
            let client = Client::builder("https://pinned.invalid")
                .tls_backend(backend)
                .tls_root_store(TlsRootStore::Specific)
                .tls_root_ca_pem(material.ca_cert_pem.as_str())
                .resolve("pinned.invalid", address)
                .request_timeout(Duration::from_secs(2))
                .retry_policy(RetryPolicy::disabled())
                .build()
                .expect("client");
            let response = client.get("/identity").send().await;
            let observed = server.await.expect("server");
            if valid {
                assert!(response.is_ok(), "{backend:?}: {response:?}");
                let (sni, header) = observed.expect("TLS accepted");
                assert_eq!(sni, "pinned.invalid");
                assert!(
                    header
                        .to_ascii_lowercase()
                        .contains("host: pinned.invalid\r\n")
                );
                assert!(header.starts_with("GET /identity "));
            } else {
                assert!(
                    matches!(
                        response,
                        Err(Error::Transport {
                            kind: TransportErrorKind::Tls,
                            ..
                        })
                    ),
                    "{backend:?}: {response:?}"
                );
            }
        }
    }
}

#[cfg(feature = "_blocking")]
#[tokio::test]
async fn dns_overrides_preserve_blocking_tls_identity() {
    let mut backends = Vec::new();
    #[cfg(feature = "blocking-tls-rustls-ring")]
    backends.push(TlsBackend::RustlsRing);
    #[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
    backends.push(TlsBackend::RustlsAwsLcRs);
    #[cfg(feature = "blocking-tls-native")]
    backends.push(TlsBackend::NativeTls);
    for backend in backends {
        for valid in [true, false] {
            let material = test_tls_material_for_names(vec![
                if valid {
                    "pinned.invalid"
                } else {
                    "wrong.invalid"
                }
                .to_owned(),
            ]);
            let (address, server) = start_dns_identity_server(&material).await;
            let response = tokio::task::spawn_blocking(move || {
                let client = reqx::blocking::Client::builder("https://pinned.invalid")
                    .tls_backend(backend)
                    .tls_root_store(TlsRootStore::Specific)
                    .tls_root_ca_pem(material.ca_cert_pem.as_str())
                    .resolve("pinned.invalid", address)
                    .request_timeout(Duration::from_secs(2))
                    .retry_policy(RetryPolicy::disabled())
                    .build()
                    .expect("client");
                client.get("/identity").send()
            })
            .await
            .expect("blocking request");
            let observed = server.await.expect("server");
            if valid {
                assert!(response.is_ok(), "{backend:?}: {response:?}");
                let (sni, header) = observed.expect("TLS accepted");
                assert_eq!(sni, "pinned.invalid");
                assert!(
                    header
                        .to_ascii_lowercase()
                        .contains("host: pinned.invalid\r\n")
                );
            } else {
                assert!(observed.is_none(), "certificate mismatch must prevent HTTP");
                assert!(
                    matches!(
                        response,
                        Err(Error::Transport {
                            kind: TransportErrorKind::Tls | TransportErrorKind::Other,
                            ..
                        })
                    ),
                    "{backend:?}: {response:?}"
                );
            }
        }
    }
}
