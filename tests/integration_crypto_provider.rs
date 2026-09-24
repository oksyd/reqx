#![cfg(any(feature = "_async", feature = "_blocking"))]

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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use reqx::prelude::RetryPolicy;
    use reqx::{TlsBackend, TlsRootStore};

    fn server() -> (String, String, std::thread::JoinHandle<()>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test certificate");
        let pem = cert.pem();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls_graviola::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key.into())
        .expect("server certificate");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        listener.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client did not connect");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).expect("TLS request");
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            assert!(request.starts_with(b"GET /provider HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("TLS response");
            stream.flush().unwrap();
        });
        (url, pem, worker)
    }

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
