use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, Uri};

use crate::core::error::TransportErrorKind;
use crate::core::proxy::ProxyConfig;
use crate::core::util::read_retry_interrupted;
use crate::tls::{TlsBackend, TlsOptions};
#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
))]
use crate::tls::{
    TlsClientIdentity, TlsRootCertificate, TlsRootStore, parse_pem_certificate_blocks,
    tls_config_error, tls_version_bounds,
};

#[cfg(feature = "blocking-tls-rustls-ring")]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;
#[cfg(all(
    not(feature = "blocking-tls-rustls-ring"),
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsAwsLcRs;
#[cfg(all(
    not(feature = "blocking-tls-rustls-ring"),
    not(feature = "blocking-tls-rustls-aws-lc-rs"),
    feature = "blocking-tls-native"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::NativeTls;
#[cfg(all(
    not(feature = "blocking-tls-rustls-ring"),
    not(feature = "blocking-tls-rustls-aws-lc-rs"),
    not(feature = "blocking-tls-native"),
    feature = "blocking-tls-rustls-no-provider"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsNoProvider;
#[cfg(not(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
)))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;

pub(super) fn default_tls_backend() -> TlsBackend {
    DEFAULT_TLS_BACKEND
}

pub(super) fn backend_is_available(backend: TlsBackend) -> bool {
    match backend {
        TlsBackend::RustlsRing => cfg!(feature = "blocking-tls-rustls-ring"),
        TlsBackend::RustlsAwsLcRs => cfg!(feature = "blocking-tls-rustls-aws-lc-rs"),
        TlsBackend::NativeTls => cfg!(feature = "blocking-tls-native"),
        TlsBackend::RustlsNoProvider => cfg!(feature = "blocking-tls-rustls-no-provider"),
    }
}

pub(super) fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

pub(super) fn is_proxy_bypassed(proxy: &ProxyConfig, uri: &Uri) -> bool {
    crate::core::proxy::should_bypass_proxy_uri(&proxy.no_proxy_rules, uri)
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
))]
fn parse_pem_certificates(
    backend: TlsBackend,
    pem_bundle: &[u8],
    context: &str,
) -> crate::Result<Vec<ureq::tls::Certificate<'static>>> {
    let mut certificates = Vec::new();
    for certificate_block in parse_pem_certificate_blocks(backend, pem_bundle, context)? {
        let certificate =
            ureq::tls::Certificate::from_pem(&certificate_block).map_err(|source| {
                tls_config_error(backend, format!("failed to parse PEM {context}: {source}"))
            })?;
        certificates.push(certificate);
    }
    Ok(certificates)
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider"
))]
fn load_system_root_certificates(
    backend: TlsBackend,
) -> crate::Result<Vec<ureq::tls::Certificate<'static>>> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut certificates = Vec::new();

    for certificate in loaded.certs {
        certificates.push(ureq::tls::Certificate::from_der(certificate.as_ref()).to_owned());
    }

    if certificates.is_empty() && !loaded.errors.is_empty() {
        return Err(tls_config_error(
            backend,
            "failed to load system root certificates",
        ));
    }

    Ok(certificates)
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider"
))]
fn bundled_webpki_root_certificates() -> Vec<ureq::tls::Certificate<'static>> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|certificate| ureq::tls::Certificate::from_der(certificate.as_ref()).to_owned())
        .collect()
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider"
))]
fn validate_custom_rustls_root_certificates(
    backend: TlsBackend,
    roots: &[ureq::tls::Certificate<'static>],
) -> crate::Result<()> {
    let mut root_store = rustls::RootCertStore::empty();
    for root in roots {
        root_store
            .add(rustls::pki_types::CertificateDer::from(root.der().to_vec()))
            .map_err(|source| {
                tls_config_error(
                    backend,
                    format!("failed to parse custom root certificate: {source}"),
                )
            })?;
    }
    Ok(())
}

#[cfg(feature = "blocking-tls-native")]
fn validate_custom_native_tls_root_certificates(
    backend: TlsBackend,
    roots: &[ureq::tls::Certificate<'static>],
) -> crate::Result<()> {
    for root in roots {
        native_tls::Certificate::from_der(root.der()).map_err(|source| {
            tls_config_error(
                backend,
                format!("failed to parse custom root certificate: {source}"),
            )
        })?;
    }
    Ok(())
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
))]
fn build_sync_tls_config(
    backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<ureq::tls::TlsConfig> {
    if !backend_is_available(backend) {
        return Err(crate::core::error::Error::TlsBackendUnavailable {
            backend: backend.as_str(),
        });
    }

    let version_bounds = tls_version_bounds(backend, tls_options)?;
    if version_bounds.min.is_some() || version_bounds.max.is_some() {
        return Err(tls_config_error(
            backend,
            "TLS version bounds are unsupported for blocking ureq transport; protocol version overrides are currently available only for async backends",
        ));
    }

    let provider = match backend {
        TlsBackend::RustlsRing | TlsBackend::RustlsAwsLcRs => ureq::tls::TlsProvider::Rustls,
        TlsBackend::NativeTls => ureq::tls::TlsProvider::NativeTls,
        TlsBackend::RustlsNoProvider => ureq::tls::TlsProvider::Rustls,
    };

    let mut tls_config_builder = ureq::tls::TlsConfig::builder().provider(provider);

    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            backend,
            "custom root CAs require tls_root_store(TlsRootStore::WebPki), tls_root_store(TlsRootStore::System), or tls_root_store(TlsRootStore::Specific)",
        ));
    }

    if backend == TlsBackend::NativeTls && tls_options.root_store == TlsRootStore::WebPki {
        return Err(tls_config_error(
            backend,
            "tls_root_store(TlsRootStore::WebPki) is unsupported for native-tls backend; use BackendDefault, System, or Specific",
        ));
    }

    if backend == TlsBackend::NativeTls
        && tls_options.root_store == TlsRootStore::System
        && !tls_options.root_certificates.is_empty()
    {
        return Err(tls_config_error(
            backend,
            "blocking native-tls backend cannot combine system roots with custom root CAs; use tls_root_store(TlsRootStore::Specific) to trust only explicit roots",
        ));
    }

    if tls_options.root_store == TlsRootStore::Specific && tls_options.root_certificates.is_empty()
    {
        return Err(tls_config_error(
            backend,
            "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
        ));
    }

    let mut roots = Vec::new();
    for root_certificate in &tls_options.root_certificates {
        match root_certificate {
            TlsRootCertificate::Pem(pem) => {
                roots.extend(parse_pem_certificates(backend, pem, "root certificate")?);
            }
            TlsRootCertificate::Der(der) => {
                roots.push(ureq::tls::Certificate::from_der(der).to_owned());
            }
        }
    }

    #[cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    if matches!(
        backend,
        TlsBackend::RustlsRing | TlsBackend::RustlsAwsLcRs | TlsBackend::RustlsNoProvider
    ) {
        validate_custom_rustls_root_certificates(backend, &roots)?;
    }

    #[cfg(feature = "blocking-tls-native")]
    if backend == TlsBackend::NativeTls {
        validate_custom_native_tls_root_certificates(backend, &roots)?;
    }

    match tls_options.root_store {
        TlsRootStore::BackendDefault => {
            if matches!(
                backend,
                TlsBackend::RustlsRing | TlsBackend::RustlsAwsLcRs | TlsBackend::RustlsNoProvider
            ) {
                tls_config_builder = tls_config_builder.root_certs(ureq::tls::RootCerts::WebPki);
            } else {
                tls_config_builder =
                    tls_config_builder.root_certs(ureq::tls::RootCerts::PlatformVerifier);
            }
        }
        TlsRootStore::WebPki => {
            #[cfg(any(
                feature = "blocking-tls-rustls-ring",
                feature = "blocking-tls-rustls-aws-lc-rs",
                feature = "blocking-tls-rustls-no-provider"
            ))]
            {
                if roots.is_empty() {
                    tls_config_builder =
                        tls_config_builder.root_certs(ureq::tls::RootCerts::WebPki);
                } else {
                    let mut combined_roots = bundled_webpki_root_certificates();
                    combined_roots.extend(roots);
                    tls_config_builder = tls_config_builder
                        .root_certs(ureq::tls::RootCerts::new_with_certs(&combined_roots));
                }
            }
            #[cfg(not(any(
                feature = "blocking-tls-rustls-ring",
                feature = "blocking-tls-rustls-aws-lc-rs",
                feature = "blocking-tls-rustls-no-provider"
            )))]
            {
                return Err(crate::core::error::Error::TlsBackendUnavailable {
                    backend: backend.as_str(),
                });
            }
        }
        TlsRootStore::System => {
            if roots.is_empty() {
                tls_config_builder =
                    tls_config_builder.root_certs(ureq::tls::RootCerts::PlatformVerifier);
            } else {
                #[cfg(any(
                    feature = "blocking-tls-rustls-ring",
                    feature = "blocking-tls-rustls-aws-lc-rs",
                    feature = "blocking-tls-rustls-no-provider"
                ))]
                {
                    let mut combined_roots = load_system_root_certificates(backend)?;
                    combined_roots.extend(roots);
                    if combined_roots.is_empty() {
                        return Err(tls_config_error(
                            backend,
                            "failed to load system root certificates",
                        ));
                    }
                    tls_config_builder = tls_config_builder
                        .root_certs(ureq::tls::RootCerts::new_with_certs(&combined_roots));
                }
                #[cfg(not(any(
                    feature = "blocking-tls-rustls-ring",
                    feature = "blocking-tls-rustls-aws-lc-rs",
                    feature = "blocking-tls-rustls-no-provider"
                )))]
                {
                    return Err(crate::core::error::Error::TlsBackendUnavailable {
                        backend: backend.as_str(),
                    });
                }
            }
        }
        TlsRootStore::Specific => {
            tls_config_builder =
                tls_config_builder.root_certs(ureq::tls::RootCerts::new_with_certs(&roots));
        }
    }

    if let Some(identity) = &tls_options.client_identity {
        let client_cert = match identity {
            TlsClientIdentity::Pem {
                cert_chain_pem,
                private_key_pem,
            } => {
                let cert_chain =
                    parse_pem_certificates(backend, cert_chain_pem, "mTLS certificate chain")?;
                let private_key =
                    ureq::tls::PrivateKey::from_pem(private_key_pem).map_err(|source| {
                        tls_config_error(
                            backend,
                            format!("failed to parse mTLS private key PEM: {source}"),
                        )
                    })?;
                ureq::tls::ClientCert::new_with_certs(&cert_chain, private_key)
            }
            TlsClientIdentity::Pkcs12 {
                identity_der,
                password,
            } => {
                return Err(tls_config_error(
                    backend,
                    format!(
                        "PKCS#12 identity is unsupported in sync ureq transport; use PEM cert+key (pkcs12_bytes={}, password_len={})",
                        identity_der.len(),
                        password.len(),
                    ),
                ));
            }
        };
        tls_config_builder = tls_config_builder.client_cert(Some(client_cert));
    }

    #[cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    {
        tls_config_builder =
            super::ureq_compat::pin_rustls_crypto_provider(tls_config_builder, backend)?;
    }

    Ok(tls_config_builder.build())
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
))]
pub(super) fn make_agent_config(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
    client_name: &str,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_max_idle_connections: usize,
    proxy: Option<ureq::Proxy>,
) -> crate::Result<ureq::config::Config> {
    let tls_config = build_sync_tls_config(tls_backend, tls_options)?;
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        // reqx owns redirect semantics; keep ureq from auto-following 3xx.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .user_agent(client_name)
        .max_idle_age(pool_idle_timeout)
        .max_idle_connections_per_host(pool_max_idle_per_host)
        .max_idle_connections(pool_max_idle_connections)
        .tls_config(tls_config)
        .proxy(proxy)
        .build();
    Ok(config)
}

#[cfg(not(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-rustls-no-provider",
    feature = "blocking-tls-native"
)))]
pub(super) fn make_agent_config(
    tls_backend: TlsBackend,
    _tls_options: &TlsOptions,
    _client_name: &str,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _pool_max_idle_connections: usize,
    _proxy: Option<ureq::Proxy>,
) -> crate::Result<ureq::config::Config> {
    Err(crate::core::error::Error::TlsBackendUnavailable {
        backend: tls_backend.as_str(),
    })
}

#[derive(Clone)]
pub(super) struct TransportAgents {
    pub(super) direct: ureq::Agent,
    pub(super) proxy: Option<ureq::Agent>,
}

pub(crate) fn is_timeout_io_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) || error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
        .is_some_and(|source| matches!(source, ureq::Error::Timeout(_)))
}

pub(super) fn classify_ureq_transport_error(error: &ureq::Error) -> TransportErrorKind {
    match error {
        ureq::Error::HostNotFound => TransportErrorKind::Dns,
        ureq::Error::Tls(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-rustls-no-provider"
        ))]
        ureq::Error::Rustls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::NativeTls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::Der(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-rustls-no-provider",
            feature = "blocking-tls-native"
        ))]
        ureq::Error::Pem(_) => TransportErrorKind::Tls,
        ureq::Error::ConnectProxyFailed(_) | ureq::Error::ConnectionFailed => {
            TransportErrorKind::Connect
        }
        ureq::Error::Io(source) if crate::core::util::is_tls_error(source) => {
            TransportErrorKind::Tls
        }
        ureq::Error::Io(source) => {
            crate::core::util::classify_io_transport_error_kind(source.kind(), false)
                .unwrap_or(TransportErrorKind::Other)
        }
        _ => TransportErrorKind::Other,
    }
}

#[derive(Debug)]
pub(super) enum ReadBodyError {
    Read(std::io::Error),
    TooLarge { actual_bytes: usize },
}

pub(super) fn read_all_body_limited(
    response: &mut ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut reader = response.body_mut().as_reader();
    read_reader_limited(&mut reader, max_bytes)
}

fn read_reader_limited<R: std::io::Read>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut collected = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut total_len = 0_usize;

    loop {
        let read = read_retry_interrupted(reader, &mut chunk).map_err(ReadBodyError::Read)?;
        if read == 0 {
            break;
        }
        total_len = total_len.saturating_add(read);
        if total_len > max_bytes {
            return Err(ReadBodyError::TooLarge {
                actual_bytes: total_len,
            });
        }
        collected.extend_from_slice(&chunk[..read]);
    }

    Ok(Bytes::from(collected))
}

#[cfg(test)]
mod read_tests {
    use std::io::{self, Read};

    use super::read_reader_limited;

    struct InterruptedOnceReader {
        data: Vec<u8>,
        offset: usize,
        interrupted: bool,
    }

    impl InterruptedOnceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
                interrupted: false,
            }
        }
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.offset >= self.data.len() {
                return Ok(0);
            }

            let read = buffer.len().min(self.data.len() - self.offset);
            buffer[..read].copy_from_slice(&self.data[self.offset..self.offset + read]);
            self.offset += read;
            Ok(read)
        }
    }

    #[test]
    fn read_reader_limited_retries_interrupted_reads() {
        let mut reader = InterruptedOnceReader::new(b"response");
        let body =
            read_reader_limited(&mut reader, 16).expect("interrupted read should be retried");

        assert_eq!(body.as_ref(), b"response");
    }
}

#[cfg(all(
    test,
    any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-no-provider"
    )
))]
mod rustls_tls_config_tests {
    use super::build_sync_tls_config;
    use crate::tls::{TlsBackend, TlsOptions, TlsRootCertificate, TlsRootStore};

    fn assert_crypto_provider_matches(
        configured: &rustls::crypto::CryptoProvider,
        expected: &rustls::crypto::CryptoProvider,
    ) {
        assert_eq!(configured.cipher_suites, expected.cipher_suites);
        assert_eq!(
            configured
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            expected
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "blocking-tls-rustls-ring")]
    fn test_tls_backend() -> TlsBackend {
        TlsBackend::RustlsRing
    }

    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        feature = "blocking-tls-rustls-aws-lc-rs"
    ))]
    fn test_tls_backend() -> TlsBackend {
        TlsBackend::RustlsAwsLcRs
    }

    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        not(feature = "blocking-tls-rustls-aws-lc-rs"),
        feature = "blocking-tls-rustls-no-provider"
    ))]
    fn test_tls_backend() -> TlsBackend {
        TlsBackend::RustlsNoProvider
    }

    #[cfg(feature = "blocking-tls-rustls-no-provider")]
    #[test]
    fn no_provider_backend_preserves_installed_provider_identity() {
        crate::test_support::install_crypto_provider();
        let config = build_sync_tls_config(TlsBackend::RustlsNoProvider, &TlsOptions::default())
            .expect("custom provider TLS config");
        let configured = super::super::ureq_compat::configured_rustls_crypto_provider(&config)
            .expect("explicit provider on ureq config");
        let installed = rustls::crypto::CryptoProvider::get_default().expect("installed provider");
        assert!(std::ptr::eq(configured, installed.as_ref()));
    }

    #[test]
    fn rustls_backend_pins_crypto_provider() {
        crate::test_support::install_crypto_provider();
        let backend = test_tls_backend();
        let config = build_sync_tls_config(backend, &TlsOptions::default())
            .expect("rustls TLS config should build");
        let configured = super::super::ureq_compat::configured_rustls_crypto_provider(&config)
            .expect("rustls backend should pin its crypto provider");

        #[cfg(feature = "blocking-tls-rustls-ring")]
        if backend == TlsBackend::RustlsRing {
            assert_crypto_provider_matches(configured, &rustls::crypto::ring::default_provider());
        }

        #[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
        if backend == TlsBackend::RustlsAwsLcRs {
            assert_crypto_provider_matches(
                configured,
                &rustls::crypto::aws_lc_rs::default_provider(),
            );
        }
        #[cfg(feature = "blocking-tls-rustls-no-provider")]
        if backend == TlsBackend::RustlsNoProvider {
            assert_crypto_provider_matches(configured, &rustls_graviola::default_provider());
        }
    }

    #[test]
    fn webpki_root_store_appends_custom_roots() {
        crate::test_support::install_crypto_provider();
        let custom_root = webpki_root_certs::TLS_SERVER_ROOT_CERTS[0]
            .as_ref()
            .to_vec();
        let options = TlsOptions {
            root_store: TlsRootStore::WebPki,
            root_certificates: vec![TlsRootCertificate::Der(custom_root)],
            ..TlsOptions::default()
        };

        let config = build_sync_tls_config(test_tls_backend(), &options)
            .expect("rustls should combine webpki roots with custom roots");

        match config.root_certs() {
            ureq::tls::RootCerts::Specific(certs) => {
                assert_eq!(
                    certs.len(),
                    webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() + 1
                );
            }
            other => panic!("unexpected root cert config: {other:?}"),
        }
    }

    #[test]
    fn webpki_root_store_rejects_invalid_custom_root() {
        crate::test_support::install_crypto_provider();
        let options = TlsOptions {
            root_store: TlsRootStore::WebPki,
            root_certificates: vec![TlsRootCertificate::Der(vec![1, 2, 3, 4])],
            ..TlsOptions::default()
        };

        let error = build_sync_tls_config(test_tls_backend(), &options)
            .expect_err("invalid custom root should fail before webpki roots are added");

        match error {
            crate::core::error::Error::TlsConfig { message, .. } => {
                assert!(message.contains("failed to parse custom root certificate"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}

#[cfg(all(test, feature = "blocking-tls-native"))]
mod native_tls_config_tests {
    use super::build_sync_tls_config;
    use crate::core::error::Error;
    use crate::tls::{TlsBackend, TlsOptions, TlsRootStore};

    #[test]
    fn native_tls_backend_default_uses_platform_roots() {
        crate::test_support::install_crypto_provider();
        let config = build_sync_tls_config(TlsBackend::NativeTls, &TlsOptions::default())
            .expect("native-tls config should build");

        assert_eq!(config.provider(), ureq::tls::TlsProvider::NativeTls);
        assert!(matches!(
            config.root_certs(),
            &ureq::tls::RootCerts::PlatformVerifier
        ));
    }

    #[test]
    fn native_tls_webpki_root_store_is_rejected_before_agent_build() {
        crate::test_support::install_crypto_provider();
        let options = TlsOptions {
            root_store: TlsRootStore::WebPki,
            ..TlsOptions::default()
        };

        let error = build_sync_tls_config(TlsBackend::NativeTls, &options)
            .expect_err("native-tls should reject WebPki roots");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("TlsRootStore::WebPki"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn native_tls_system_roots_cannot_be_extended_with_custom_roots() {
        crate::test_support::install_crypto_provider();
        let options = TlsOptions {
            root_store: TlsRootStore::System,
            root_certificates: vec![crate::tls::TlsRootCertificate::Der(vec![1, 2, 3, 4])],
            ..TlsOptions::default()
        };

        let error = build_sync_tls_config(TlsBackend::NativeTls, &options)
            .expect_err("native-tls should reject system roots plus custom roots");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("cannot combine system roots"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn native_tls_specific_rejects_invalid_custom_root() {
        crate::test_support::install_crypto_provider();
        let options = TlsOptions {
            root_store: TlsRootStore::Specific,
            root_certificates: vec![crate::tls::TlsRootCertificate::Der(vec![1, 2, 3, 4])],
            ..TlsOptions::default()
        };

        let error = build_sync_tls_config(TlsBackend::NativeTls, &options)
            .expect_err("native-tls should reject invalid custom roots during config build");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("failed to parse custom root certificate"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}

#[cfg(test)]
mod transport_error_classification_tests {
    use super::classify_ureq_transport_error;
    use crate::core::error::TransportErrorKind;

    #[cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    #[test]
    fn wrapped_tls_errors_retain_their_category() {
        for kind in [
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::ConnectionReset,
        ] {
            let error = ureq::Error::Io(std::io::Error::new(
                kind,
                std::io::Error::other(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                )),
            ));
            assert_eq!(
                classify_ureq_transport_error(&error),
                TransportErrorKind::Tls
            );
        }
        let error = ureq::Error::Io(std::io::Error::other(
            "certificate error in arbitrary user text",
        ));
        assert_eq!(
            classify_ureq_transport_error(&error),
            TransportErrorKind::Other
        );
    }

    #[test]
    fn blocking_transport_maps_extended_connect_error_kinds() {
        let host_unreachable =
            ureq::Error::Io(std::io::Error::from(std::io::ErrorKind::HostUnreachable));
        assert_eq!(
            classify_ureq_transport_error(&host_unreachable),
            TransportErrorKind::Connect
        );

        let network_unreachable =
            ureq::Error::Io(std::io::Error::from(std::io::ErrorKind::NetworkUnreachable));
        assert_eq!(
            classify_ureq_transport_error(&network_unreachable),
            TransportErrorKind::Connect
        );
    }
}

#[cfg(test)]
mod contract_tests;
