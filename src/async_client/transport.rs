#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response as HttpResponse};
use hyper::body::Incoming;
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use hyper_util::rt::TokioExecutor;
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use tracing::warn;

use crate::body::ReqBody;
use crate::error::Error;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use crate::error::transport_error;
use crate::execution::RequestExecutionState;
use crate::proxy::ProxyConnector;
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native",
    feature = "async-tls-rustls-no-provider"
))]
use crate::tls::tls_config_error;
use crate::tls::{TlsBackend, TlsOptions};
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
use crate::tls::{TlsClientIdentity, TlsRootCertificate, TlsRootStore, TlsVersion};
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native",
    feature = "async-tls-rustls-no-provider"
))]
use crate::tls::{parse_pem_certificate_blocks, tls_version_bounds};
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native",
    feature = "async-tls-rustls-no-provider"
))]
use crate::util::classify_transport_error;
use crate::util::duration_millis_ceil;

#[cfg(feature = "async-tls-rustls-ring")]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;
#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    feature = "async-tls-rustls-aws-lc-rs"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsAwsLcRs;
#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    not(feature = "async-tls-rustls-aws-lc-rs"),
    feature = "async-tls-native"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::NativeTls;
#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    not(feature = "async-tls-rustls-aws-lc-rs"),
    not(feature = "async-tls-native"),
    feature = "async-tls-rustls-no-provider"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsNoProvider;
#[cfg(not(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native",
    feature = "async-tls-rustls-no-provider"
)))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;

pub(super) fn default_tls_backend() -> TlsBackend {
    DEFAULT_TLS_BACKEND
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn add_custom_rustls_root_certificates(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
    root_store: &mut rustls::RootCertStore,
) -> crate::Result<usize> {
    use rustls::pki_types::pem::PemObject;

    let mut added_total = 0usize;
    for certificate in &tls_options.root_certificates {
        match certificate {
            TlsRootCertificate::Pem(pem) => {
                for certificate_block in
                    parse_pem_certificate_blocks(tls_backend, pem, "root certificate")?
                {
                    let certificate =
                        rustls::pki_types::CertificateDer::from_pem_slice(&certificate_block)
                            .map_err(|source| {
                                tls_config_error(
                                    tls_backend,
                                    format!("failed to parse PEM root certificate: {source}"),
                                )
                            })?;
                    root_store.add(certificate).map_err(|source| {
                        tls_config_error(
                            tls_backend,
                            format!("failed to add PEM root certificate: {source}"),
                        )
                    })?;
                    added_total = added_total.saturating_add(1);
                }
            }
            TlsRootCertificate::Der(der) => {
                root_store
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|source| {
                        tls_config_error(
                            tls_backend,
                            format!("failed to add DER root certificate: {source}"),
                        )
                    })?;
                added_total = added_total.saturating_add(1);
            }
        }
    }

    Ok(added_total)
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn build_rustls_root_store(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<rustls::RootCertStore> {
    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            tls_backend,
            "custom root CAs require tls_root_store(TlsRootStore::WebPki), tls_root_store(TlsRootStore::System), or tls_root_store(TlsRootStore::Specific)",
        ));
    }

    let mut root_store = match tls_options.root_store {
        TlsRootStore::BackendDefault | TlsRootStore::WebPki => {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        }
        TlsRootStore::System | TlsRootStore::Specific => rustls::RootCertStore::empty(),
    };

    if tls_options.root_store == TlsRootStore::Specific && tls_options.root_certificates.is_empty()
    {
        return Err(tls_config_error(
            tls_backend,
            "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
        ));
    }

    let mut system_added = 0usize;
    if tls_options.root_store == TlsRootStore::System {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            warn!(
                backend = tls_backend.as_str(),
                error_count = loaded.errors.len(),
                "system root certificate loading returned partial errors"
            );
        }
        let (added, _ignored) = root_store.add_parsable_certificates(loaded.certs);
        system_added = added;
    }

    let custom_added = if matches!(
        tls_options.root_store,
        TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
    ) && !tls_options.root_certificates.is_empty()
    {
        add_custom_rustls_root_certificates(tls_backend, tls_options, &mut root_store)?
    } else {
        0
    };

    if tls_options.root_store == TlsRootStore::System && system_added + custom_added == 0 {
        return Err(tls_config_error(
            tls_backend,
            "failed to load system root certificates",
        ));
    }

    Ok(root_store)
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
pub(crate) fn configured_rustls_protocol_versions(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let bounds = tls_version_bounds(tls_backend, tls_options)?;
    let versions = [TlsVersion::V1_3, TlsVersion::V1_2]
        .into_iter()
        .filter(|version| bounds.contains(*version))
        .collect::<Vec<_>>();

    Ok(versions
        .into_iter()
        .map(|version| match version {
            TlsVersion::V1_2 => &rustls::version::TLS12,
            TlsVersion::V1_3 => &rustls::version::TLS13,
        })
        .collect())
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
fn build_rustls_tls_config(
    tls_backend: TlsBackend,
    provider: impl Into<Arc<rustls::crypto::CryptoProvider>>,
    tls_options: &TlsOptions,
) -> crate::Result<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;

    let root_store = build_rustls_root_store(tls_backend, tls_options)?;
    let protocol_versions = configured_rustls_protocol_versions(tls_backend, tls_options)?;

    let config_builder = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&protocol_versions)
        .map_err(|source| Error::TlsBackendInit {
            backend: tls_backend.as_str(),
            message: source.to_string(),
        })?
        .with_root_certificates(root_store);

    match &tls_options.client_identity {
        None => Ok(config_builder.with_no_client_auth()),
        Some(TlsClientIdentity::Pem {
            cert_chain_pem,
            private_key_pem,
        }) => {
            let mut cert_chain = Vec::new();
            for certificate_block in
                parse_pem_certificate_blocks(tls_backend, cert_chain_pem, "mTLS certificate chain")?
            {
                let certificate = rustls::pki_types::CertificateDer::from_pem_slice(
                    &certificate_block,
                )
                .map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to parse mTLS certificate chain PEM: {source}"),
                    )
                })?;
                cert_chain.push(certificate);
            }
            let private_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(private_key_pem)
                .map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to parse mTLS private key PEM: {source}"),
                    )
                })?;
            config_builder
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to configure mTLS identity: {source}"),
                    )
                })
        }
        Some(TlsClientIdentity::Pkcs12 {
            identity_der,
            password,
        }) => Err(tls_config_error(
            tls_backend,
            format!(
                "PKCS#12 identity is unsupported for rustls backends; use PEM cert+key (pkcs12_bytes={}, password_len={})",
                identity_der.len(),
                password.len()
            ),
        )),
    }
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
type RustlsHttpsConnector = hyper_rustls::HttpsConnector<ProxyConnector>;
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-rustls-no-provider"
))]
type RustlsHyperClient = HyperClient<RustlsHttpsConnector, ReqBody>;

#[cfg(feature = "async-tls-native")]
type NativeHttpsConnector = hyper_tls::HttpsConnector<ProxyConnector>;
#[cfg(feature = "async-tls-native")]
type NativeHyperClient = HyperClient<NativeHttpsConnector, ReqBody>;

#[derive(Clone)]
pub(super) enum TransportClient {
    #[cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-rustls-no-provider"
    ))]
    Rustls(RustlsHyperClient),
    #[cfg(feature = "async-tls-native")]
    Native(NativeHyperClient),
}

impl TransportClient {
    pub(super) async fn request(
        &self,
        request: Request<ReqBody>,
    ) -> Result<HttpResponse<Incoming>, TransportRequestError> {
        #[cfg(any(
            feature = "async-tls-native",
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-rustls-no-provider"
        ))]
        {
            match self {
                #[cfg(any(
                    feature = "async-tls-rustls-ring",
                    feature = "async-tls-rustls-aws-lc-rs",
                    feature = "async-tls-rustls-no-provider"
                ))]
                Self::Rustls(client) => client
                    .request(request)
                    .await
                    .map_err(TransportRequestError::Transport),
                #[cfg(feature = "async-tls-native")]
                Self::Native(client) => client
                    .request(request)
                    .await
                    .map_err(TransportRequestError::Transport),
            }
        }
        #[cfg(not(any(
            feature = "async-tls-native",
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-rustls-no-provider"
        )))]
        {
            let _ = self;
            let _ = request;
            Err(TransportRequestError::TlsBackendUnavailable {
                backend: default_tls_backend().as_str(),
            })
        }
    }
}

pub(super) enum TransportRequestError {
    #[cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native",
        feature = "async-tls-rustls-no-provider"
    ))]
    Transport(hyper_util::client::legacy::Error),
    Timeout,
    #[cfg(not(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native",
        feature = "async-tls-rustls-no-provider"
    )))]
    TlsBackendUnavailable {
        backend: &'static str,
    },
}

impl TransportRequestError {
    pub(super) fn into_error(
        self,
        execution: &RequestExecutionState,
        transport_timeout: Duration,
    ) -> Error {
        match self {
            #[cfg(any(
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs",
                feature = "async-tls-native",
                feature = "async-tls-rustls-no-provider"
            ))]
            Self::Transport(source) => transport_error(
                classify_transport_error(&source),
                execution.current_method().clone(),
                execution.current_redacted_uri().to_owned(),
                source,
            ),
            Self::Timeout => {
                execution.transport_timeout_error(duration_millis_ceil(transport_timeout))
            }
            #[cfg(not(any(
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs",
                feature = "async-tls-native",
                feature = "async-tls-rustls-no-provider"
            )))]
            Self::TlsBackendUnavailable { backend } => Error::TlsBackendUnavailable { backend },
        }
    }
}

#[cfg(feature = "async-tls-rustls-ring")]
fn build_rustls_ring_transport(
    connector: ProxyConnector,
    tls_options: &TlsOptions,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let tls_config = build_rustls_tls_config(
        TlsBackend::RustlsRing,
        rustls::crypto::ring::default_provider(),
        tls_options,
    )?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Rustls(transport))
}

#[cfg(not(feature = "async-tls-rustls-ring"))]
fn build_rustls_ring_transport(
    _connector: ProxyConnector,
    _tls_options: &TlsOptions,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::RustlsRing.as_str(),
    })
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
fn build_rustls_aws_lc_rs_transport(
    connector: ProxyConnector,
    tls_options: &TlsOptions,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let tls_config = build_rustls_tls_config(
        TlsBackend::RustlsAwsLcRs,
        rustls::crypto::aws_lc_rs::default_provider(),
        tls_options,
    )?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Rustls(transport))
}

#[cfg(not(feature = "async-tls-rustls-aws-lc-rs"))]
fn build_rustls_aws_lc_rs_transport(
    _connector: ProxyConnector,
    _tls_options: &TlsOptions,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::RustlsAwsLcRs.as_str(),
    })
}

#[cfg(feature = "async-tls-rustls-no-provider")]
fn build_rustls_no_provider_transport(
    connector: ProxyConnector,
    tls_options: &TlsOptions,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| Error::TlsBackendInit {
            backend: TlsBackend::RustlsNoProvider.as_str(),
            message: "no rustls CryptoProvider is installed as the process-wide default; \
                install one (e.g. rustls-graviola) via \
                rustls::crypto::CryptoProvider::install_default(...) before building a client \
                with the async-tls-rustls-no-provider backend"
                .to_string(),
        })?;
    let tls_config = build_rustls_tls_config(TlsBackend::RustlsNoProvider, provider, tls_options)?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Rustls(transport))
}

#[cfg(not(feature = "async-tls-rustls-no-provider"))]
fn build_rustls_no_provider_transport(
    _connector: ProxyConnector,
    _tls_options: &TlsOptions,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::RustlsNoProvider.as_str(),
    })
}

#[cfg(feature = "async-tls-native")]
fn native_tls_protocol(version: TlsVersion) -> hyper_tls::native_tls::Protocol {
    match version {
        TlsVersion::V1_2 => hyper_tls::native_tls::Protocol::Tlsv12,
        TlsVersion::V1_3 => hyper_tls::native_tls::Protocol::Tlsv13,
    }
}

#[cfg(feature = "async-tls-native")]
fn apply_native_tls_protocol_versions(
    connector_builder: &mut hyper_tls::native_tls::TlsConnectorBuilder,
    tls_options: &TlsOptions,
) -> crate::Result<()> {
    let bounds = tls_version_bounds(TlsBackend::NativeTls, tls_options)?;
    if bounds.min.is_none() && bounds.max.is_none() {
        return Ok(());
    }

    if let Some(min) = bounds.min {
        connector_builder.min_protocol_version(Some(native_tls_protocol(min)));
    }

    if let Some(max) = bounds.max {
        connector_builder.max_protocol_version(Some(native_tls_protocol(max)));
    }

    Ok(())
}

#[cfg(feature = "async-tls-native")]
fn build_native_tls_connector(
    tls_options: &TlsOptions,
    http2_only: bool,
) -> crate::Result<hyper_tls::native_tls::TlsConnector> {
    let mut connector_builder = hyper_tls::native_tls::TlsConnector::builder();
    connector_builder.request_alpns(if http2_only {
        &["h2"]
    } else {
        &["h2", "http/1.1"]
    });

    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            TlsBackend::NativeTls,
            "custom root CAs require tls_root_store(TlsRootStore::WebPki), tls_root_store(TlsRootStore::System), or tls_root_store(TlsRootStore::Specific)",
        ));
    }

    match tls_options.root_store {
        TlsRootStore::BackendDefault | TlsRootStore::System => {
            connector_builder.disable_built_in_roots(false);
        }
        TlsRootStore::Specific => {
            if tls_options.root_certificates.is_empty() {
                return Err(tls_config_error(
                    TlsBackend::NativeTls,
                    "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
                ));
            }
            connector_builder.disable_built_in_roots(true);
        }
        TlsRootStore::WebPki => {
            return Err(tls_config_error(
                TlsBackend::NativeTls,
                "tls_root_store(TlsRootStore::WebPki) is unsupported for native-tls backend; use System or Specific",
            ));
        }
    }

    for certificate in &tls_options.root_certificates {
        match certificate {
            TlsRootCertificate::Pem(pem) => {
                let certificate_blocks =
                    parse_pem_certificate_blocks(TlsBackend::NativeTls, pem, "root certificate")?;
                for certificate_block in certificate_blocks {
                    let certificate = hyper_tls::native_tls::Certificate::from_pem(
                        &certificate_block,
                    )
                    .map_err(|source| {
                        tls_config_error(
                            TlsBackend::NativeTls,
                            format!("failed to parse PEM root certificate: {source}"),
                        )
                    })?;
                    connector_builder.add_root_certificate(certificate);
                }
            }
            TlsRootCertificate::Der(der) => {
                let certificate =
                    hyper_tls::native_tls::Certificate::from_der(der).map_err(|source| {
                        tls_config_error(
                            TlsBackend::NativeTls,
                            format!("failed to parse DER root certificate: {source}"),
                        )
                    })?;
                connector_builder.add_root_certificate(certificate);
            }
        }
    }

    if let Some(identity) = &tls_options.client_identity {
        let identity = match identity {
            TlsClientIdentity::Pem {
                cert_chain_pem,
                private_key_pem,
            } => hyper_tls::native_tls::Identity::from_pkcs8(cert_chain_pem, private_key_pem)
                .map_err(|source| {
                    tls_config_error(
                        TlsBackend::NativeTls,
                        format!("failed to parse PKCS#8 mTLS identity: {source}"),
                    )
                })?,
            TlsClientIdentity::Pkcs12 {
                identity_der,
                password,
            } => hyper_tls::native_tls::Identity::from_pkcs12(identity_der, password).map_err(
                |source| {
                    tls_config_error(
                        TlsBackend::NativeTls,
                        format!("failed to parse PKCS#12 mTLS identity: {source}"),
                    )
                },
            )?,
        };
        connector_builder.identity(identity);
    }

    apply_native_tls_protocol_versions(&mut connector_builder, tls_options)?;

    connector_builder
        .build()
        .map_err(|source| Error::TlsBackendInit {
            backend: TlsBackend::NativeTls.as_str(),
            message: source.to_string(),
        })
}

#[cfg(feature = "async-tls-native")]
fn build_native_tls_transport(
    connector: ProxyConnector,
    tls_options: &TlsOptions,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let tls_connector = build_native_tls_connector(tls_options, http2_only)?;
    let https = hyper_tls::HttpsConnector::from((connector, tls_connector.into()));
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Native(transport))
}

#[cfg(not(feature = "async-tls-native"))]
fn build_native_tls_transport(
    _connector: ProxyConnector,
    _tls_options: &TlsOptions,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::NativeTls.as_str(),
    })
}

pub(super) fn build_transport_client(
    tls_backend: TlsBackend,
    connector: ProxyConnector,
    tls_options: &TlsOptions,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    match tls_backend {
        TlsBackend::RustlsRing => build_rustls_ring_transport(
            connector,
            tls_options,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::RustlsAwsLcRs => build_rustls_aws_lc_rs_transport(
            connector,
            tls_options,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::RustlsNoProvider => build_rustls_no_provider_transport(
            connector,
            tls_options,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::NativeTls => build_native_tls_transport(
            connector,
            tls_options,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
    }
}
