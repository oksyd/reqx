use super::tls_version_bounds;

use crate::core::error::Error;
use crate::tls::{
    TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore, TlsVersion,
};

#[test]
fn tls_version_bounds_validate_range() {
    let tls_options = TlsOptions {
        min_protocol_version: Some(TlsVersion::V1_2),
        max_protocol_version: Some(TlsVersion::V1_3),
        ..TlsOptions::default()
    };
    assert_eq!(
        tls_version_bounds(TlsBackend::RustlsRing, &tls_options)
            .expect("version bounds should validate"),
        crate::tls::TlsVersionBounds {
            min: Some(TlsVersion::V1_2),
            max: Some(TlsVersion::V1_3),
        }
    );

    let invalid = TlsOptions {
        min_protocol_version: Some(TlsVersion::V1_3),
        max_protocol_version: Some(TlsVersion::V1_2),
        ..TlsOptions::default()
    };
    match tls_version_bounds(TlsBackend::RustlsRing, &invalid) {
        Ok(_) => panic!("invalid tls version bounds should fail"),
        Err(Error::TlsConfig { message, .. }) => {
            assert!(message.contains("min version"));
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn tls_options_debug_omits_key_material_and_passwords() {
    let pem_options = TlsOptions {
        root_store: TlsRootStore::Specific,
        root_certificates: vec![
            TlsRootCertificate::Pem(b"secret-root-ca-pem".to_vec()),
            TlsRootCertificate::Der(b"secret-root-ca-der".to_vec()),
        ],
        client_identity: Some(TlsClientIdentity::Pem {
            cert_chain_pem: b"secret-cert-chain".to_vec(),
            private_key_pem: b"secret-private-key".to_vec(),
        }),
        min_protocol_version: Some(TlsVersion::V1_2),
        max_protocol_version: Some(TlsVersion::V1_3),
    };
    let debug = format!("{pem_options:?}");

    assert!(debug.contains("root_certificates"));
    assert!(debug.contains("private_key_pem_len"));
    assert!(!debug.contains("secret-root-ca-pem"));
    assert!(!debug.contains("secret-root-ca-der"));
    assert!(!debug.contains("secret-cert-chain"));
    assert!(!debug.contains("secret-private-key"));

    let pkcs12_options = TlsOptions {
        client_identity: Some(TlsClientIdentity::Pkcs12 {
            identity_der: b"secret-pkcs12-identity".to_vec(),
            password: "secret-password".to_owned(),
        }),
        ..TlsOptions::default()
    };
    let debug = format!("{pkcs12_options:?}");

    assert!(debug.contains("identity_der_len"));
    assert!(debug.contains("password_len"));
    assert!(!debug.contains("secret-pkcs12-identity"));
    assert!(!debug.contains("secret-password"));
}
