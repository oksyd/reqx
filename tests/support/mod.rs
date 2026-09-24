// Shared setup for tests that require a working default client.
// Missing-provider behavior is tested in a separate integration test process.
#[allow(dead_code)]
pub fn install_crypto_provider() {
    #[cfg(any(
        feature = "async-tls-rustls-no-provider",
        feature = "blocking-tls-rustls-no-provider"
    ))]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            rustls_graviola::default_provider()
                .install_default()
                .expect("install test crypto provider before building clients");
        });
    }
}
