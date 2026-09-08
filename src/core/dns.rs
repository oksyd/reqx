//! Validated, immutable overrides shared by both transports.
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Error;

// ureq 3.3.0 has a fixed-size resolver result. Keep the public limit identical
// across transports, and reject overflow before constructing either client.
const MAX_ADDRESSES: usize = 16;

#[derive(Default)]
pub(crate) struct DnsOverridesBuilder {
    entries: BTreeMap<String, Vec<SocketAddr>>,
    error: Option<&'static str>,
}

impl DnsOverridesBuilder {
    pub(crate) fn insert(&mut self, domain: &str, addresses: &[SocketAddr]) {
        let Some(domain) = normalize_domain(domain) else {
            self.error.get_or_insert(
                "override key must be a valid DNS hostname, not a URL or IP literal",
            );
            return;
        };
        if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
            self.error
                .get_or_insert("each DNS override must contain between 1 and 16 addresses");
            return;
        }
        let mut unique = Vec::new();
        for address in addresses {
            if !unique.contains(address) {
                unique.push(*address);
            }
        }
        self.entries.insert(domain, unique);
    }

    pub(crate) fn build(self, has_proxy: bool) -> crate::Result<DnsOverrides> {
        if let Some(message) = self.error {
            return Err(Error::InvalidDnsOverrideConfig { message });
        }
        if has_proxy && !self.entries.is_empty() {
            return Err(Error::InvalidDnsOverrideConfig {
                message: "DNS overrides cannot be combined with http_proxy, even with no_proxy rules",
            });
        }
        Ok(DnsOverrides(Arc::new(self.entries)))
    }
}

fn normalize_domain(domain: &str) -> Option<String> {
    if domain.is_empty()
        || domain.chars().any(char::is_whitespace)
        || domain.contains(['/', ':', '?', '#', '@', '\\', '%', '*', '[', ']'])
    {
        return None;
    }
    let url::Host::Domain(ascii) = url::Host::parse(domain).ok()? else {
        return None;
    };
    let normalized = ascii
        .strip_suffix('.')
        .unwrap_or(&ascii)
        .to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return None;
    }
    let valid = normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    valid.then_some(normalized)
}

#[derive(Clone, Default)]
pub(crate) struct DnsOverrides(Arc<BTreeMap<String, Vec<SocketAddr>>>);

impl std::fmt::Debug for DnsOverrides {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsOverrides")
            .field("domains", &self.0.len())
            .finish()
    }
}

impl DnsOverrides {
    fn lookup(&self, domain: &str) -> Option<&[SocketAddr]> {
        self.0.get(&normalize_domain(domain)?).map(Vec::as_slice)
    }
}

#[cfg(feature = "_async")]
mod asynchronous {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
    use tower_service::Service;

    use super::DnsOverrides;

    #[derive(Clone, Debug)]
    pub(crate) struct OverrideResolver {
        overrides: DnsOverrides,
        fallback: GaiResolver,
    }

    impl OverrideResolver {
        pub(crate) fn new(overrides: DnsOverrides) -> Self {
            Self {
                overrides,
                fallback: GaiResolver::new(),
            }
        }
    }

    impl Service<Name> for OverrideResolver {
        type Response = std::vec::IntoIter<SocketAddr>;
        type Error = io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.fallback.poll_ready(cx)
        }

        fn call(&mut self, name: Name) -> Self::Future {
            if let Some(addresses) = self.overrides.lookup(name.as_str()) {
                let addresses = addresses.to_vec();
                return Box::pin(async move { Ok(addresses.into_iter()) });
            }
            let resolving = self.fallback.call(name);
            Box::pin(async move { Ok(resolving.await?.collect::<Vec<_>>().into_iter()) })
        }
    }
}

#[cfg(feature = "_async")]
pub(crate) use asynchronous::OverrideResolver;

#[cfg(feature = "_blocking")]
mod blocking {
    use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
    use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

    use super::DnsOverrides;

    #[derive(Debug)]
    struct OverrideResolver {
        overrides: DnsOverrides,
        fallback: DefaultResolver,
    }

    impl Resolver for OverrideResolver {
        fn resolve(
            &self,
            uri: &http::Uri,
            config: &ureq::config::Config,
            timeout: NextTimeout,
        ) -> Result<ResolvedSocketAddrs, ureq::Error> {
            if let Some(addresses) = uri.host().and_then(|host| self.overrides.lookup(host)) {
                let mut resolved = self.empty();
                for mut address in addresses.iter().copied() {
                    if let Some(port) = uri.port_u16() {
                        address.set_port(port);
                    } else if address.port() == 0 {
                        address.set_port(if uri.scheme_str() == Some("https") {
                            443
                        } else {
                            80
                        });
                    }
                    // The immutable map was checked against ureq's capacity at build time.
                    resolved.push(address);
                }
                return Ok(resolved);
            }
            self.fallback.resolve(uri, config, timeout)
        }
    }

    #[test]
    fn resolves_full_capacity_with_ipv6_and_default_ports() {
        use std::net::{Ipv6Addr, SocketAddr};
        let addresses: Vec<_> = (1..=16)
            .map(|last| SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last), 0)))
            .collect();
        let mut builder = super::DnsOverridesBuilder::default();
        builder.insert("pinned.invalid", &addresses);
        let resolver = OverrideResolver {
            overrides: builder.build(false).expect("valid overrides"),
            fallback: DefaultResolver::default(),
        };
        for (url, port) in [
            ("http://pinned.invalid", 80),
            ("https://pinned.invalid", 443),
        ] {
            let resolved = resolver
                .resolve(
                    &url.parse().expect("URI"),
                    &ureq::Agent::config_builder().build(),
                    NextTimeout {
                        after: std::time::Duration::from_secs(1).into(),
                        reason: ureq::Timeout::Resolve,
                    },
                )
                .expect("override resolution");
            assert_eq!(resolved.len(), 16);
            for (actual, original) in resolved.iter().zip(&addresses) {
                assert_eq!(actual.ip(), original.ip());
                assert_eq!(actual.port(), port);
            }
        }
    }

    impl DnsOverrides {
        pub(crate) fn into_agent(self, config: ureq::config::Config) -> ureq::Agent {
            ureq::Agent::with_parts(
                config,
                DefaultConnector::default(),
                OverrideResolver {
                    overrides: self,
                    fallback: DefaultResolver::default(),
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_keys_lists_and_proxy_conflicts() {
        let address = SocketAddr::from(([127, 0, 0, 1], 8080));
        for domain in [
            "",
            "https://example.com",
            "example.com:80",
            "*.example.com",
            "127.0.0.1",
            "[::1]",
            "example..com",
            "-bad.test",
            "bad-.test",
            "a_b.test",
            " example.com",
            "example.com..",
            "%65xample.com",
        ] {
            let mut config = DnsOverridesBuilder::default();
            config.insert(domain, &[address]);
            assert!(
                matches!(
                    config.build(false),
                    Err(Error::InvalidDnsOverrideConfig { .. })
                ),
                "{domain}"
            );
        }
        for addresses in [vec![], vec![address; 17]] {
            let mut config = DnsOverridesBuilder::default();
            config.insert("example.com", &addresses);
            assert!(config.build(false).is_err());
        }
        let mut config = DnsOverridesBuilder::default();
        config.insert("example.com", &[address]);
        assert!(config.build(true).is_err());
    }

    #[test]
    fn normalizes_replaces_and_matches_only_exact_names() {
        let first = SocketAddr::from(([127, 0, 0, 1], 1));
        let second = SocketAddr::from(([127, 0, 0, 1], 2));
        let mut config = DnsOverridesBuilder::default();
        config.insert("EXAMPLE.COM.", &[first]);
        config.insert("example.com", &[second, second]);
        config.insert("bücher.example", &[first]);
        let overrides = config.build(false).expect("overrides");
        assert_eq!(overrides.lookup("EXAMPLE.COM."), Some([second].as_slice()));
        assert_eq!(
            overrides.lookup("xn--bcher-kva.example"),
            Some([first].as_slice())
        );
        assert!(overrides.lookup("sub.example.com").is_none());
        assert!(overrides.lookup("otherexample.com").is_none());
    }

    #[cfg(feature = "_async")]
    #[test]
    fn async_override_resolution_does_not_start_system_dns() {
        use std::task::{Context, Poll, Waker};
        use tower_service::Service;
        let address = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 1234));
        let mut config = DnsOverridesBuilder::default();
        config.insert("nonexistent.invalid", &[address]);
        let mut resolver = OverrideResolver::new(config.build(false).expect("overrides"));
        // GaiResolver needs a Tokio runtime even to start resolving. This test
        // deliberately has none: a matching override must never delegate to it.
        let mut resolving = resolver.call("nonexistent.invalid".parse().expect("name"));
        let mut context = Context::from_waker(Waker::noop());
        match resolving.as_mut().poll(&mut context) {
            Poll::Ready(Ok(addresses)) => assert_eq!(addresses.collect::<Vec<_>>(), vec![address]),
            _ => panic!("an override must resolve immediately without DNS"),
        }
    }
}
