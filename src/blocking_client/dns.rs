//! ureq DNS resolution backed by immutable shared overrides.

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::core::dns::DnsOverrides;

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

pub(super) fn build_agent(config: ureq::config::Config, overrides: DnsOverrides) -> ureq::Agent {
    ureq::Agent::with_parts(
        config,
        DefaultConnector::default(),
        OverrideResolver {
            overrides,
            fallback: DefaultResolver::default(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_full_capacity_with_ipv6_and_default_ports() {
        use std::net::{Ipv6Addr, SocketAddr};
        let addresses: Vec<_> = (1..=16)
            .map(|last| SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last), 0)))
            .collect();
        let mut builder = crate::core::dns::DnsOverridesBuilder::default();
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
}
