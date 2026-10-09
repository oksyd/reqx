//! Validated, immutable overrides shared by both transports.
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::core::error::Error;

// ureq has a fixed-size resolver result. Keep the public limit identical
// across transports, and reject overflow before constructing either client.
const MAX_ADDRESSES: usize = 16;

#[derive(Default)]
pub(crate) struct DnsOverridesBuilder {
    entries: BTreeMap<String, Vec<SocketAddr>>,
}

impl DnsOverridesBuilder {
    pub(crate) fn insert(&mut self, domain: &str, addresses: &[SocketAddr]) -> crate::Result<()> {
        let domain = normalize_domain(domain).ok_or(Error::InvalidDnsOverrideConfig {
            message: "override key must be a valid DNS hostname, not a URL or IP literal",
        })?;
        if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
            return Err(Error::InvalidDnsOverrideConfig {
                message: "each DNS override must contain between 1 and 16 addresses",
            });
        }
        let mut unique = Vec::with_capacity(addresses.len());
        for address in addresses {
            if !unique.contains(address) {
                unique.push(*address);
            }
        }
        self.entries.insert(domain, unique);
        Ok(())
    }

    pub(crate) fn build(self, has_proxy: bool) -> crate::Result<DnsOverrides> {
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
    pub(crate) fn lookup(&self, domain: &str) -> Option<&[SocketAddr]> {
        self.0.get(&normalize_domain(domain)?).map(Vec::as_slice)
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
            assert!(
                matches!(
                    config.insert(domain, &[address]),
                    Err(Error::InvalidDnsOverrideConfig { .. })
                ),
                "{domain}"
            );
        }
        for addresses in [vec![], vec![address; 17]] {
            let mut config = DnsOverridesBuilder::default();
            assert!(config.insert("example.com", &addresses).is_err());
        }
        let mut config = DnsOverridesBuilder::default();
        config
            .insert("example.com", &[address])
            .expect("valid override");
        assert!(config.build(true).is_err());
    }

    #[test]
    fn normalizes_replaces_and_matches_only_exact_names() {
        let first = SocketAddr::from(([127, 0, 0, 1], 1));
        let second = SocketAddr::from(([127, 0, 0, 1], 2));
        let mut config = DnsOverridesBuilder::default();
        config
            .insert("EXAMPLE.COM.", &[first])
            .expect("valid override");
        config
            .insert("example.com", &[second, second])
            .expect("valid override");
        config
            .insert("bücher.example", &[first])
            .expect("valid override");
        let overrides = config.build(false).expect("overrides");
        assert_eq!(overrides.lookup("EXAMPLE.COM."), Some([second].as_slice()));
        assert_eq!(
            overrides.lookup("xn--bcher-kva.example"),
            Some([first].as_slice())
        );
        assert!(overrides.lookup("sub.example.com").is_none());
        assert!(overrides.lookup("otherexample.com").is_none());
    }
}
