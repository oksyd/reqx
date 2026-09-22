#![cfg_attr(
    all(
        feature = "_async",
        not(feature = "async-tls-native"),
        not(feature = "async-tls-rustls-ring"),
        not(feature = "async-tls-rustls-aws-lc-rs"),
        not(feature = "async-tls-rustls-no-provider")
    ),
    allow(dead_code)
)]

#[cfg(feature = "_async")]
use std::error::Error as StdError;
#[cfg(feature = "_async")]
use std::future::Future;
use std::net::IpAddr;
#[cfg(feature = "_async")]
use std::pin::Pin;
#[cfg(feature = "_async")]
use std::task::{Context, Poll};
#[cfg(feature = "_async")]
use std::time::Duration;

use http::Uri;
use http::header::HeaderValue;
#[cfg(feature = "_async")]
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
#[cfg(feature = "_async")]
use hyper_util::client::legacy::connect::proxy::Tunnel;
#[cfg(feature = "_async")]
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
#[cfg(feature = "_async")]
use tower_service::Service;
use url::Url;

use crate::error::Error;
use crate::util::{
    default_port, is_valid_absolute_http_uri_text, normalize_host_key,
    redact_uri_without_url_normalization,
};

#[cfg(feature = "_async")]
pub(crate) type BoxConnectError = Box<dyn StdError + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ProxyConfig {
    pub(crate) uri: Uri,
    pub(crate) authorization: Option<HeaderValue>,
    pub(crate) no_proxy_rules: Vec<NoProxyRule>,
}

#[derive(Clone, Debug)]
pub(crate) enum NoProxyRule {
    Any,
    Cidr(ipnet::IpNet),
    Domain { host: String, port: Option<u16> },
}

fn normalize_no_proxy_host(host: &str) -> Option<String> {
    let normalized = normalize_host_key(host)?;
    if let Some(unbracketed) = normalized
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        && unbracketed.parse::<IpAddr>().is_ok()
    {
        return Some(unbracketed.to_owned());
    }
    Some(normalized)
}

fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return inner.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    host.parse().ok()
}

fn plain_no_proxy_host_is_valid(host: &str) -> bool {
    if host.is_empty()
        || host.contains(['/', '?', '#', '@', '\\', '*'])
        || host.chars().any(char::is_whitespace)
    {
        return false;
    }
    if host.contains(':') {
        return host.parse::<IpAddr>().is_ok();
    }
    true
}

fn host_matches_no_proxy_rule(host: &str, rule_host: &str) -> bool {
    let host_ip = parse_ip_literal(host);
    let rule_ip = parse_ip_literal(rule_host);
    if host_ip.is_some() || rule_ip.is_some() {
        return host_ip.is_some() && host_ip == rule_ip;
    }

    host == rule_host
        || host
            .strip_suffix(rule_host)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

impl NoProxyRule {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        fn looks_like_url_rule(value: &str) -> bool {
            let bytes = value.as_bytes();
            value.contains("://")
                || bytes
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http:"))
                || bytes
                    .get(..6)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https:"))
        }

        let mut candidate = text.trim().to_owned();
        let mut port = None;
        if candidate.is_empty() {
            return None;
        }
        if candidate == "*" {
            return Some(Self::Any);
        }
        if let Ok(url) = Url::parse(&candidate)
            && let Some(host) = url.host_str()
        {
            if !matches!(url.scheme(), "http" | "https")
                || !is_valid_absolute_http_uri_text(&candidate)
            {
                return None;
            }
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return None;
            }
            let host = host
                .strip_prefix("*.")
                .unwrap_or_else(|| host.trim_start_matches('.'));
            let host = normalize_no_proxy_host(host)?;
            if !plain_no_proxy_host_is_valid(&host) {
                return None;
            }
            return Some(Self::Domain {
                host,
                port: url.port_or_known_default(),
            });
        } else if looks_like_url_rule(&candidate) {
            return None;
        }
        // URL rules above retain their existing path and port validation.
        // A slash in any other rule unambiguously denotes CIDR: never fall back.
        if candidate.contains('/') {
            return candidate
                .parse::<ipnet::IpNet>()
                .ok()
                .map(|net| Self::Cidr(net.trunc()));
        }
        candidate = if let Some(host) = candidate.strip_prefix("*.") {
            host.to_owned()
        } else {
            candidate.trim_start_matches('.').to_owned()
        };
        if candidate.is_empty() {
            return None;
        }
        if let Some(stripped) = candidate.strip_prefix('[') {
            let end = stripped.find(']')?;
            let host = &stripped[..end];
            if host.parse::<IpAddr>().is_err() {
                return None;
            }
            let suffix = &stripped[end + 1..];
            if suffix.is_empty() {
                port = None;
            } else {
                let raw_port = suffix.strip_prefix(':')?;
                port = Some(raw_port.parse::<u16>().ok()?);
            }
            candidate = host.to_owned();
        } else if candidate.matches(':').count() == 1 {
            let (host, raw_port) = candidate.rsplit_once(':')?;
            if host.is_empty() {
                return None;
            }
            port = Some(raw_port.parse::<u16>().ok()?);
            candidate = host.to_owned();
        }
        if !plain_no_proxy_host_is_valid(&candidate) {
            return None;
        }
        Some(Self::Domain {
            host: normalize_no_proxy_host(&candidate)?,
            port,
        })
    }

    pub(crate) fn matches(&self, host: &str, port: Option<u16>) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr(network) => parse_ip_literal(host).is_some_and(|ip| network.contains(&ip)),
            Self::Domain {
                host: domain,
                port: rule_port,
            } => {
                let Some(host) = normalize_no_proxy_host(host) else {
                    return false;
                };
                let host_matches = host_matches_no_proxy_rule(&host, domain);
                if !host_matches {
                    return false;
                }

                match rule_port {
                    Some(rule_port) => port == Some(*rule_port),
                    None => true,
                }
            }
        }
    }
}

pub(crate) fn redact_no_proxy_rule_for_logs(rule: &str) -> String {
    redact_uri_without_url_normalization(rule.trim())
}

pub(crate) fn should_bypass_proxy_uri(no_proxy_rules: &[NoProxyRule], uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let port = uri.port_u16().or_else(|| default_port(uri));
    no_proxy_rules.iter().any(|rule| rule.matches(host, port))
}

pub(crate) fn parse_no_proxy_rule(rule: &str) -> crate::Result<NoProxyRule> {
    NoProxyRule::parse(rule).ok_or_else(|| Error::InvalidNoProxyRule {
        rule: redact_no_proxy_rule_for_logs(rule),
    })
}

pub(crate) fn parse_no_proxy_rules<I, S>(rules: I) -> crate::Result<Vec<NoProxyRule>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    rules
        .into_iter()
        .map(|rule| parse_no_proxy_rule(rule.as_ref()))
        .collect()
}

#[derive(Clone)]
#[cfg(feature = "_async")]
struct ProxyRuntime {
    tunnel: Tunnel<HttpConnector<crate::core::dns::OverrideResolver>>,
    proxy_uri: Uri,
    no_proxy_rules: Vec<NoProxyRule>,
}

#[cfg(feature = "_async")]
impl ProxyRuntime {
    fn should_bypass_proxy(&self, uri: &Uri) -> bool {
        should_bypass_proxy_uri(&self.no_proxy_rules, uri)
    }
}

#[cfg(feature = "_async")]
#[derive(Debug)]
pub(crate) struct ProxyConnection<T> {
    inner: T,
    proxied: bool,
}

#[cfg(feature = "_async")]
impl<T> ProxyConnection<T> {
    fn new(inner: T, proxied: bool) -> Self {
        Self { inner, proxied }
    }
}

#[cfg(feature = "_async")]
impl<T> HyperRead for ProxyConnection<T>
where
    T: HyperRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "_async")]
impl<T> HyperWrite for ProxyConnection<T>
where
    T: HyperWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_write_vectored(cx, bufs)
    }
}

#[cfg(feature = "_async")]
impl<T> Connection for ProxyConnection<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        self.inner.connected().proxy(self.proxied)
    }
}

#[derive(Clone)]
#[cfg(feature = "_async")]
pub(crate) struct ProxyConnector {
    direct: HttpConnector<crate::core::dns::OverrideResolver>,
    proxy: Option<ProxyRuntime>,
}

#[cfg(feature = "_async")]
impl ProxyConnector {
    pub(crate) fn new(
        proxy_config: Option<ProxyConfig>,
        connect_timeout: Duration,
        overrides: crate::core::dns::DnsOverrides,
    ) -> Self {
        let mut direct =
            HttpConnector::new_with_resolver(crate::core::dns::OverrideResolver::new(overrides));
        direct.enforce_http(false);
        direct.set_connect_timeout(Some(connect_timeout));
        let proxy = proxy_config.map(|config| {
            let mut tunnel = Tunnel::new(config.uri.clone(), direct.clone());
            if let Some(authorization) = config.authorization {
                tunnel = tunnel.with_auth(authorization);
            }
            ProxyRuntime {
                tunnel,
                proxy_uri: config.uri,
                no_proxy_rules: config.no_proxy_rules,
            }
        });
        Self { direct, proxy }
    }
}

#[cfg(feature = "_async")]
impl Service<Uri> for ProxyConnector {
    type Response = ProxyConnection<
        <HttpConnector<crate::core::dns::OverrideResolver> as Service<Uri>>::Response,
    >;
    type Error = BoxConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(proxy) = &mut self.proxy {
            let direct_ready = match self.direct.poll_ready(cx) {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => false,
            };
            let tunnel_ready = match proxy.tunnel.poll_ready(cx) {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => false,
            };
            return if direct_ready && tunnel_ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }

        match self.direct.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        if let Some(proxy) = &mut self.proxy {
            if proxy.should_bypass_proxy(&dst) {
                let connecting = self.direct.call(dst);
                return Box::pin(async move {
                    connecting
                        .await
                        .map(|connection| ProxyConnection::new(connection, false))
                        .map_err(|error| Box::new(error) as _)
                });
            }
            let scheme = dst.scheme_str().unwrap_or_default();
            if scheme.eq_ignore_ascii_case("https") {
                let tunnel_target = normalize_tunnel_target_uri(dst);
                let connecting = proxy.tunnel.call(tunnel_target);
                return Box::pin(async move {
                    connecting
                        .await
                        .map(|connection| ProxyConnection::new(connection, false))
                        .map_err(|error| Box::new(error) as _)
                });
            }
            let connecting = self.direct.call(proxy.proxy_uri.clone());
            return Box::pin(async move {
                connecting
                    .await
                    .map(|connection| ProxyConnection::new(connection, true))
                    .map_err(|error| Box::new(error) as _)
            });
        }

        let connecting = self.direct.call(dst);
        Box::pin(async move {
            connecting
                .await
                .map(|connection| ProxyConnection::new(connection, false))
                .map_err(|error| Box::new(error) as _)
        })
    }
}

#[cfg(feature = "_async")]
pub(crate) fn normalize_tunnel_target_uri(dst: Uri) -> Uri {
    if dst.port().is_some() {
        return dst;
    }

    let Some(scheme) = dst.scheme_str() else {
        return dst;
    };
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        return dst;
    };
    let Some(host) = dst.host() else {
        return dst;
    };
    let authority_text = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{default_port}")
    } else {
        format!("{host}:{default_port}")
    };

    let Ok(authority) = authority_text.parse() else {
        return dst;
    };
    let original = dst.clone();
    let mut parts = dst.into_parts();
    parts.authority = Some(authority);
    Uri::from_parts(parts).unwrap_or(original)
}

#[cfg(test)]
mod rule_tests {
    use super::{NoProxyRule, should_bypass_proxy_uri};

    #[test]
    fn cidr_rules_match_only_literal_ips_in_the_same_family() {
        for (rule, matches, misses) in [
            (
                "192.168.88.42/24",
                vec!["192.168.88.0", "192.168.88.255"],
                vec!["192.168.87.255", "192.168.89.0"],
            ),
            (
                "127.0.0.0/8",
                vec!["127.0.0.1", "127.255.255.255"],
                vec!["126.255.255.255", "128.0.0.0"],
            ),
            (
                "0.0.0.0/0",
                vec!["0.0.0.0", "255.255.255.255"],
                vec!["::1", "::ffff:127.0.0.1"],
            ),
            (
                "127.0.0.1/32",
                vec!["127.0.0.1"],
                vec!["127.0.0.0", "127.0.0.2"],
            ),
            (
                "::/0",
                vec!["::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
                vec!["127.0.0.1"],
            ),
            ("::1/128", vec!["::1", "[::1]"], vec!["::", "::2"]),
            (
                "2001:db8::1234/32",
                vec!["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"],
                vec!["2001:db7::", "2001:db9::"],
            ),
        ] {
            let parsed = NoProxyRule::parse(rule).expect("CIDR");
            for host in matches {
                for port in [None, Some(80), Some(443), Some(8080)] {
                    assert!(parsed.matches(host, port), "{rule}: {host}:{port:?}");
                }
            }
            for host in misses.into_iter().chain(["localhost", "example.com"]) {
                assert!(!parsed.matches(host, Some(80)), "{rule}: {host}");
            }
        }
        let NoProxyRule::Cidr(net) = NoProxyRule::parse(" 192.168.88.42/24 ").expect("CIDR") else {
            panic!("expected CIDR");
        };
        assert_eq!(net.to_string(), "192.168.88.0/24");
    }

    #[test]
    fn cidr_rules_reject_invalid_or_ambiguous_syntax() {
        for text in [
            "1.2.3.4/33",
            "::/129",
            "1.2.3.4/-1",
            "::/+1",
            "1.2.3.4/",
            "1.2.3.4/999",
            "1.2.3.4/24/8",
            "999.0.0.1/8",
            "example.com/24",
            "*.example.com/24",
            "1.2.3.4/24:80",
            "[::1]/128",
            "[::1]:80/128",
            "fe80::1%eth0/64",
            "http://1.2.3.4/24",
            "https://[::1]/128",
            "1.2.3.4/ 24",
        ] {
            assert!(NoProxyRule::parse(text).is_none(), "{text}");
        }
    }

    #[test]
    fn cidr_rules_mix_with_existing_rules_without_changing_their_semantics() {
        let rules = super::parse_no_proxy_rules([
            "192.168.88.0/24",
            "::1/128",
            "*.example.com:443",
            "localhost",
        ])
        .expect("rules");
        for uri in [
            "http://192.168.88.23:8080/",
            "http://[::1]/",
            "https://example.com/",
            "https://sub.example.com/",
            "http://localhost/",
        ] {
            assert!(
                should_bypass_proxy_uri(&rules, &uri.parse().expect("URI")),
                "{uri}"
            );
        }
        for uri in [
            "http://192.168.89.23/",
            "http://[::2]/",
            "http://sub.example.com/",
            "http://other.invalid/",
        ] {
            assert!(
                !should_bypass_proxy_uri(&rules, &uri.parse().expect("URI")),
                "{uri}"
            );
        }
    }

    #[test]
    fn no_proxy_url_rules_preserve_domain_suffix_matching() {
        for text in ["http://example.com:8080", "http://*.example.com:8080"] {
            let rule = NoProxyRule::parse(text).expect("domain URL rule");
            assert!(rule.matches("example.com", Some(8080)), "{text}");
            assert!(rule.matches("api.example.com", Some(8080)), "{text}");
            assert!(!rule.matches("example.com", Some(9090)), "{text}");
            assert!(!rule.matches("otherexample.com", Some(8080)), "{text}");
        }
        for text in [
            "http://*",
            "http://api.*.example.com",
            "http://**.example.com",
        ] {
            assert!(NoProxyRule::parse(text).is_none(), "{text}");
        }
    }

    #[test]
    fn ipv6_url_rules_preserve_explicit_and_default_ports() {
        for (text, port) in [
            ("http://[::1]:8080", 8080),
            ("http://[::1]", 80),
            ("https://[::1]", 443),
            ("[::1]:8080", 8080),
        ] {
            let rules = [NoProxyRule::parse(text).expect("valid rule")];
            let matching = format!("http://[::1]:{port}/").parse().expect("URI");
            assert!(should_bypass_proxy_uri(&rules, &matching), "{text}");
            let other = "http://[::1]:9090/".parse().expect("URI");
            assert!(!should_bypass_proxy_uri(&rules, &other), "{text}");
        }
        let rule = NoProxyRule::parse("[::1]").expect("bare IPv6 rule");
        assert!(rule.matches("[::1]", Some(8080)));
        assert!(rule.matches("[::1]", Some(9090)));
    }
}
