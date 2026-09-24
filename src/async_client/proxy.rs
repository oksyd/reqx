//! Hyper connections for direct requests and HTTP proxy tunnels.
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper_util::client::legacy::connect::proxy::Tunnel;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use tower_service::Service;

use crate::core::dns::DnsOverrides;
use crate::core::proxy::{NoProxyRule, ProxyConfig, should_bypass_proxy_uri};

use super::dns::OverrideResolver;

pub(crate) type BoxConnectError = Box<dyn StdError + Send + Sync>;

#[derive(Clone)]
struct ProxyRuntime {
    tunnel: Tunnel<HttpConnector<OverrideResolver>>,
    proxy_uri: Uri,
    no_proxy_rules: Vec<NoProxyRule>,
}

impl ProxyRuntime {
    fn should_bypass_proxy(&self, uri: &Uri) -> bool {
        should_bypass_proxy_uri(&self.no_proxy_rules, uri)
    }
}

#[derive(Debug)]
pub(crate) struct ProxyConnection<T> {
    inner: T,
    proxied: bool,
}

impl<T> ProxyConnection<T> {
    fn new(inner: T, proxied: bool) -> Self {
        Self { inner, proxied }
    }
}

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

impl<T> Connection for ProxyConnection<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        self.inner.connected().proxy(self.proxied)
    }
}

#[derive(Clone)]
pub(crate) struct ProxyConnector {
    direct: HttpConnector<OverrideResolver>,
    proxy: Option<ProxyRuntime>,
}

impl ProxyConnector {
    pub(crate) fn new(
        proxy_config: Option<ProxyConfig>,
        connect_timeout: Duration,
        overrides: DnsOverrides,
    ) -> Self {
        let mut direct = HttpConnector::new_with_resolver(OverrideResolver::new(overrides));
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

impl Service<Uri> for ProxyConnector {
    type Response = ProxyConnection<<HttpConnector<OverrideResolver> as Service<Uri>>::Response>;
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
mod contract_tests;
