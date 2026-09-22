//! Hyper DNS resolution backed by immutable shared overrides.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use tower_service::Service;

use crate::core::dns::DnsOverrides;

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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::OverrideResolver;
    use crate::core::dns::DnsOverridesBuilder;

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
