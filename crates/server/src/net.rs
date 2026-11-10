use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local()),
    }
}

pub fn enforce_public_dns() -> bool {
    !std::env::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false)
        && std::env::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false)
}

pub fn filter_addrs(addrs: Vec<SocketAddr>, enforce: bool) -> Vec<SocketAddr> {
    if enforce { addrs.into_iter().filter(|a| public_ip(a.ip())).collect() } else { addrs }
}

#[derive(Debug)]
pub struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0u16).to_socket_addrs().map(|iter| iter.collect::<Vec<_>>()).unwrap_or_default()
            }).await.unwrap_or_default();
            let addrs = filter_addrs(resolved, enforce_public_dns());
            if addrs.is_empty() {
                return Err(format!("no public address for {}", name.as_str()).into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

pub fn client(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(PublicResolver))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_addresses_are_filtered_when_enforced() {
        let addrs = vec![
            "127.0.0.1:443".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        ];
        let public = filter_addrs(addrs.clone(), true);
        assert_eq!(public.len(), 1);
        assert!(public[0].ip().is_ipv4());
        assert_eq!(filter_addrs(addrs, false).len(), 3);
    }
}
