use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, MutexGuard,
};

use once_cell::sync::Lazy;

use thiserror::Error;
use tokio::net::lookup_host;
use url::Url;

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("url is missing a host")]
    MissingHost,
    #[error("unable to determine port for scheme `{scheme}`")]
    MissingPort { scheme: String },
    #[error("onion service hosts are not allowed: {host}")]
    OnionHost { host: String },
    #[error("failed to resolve host `{host}`: {source}")]
    Lookup {
        host: String,
        #[source]
        source: io::Error,
    },
    #[error("hostname `{host}` did not resolve to any addresses")]
    NoAddresses { host: String },
    #[error("resolved to disallowed ip address {ip}")]
    BlockedIp { ip: IpAddr },
}

#[cfg_attr(not(test), allow(dead_code))]
static LOOPBACK_ALLOWED: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(test), allow(dead_code))]
static LOOPBACK_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn loopback_allowed() -> bool {
    LOOPBACK_ALLOWED.load(Ordering::SeqCst)
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct LoopbackGuard {
    guard: Option<MutexGuard<'static, ()>>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn allow_loopback_for_tests() -> LoopbackGuard {
    let guard = LOOPBACK_LOCK.lock().expect("loopback guard mutex poisoned");
    LOOPBACK_ALLOWED.store(true, Ordering::SeqCst);
    LoopbackGuard { guard: Some(guard) }
}

#[cfg(test)]
pub(crate) fn lock_loopback_for_tests() -> MutexGuard<'static, ()> {
    LOOPBACK_LOCK.lock().expect("loopback guard mutex poisoned")
}

impl Drop for LoopbackGuard {
    fn drop(&mut self) {
        LOOPBACK_ALLOWED.store(false, Ordering::SeqCst);
        if let Some(guard) = self.guard.take() {
            drop(guard);
        }
    }
}

/// Returns true when the provided IP address is permitted for upstream
/// requests.
pub fn is_ip_allowed(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_ipv4_allowed(addr),
        IpAddr::V6(addr) => is_ipv6_allowed(addr),
    }
}

fn is_ipv4_allowed(addr: &Ipv4Addr) -> bool {
    if loopback_allowed() && addr.is_loopback() {
        return true;
    }

    if addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_unspecified()
        || *addr == Ipv4Addr::BROADCAST
    {
        return false;
    }

    // Carrier-grade NAT (100.64.0.0/10) and other reserved ranges should not
    // be reachable from the proxy.
    let octets = addr.octets();
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return false;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }

    true
}

fn is_ipv6_allowed(addr: &Ipv6Addr) -> bool {
    if loopback_allowed() && addr.is_loopback() {
        return true;
    }

    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }

    let segments = addr.segments();
    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80;

    if is_unique_local || is_link_local {
        return false;
    }

    // IPv4-mapped IPv6 addresses should reuse IPv4 checks.
    if let Some(mapped) = addr.to_ipv4() {
        return is_ipv4_allowed(&mapped);
    }

    // Disallow IPv6 documentation ranges (2001:db8::/32).
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    true
}

/// Resolves the provided URL to a socket address and ensures the resulting IP
/// resides in an allowed range.
pub async fn resolve_and_check(url: &Url) -> Result<SocketAddr, ResolveError> {
    let host = url
        .host_str()
        .ok_or(ResolveError::MissingHost)?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ResolveError::MissingPort {
            scheme: url.scheme().to_string(),
        })?;

    if host.ends_with(".onion") {
        return Err(ResolveError::OnionHost { host });
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_ip_allowed(&ip) {
            return Err(ResolveError::BlockedIp { ip });
        }

        return Ok(SocketAddr::new(ip, port));
    }

    let mut addrs =
        lookup_host((host.as_str(), port))
            .await
            .map_err(|source| ResolveError::Lookup {
                host: host.clone(),
                source,
            })?;

    let mut allowed = None;
    for addr in addrs.by_ref() {
        if !is_ip_allowed(&addr.ip()) {
            return Err(ResolveError::BlockedIp { ip: addr.ip() });
        }

        if allowed.is_none() {
            allowed = Some(addr);
        }
    }

    drop(addrs);

    allowed.ok_or_else(|| ResolveError::NoAddresses { host })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(addr: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    }

    fn ipv6(addr: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        ))
    }

    #[test]
    fn rejects_private_ipv4_ranges() {
        let _lock = lock_loopback_for_tests();
        let blocked = [
            ipv4([10, 0, 0, 1]),
            ipv4([172, 16, 0, 1]),
            ipv4([192, 168, 1, 1]),
            ipv4([127, 0, 0, 1]),
            ipv4([169, 254, 1, 1]),
            ipv4([224, 0, 0, 1]),
            ipv4([0, 0, 0, 0]),
            ipv4([255, 255, 255, 255]),
            ipv4([100, 64, 0, 1]),
            ipv4([192, 0, 0, 1]),
            ipv4([192, 0, 2, 1]),
            ipv4([198, 18, 0, 1]),
            ipv4([198, 51, 100, 1]),
            ipv4([203, 0, 113, 1]),
        ];

        for ip in blocked {
            assert!(!is_ip_allowed(&ip), "{ip:?} should be blocked");
        }
    }

    #[test]
    fn rejects_private_ipv6_ranges() {
        let _lock = lock_loopback_for_tests();
        let blocked = [
            ipv6([0, 0, 0, 0, 0, 0, 0, 1]),
            ipv6([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
            ipv6([0xfc00, 0, 0, 0, 0, 0, 0, 1]),
            ipv6([0xff02, 0, 0, 0, 0, 0, 0, 1]),
            ipv6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]),
        ];

        for ip in blocked {
            assert!(!is_ip_allowed(&ip), "{ip:?} should be blocked");
        }
    }

    #[test]
    fn allows_public_addresses() {
        let allowed = [
            ipv4([1, 1, 1, 1]),
            ipv4([8, 8, 8, 8]),
            ipv6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888]),
        ];

        for ip in allowed {
            assert!(is_ip_allowed(&ip), "{ip:?} should be allowed");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_blocks_ip_literals() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let error = {
            let _lock = lock_loopback_for_tests();
            resolve_and_check(&url)
        }
        .await
        .unwrap_err();
        assert!(matches!(error, ResolveError::BlockedIp { ip } if ip.is_loopback()));
    }

    #[tokio::test]
    async fn resolve_allows_public_ip_literal() {
        let url = Url::parse("http://8.8.8.8/").unwrap();
        let addr = resolve_and_check(&url).await.unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(addr.port(), 80);
    }

    #[tokio::test]
    async fn resolve_blocks_onion_hosts() {
        let url = Url::parse("http://example.onion/").unwrap();
        let error = resolve_and_check(&url).await.unwrap_err();
        assert!(matches!(
            error,
            ResolveError::OnionHost { host } if host == "example.onion"
        ));
    }
}
