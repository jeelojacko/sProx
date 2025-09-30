use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Time-to-live aware cache used for storing the proxy's public IP address.
///
/// The cache is intentionally backend agnostic: callers provide an asynchronous
/// fetcher when a refresh is required. This keeps the module straightforward to
/// test while still allowing integration with HTTP based discovery services.
#[derive(Debug)]
pub struct PublicIpCache {
    ttl: Duration,
    inner: Mutex<Option<CacheEntry>>,
}

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    value: IpAddr,
    fetched_at: Instant,
}

impl PublicIpCache {
    /// Creates a new cache with the provided time-to-live.
    pub fn new(ttl: Duration) -> Self {
        assert!(ttl > Duration::ZERO, "cache TTL must be greater than zero");

        Self {
            ttl,
            inner: Mutex::new(None),
        }
    }

    /// Returns the cached value if it is still fresh.
    pub async fn get(&self) -> Option<IpAddr> {
        let guard = self.inner.lock().await;
        guard.as_ref().and_then(|entry| {
            if entry.fetched_at.elapsed() <= self.ttl {
                Some(entry.value)
            } else {
                None
            }
        })
    }

    /// Retrieves the cached public IP address, refreshing it via `fetcher`
    /// when the cache has expired.
    pub async fn get_or_update<E, F, Fut>(&self, fetcher: F) -> Result<IpAddr, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<IpAddr, E>>,
    {
        if let Some(value) = self.get().await {
            return Ok(value);
        }

        let value = fetcher().await?;
        let mut guard = self.inner.lock().await;
        *guard = Some(CacheEntry {
            value,
            fetched_at: Instant::now(),
        });

        Ok(value)
    }

    /// Invalidates the cached value, forcing the next lookup to invoke the
    /// provided fetcher.
    pub async fn invalidate(&self) {
        let mut guard = self.inner.lock().await;
        guard.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn cache_returns_existing_value() {
        let cache = PublicIpCache::new(Duration::from_millis(20));
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        cache
            .get_or_update(|| async { Ok::<_, ()>(ip) })
            .await
            .unwrap();

        let cached = cache.get().await;
        assert_eq!(cached, Some(ip));
    }

    #[tokio::test]
    async fn cache_refreshes_after_ttl() {
        let cache = PublicIpCache::new(Duration::from_millis(10));
        let first: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let second: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();

        let value = cache
            .get_or_update(|| async { Ok::<_, ()>(first) })
            .await
            .unwrap();
        assert_eq!(value, first);

        sleep(Duration::from_millis(15)).await;

        let value = cache
            .get_or_update(|| async { Ok::<_, ()>(second) })
            .await
            .unwrap();
        assert_eq!(value, second);
    }

    #[tokio::test]
    async fn invalidate_clears_cache() {
        let cache = PublicIpCache::new(Duration::from_secs(1));
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 1).into();

        cache
            .get_or_update(|| async { Ok::<_, ()>(ip) })
            .await
            .unwrap();

        cache.invalidate().await;
        assert!(cache.get().await.is_none());
    }
}
