use url::Url;

/// Classification type for incoming `d=` URLs handled by the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Torrentio resolver endpoint.
    TorrentioResolve,
    /// Generic proxy-style playback endpoints hosted by community mirrors.
    ProxyPlayback,
    /// AIOS nightly encrypted playback endpoints.
    AiosDebrid,
    /// EasyDebrid direct download endpoints.
    EasyDebridDirect,
    /// Fallback classification when no explicit mapping exists.
    Generic,
}

/// Provider hint derived from a classified URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// RealDebrid style host.
    RealDebrid,
    /// EasyDebrid style host.
    EasyDebrid,
    /// Provider could not be determined.
    Unknown,
}

/// Result of classifying a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub class: Class,
    pub provider: Provider,
}

/// Classify a URL into a [`Class`] and [`Provider`] hint combination.
///
/// The mapping is intentionally conservative and only recognizes the specific
/// hosts used in production traffic today. Any unknown host falls back to the
/// [`Class::Generic`] / [`Provider::Unknown`] combination to ensure the proxy
/// never panics on unexpected input.
pub fn classify_url(url: &Url) -> Classification {
    let host = url.host_str().map(str::to_ascii_lowercase);
    let host = match host {
        Some(host) => host,
        None => {
            return Classification {
                class: Class::Generic,
                provider: Provider::Unknown,
            }
        }
    };

    let path = url.path();

    if is_torrentio_resolve(&host, path) {
        return Classification {
            class: Class::TorrentioResolve,
            provider: Provider::Unknown,
        };
    }

    if is_proxy_playback(&host) {
        return Classification {
            class: Class::ProxyPlayback,
            provider: Provider::RealDebrid,
        };
    }

    if host.contains("aios-nightly") {
        return Classification {
            class: Class::AiosDebrid,
            provider: Provider::RealDebrid,
        };
    }

    if host.contains("torrentsdb") {
        return Classification {
            class: Class::EasyDebridDirect,
            provider: Provider::EasyDebrid,
        };
    }

    if is_real_debrid_host(&host) {
        return Classification {
            class: Class::Generic,
            provider: Provider::RealDebrid,
        };
    }

    if is_easydebrid_host(&host) {
        return Classification {
            class: Class::Generic,
            provider: Provider::EasyDebrid,
        };
    }

    Classification {
        class: Class::Generic,
        provider: Provider::Unknown,
    }
}

fn is_torrentio_resolve(host: &str, path: &str) -> bool {
    host.ends_with("torrentio.strem.fun") && path.starts_with("/resolve")
}

fn is_proxy_playback(host: &str) -> bool {
    const PROXY_HOST_FRAGMENTS: [&str; 4] = ["stremthru", "comet", "mediafusion", "elfhosted"];
    PROXY_HOST_FRAGMENTS
        .iter()
        .any(|fragment| host.contains(fragment))
}

fn is_real_debrid_host(host: &str) -> bool {
    host.contains("real-debrid") || host.contains("realdebrid")
}

fn is_easydebrid_host(host: &str) -> bool {
    host.contains("easydebrid") || host.contains("easy-debrid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(input: &str) -> Url {
        Url::parse(input).expect("test urls should be valid")
    }

    #[test]
    fn torrentio_resolve_is_classified() {
        let classification = classify_url(&url("https://torrentio.strem.fun/resolve?d=abc"));
        assert_eq!(classification.class, Class::TorrentioResolve);
        assert_eq!(classification.provider, Provider::Unknown);
    }

    #[test]
    fn proxy_playback_variants_are_detected() {
        for host in [
            "https://stremthru.com/play?d=abc",
            "https://comet.proxy.example/redirect?d=abc",
            "https://mediafusion.elfhosted.com/hls?d=abc",
        ] {
            let classification = classify_url(&url(host));
            assert_eq!(
                classification.class,
                Class::ProxyPlayback,
                "host {host} should be proxy playback"
            );
            assert_eq!(classification.provider, Provider::RealDebrid);
        }
    }

    #[test]
    fn aios_nightly_is_detected() {
        let classification = classify_url(&url("https://aios-nightly.strem.fun/play?d=abc"));
        assert_eq!(classification.class, Class::AiosDebrid);
        assert_eq!(classification.provider, Provider::RealDebrid);
    }

    #[test]
    fn torrentsdb_easydebrid_is_detected() {
        let classification = classify_url(&url("https://torrentsdb.com/download?d=abc"));
        assert_eq!(classification.class, Class::EasyDebridDirect);
        assert_eq!(classification.provider, Provider::EasyDebrid);
    }

    #[test]
    fn real_debrid_hosts_are_detected() {
        let classification = classify_url(&url("https://real-debrid.com/d/abc"));
        assert_eq!(classification.class, Class::Generic);
        assert_eq!(classification.provider, Provider::RealDebrid);
    }

    #[test]
    fn easydebrid_hosts_are_detected() {
        let classification = classify_url(&url("https://app.easydebrid.com/d/abc"));
        assert_eq!(classification.class, Class::Generic);
        assert_eq!(classification.provider, Provider::EasyDebrid);
    }

    #[test]
    fn unknown_hosts_fallback_to_generic() {
        let classification = classify_url(&url("https://unknown.example/d=abc"));
        assert_eq!(classification.class, Class::Generic);
        assert_eq!(classification.provider, Provider::Unknown);
    }
}
