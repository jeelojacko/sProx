use std::path::{Path, PathBuf};
use std::time::Duration;

use config as config_rs;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct Config {
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub id: String,
    pub listen: ListenerConfig,
    pub upstream: UpstreamConfig,
    pub hls: Option<HlsConfig>,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub origin: Url,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub tls: TlsConfig,
    pub socks5: Socks5Config,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub sni_hostname: Option<String>,
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub enabled: bool,
    pub address: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HlsConfig {
    pub enabled: bool,
    pub rewrite_playlist_urls: bool,
    pub base_url: Option<Url>,
    pub allow_insecure_segments: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration file not found at {path:?}")]
    NotFound { path: PathBuf },

    #[error("failed to load configuration from {path:?}: {source}")]
    Load {
        path: PathBuf,
        #[source]
        source: config_rs::ConfigError,
    },

    #[error("configuration validation error at {context}: {message}")]
    Validation { context: String, message: String },
}

impl Config {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let settings = config_rs::Config::builder()
            .add_source(config_rs::File::from(path))
            .build()
            .map_err(|source| map_config_error(path, source))?;

        let raw: RawConfig = settings
            .try_deserialize()
            .map_err(|source| map_config_error(path, source))?;

        raw.try_into()
    }
}

fn map_config_error(path: &Path, error: config_rs::ConfigError) -> ConfigError {
    match error {
        config_rs::ConfigError::NotFound(_) => ConfigError::NotFound {
            path: path.to_path_buf(),
        },
        other => ConfigError::Load {
            path: path.to_path_buf(),
            source: other,
        },
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    routes: Vec<RawRoute>,
}

#[derive(Debug, Deserialize)]
struct RawRoute {
    id: String,
    listen: RawListener,
    upstream: RawUpstream,
    #[serde(default)]
    hls: Option<RawHls>,
}

#[derive(Debug, Deserialize)]
struct RawListener {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct RawUpstream {
    origin: String,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    #[serde(default)]
    tls: RawTls,
    #[serde(default)]
    socks5: RawSocks5,
}

#[derive(Debug, Deserialize, Default)]
struct RawTls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    sni_hostname: Option<String>,
    #[serde(default)]
    insecure_skip_verify: bool,
}

#[derive(Debug, Deserialize, Default)]
struct RawSocks5 {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

// Default is derived above.

#[derive(Debug, Deserialize)]
struct RawHls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    rewrite_playlist_urls: bool,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    allow_insecure_segments: bool,
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        if raw.routes.is_empty() {
            return Err(validation_error(
                "routes",
                "at least one route must be defined",
            ));
        }

        let mut routes = Vec::with_capacity(raw.routes.len());
        for (idx, route) in raw.routes.into_iter().enumerate() {
            let context = format!("routes[{idx}]");
            routes.push(route.try_into_context(context)?);
        }

        Ok(Self { routes })
    }
}

impl RawRoute {
    fn try_into_context(self, context: String) -> Result<RouteConfig, ConfigError> {
        if self.id.trim().is_empty() {
            return Err(validation_error(
                format!("{context}.id"),
                "route id must not be empty",
            ));
        }

        let listen = parse_listener(self.listen, &context)?;
        let upstream = parse_upstream(self.upstream, &context)?;
        let hls = match self.hls {
            Some(hls) => Some(parse_hls(hls, &context)?),
            None => None,
        };

        Ok(RouteConfig {
            id: self.id,
            listen,
            upstream,
            hls,
        })
    }
}

fn parse_listener(raw: RawListener, context: &str) -> Result<ListenerConfig, ConfigError> {
    if raw.host.trim().is_empty() {
        return Err(validation_error(
            format!("{context}.listen.host"),
            "host must not be empty",
        ));
    }

    if raw.port == 0 {
        return Err(validation_error(
            format!("{context}.listen.port"),
            "port must be greater than zero",
        ));
    }

    Ok(ListenerConfig {
        host: raw.host,
        port: raw.port,
    })
}

fn parse_upstream(raw: RawUpstream, context: &str) -> Result<UpstreamConfig, ConfigError> {
    let origin = Url::parse(&raw.origin).map_err(|err| {
        validation_error(
            format!("{context}.upstream.origin"),
            format!("invalid URL: {err}"),
        )
    })?;

    let connect_timeout = duration_from_millis(
        raw.connect_timeout_ms,
        format!("{context}.upstream.connect_timeout_ms"),
    )?;
    let read_timeout = duration_from_millis(
        raw.read_timeout_ms,
        format!("{context}.upstream.read_timeout_ms"),
    )?;

    let tls_context = format!("{context}.upstream.tls");
    let tls = parse_tls(raw.tls, &tls_context);
    let socks5 = parse_socks5(raw.socks5, context)?;

    Ok(UpstreamConfig {
        origin,
        connect_timeout,
        read_timeout,
        tls,
        socks5,
    })
}

fn parse_tls(raw: RawTls, context: &str) -> TlsConfig {
    let sni_hostname = raw
        .sni_hostname
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    if raw.enabled && raw.insecure_skip_verify {
        #[cfg(feature = "telemetry")]
        tracing::warn!(
            context = %context,
            "TLS insecure_skip_verify is enabled; upstream certificates will not be validated.",
        );
    }

    TlsConfig {
        enabled: raw.enabled,
        sni_hostname,
        insecure_skip_verify: raw.insecure_skip_verify,
    }
}

fn parse_socks5(raw: RawSocks5, context: &str) -> Result<Socks5Config, ConfigError> {
    let address = raw
        .address
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    if raw.enabled && address.is_none() {
        return Err(validation_error(
            format!("{context}.upstream.socks5.address"),
            "address must be set when SOCKS5 is enabled",
        ));
    }

    let username = raw
        .username
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let password = raw
        .password
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    Ok(Socks5Config {
        enabled: raw.enabled,
        address,
        username,
        password,
    })
}

fn parse_hls(raw: RawHls, context: &str) -> Result<HlsConfig, ConfigError> {
    let base_context = format!("{context}.hls.base_url");
    let base_url =
        match raw.base_url {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(validation_error(
                        &base_context,
                        "base_url must not be empty when set",
                    ));
                }

                Some(Url::parse(trimmed).map_err(|err| {
                    validation_error(&base_context, format!("invalid URL: {err}"))
                })?)
            }
            None => None,
        };

    if raw.enabled && raw.rewrite_playlist_urls && base_url.is_none() {
        return Err(validation_error(
            format!("{context}.hls.base_url"),
            "base_url must be provided when rewrite_playlist_urls is true",
        ));
    }

    if raw.allow_insecure_segments {
        #[cfg(feature = "telemetry")]
        tracing::warn!(
            context = %context,
            "allow_insecure_segments is enabled; rewritten manifests may emit http:// URLs.",
        );
    }

    Ok(HlsConfig {
        enabled: raw.enabled,
        rewrite_playlist_urls: raw.rewrite_playlist_urls,
        base_url,
        allow_insecure_segments: raw.allow_insecure_segments,
    })
}

fn duration_from_millis(value: u64, context: String) -> Result<Duration, ConfigError> {
    if value == 0 {
        return Err(validation_error(
            context,
            "duration must be greater than zero",
        ));
    }

    Ok(Duration::from_millis(value))
}

fn validation_error(context: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        context: context.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_sample_routes_configuration() {
        let config =
            Config::load_from_path("config/routes.yaml").expect("configuration should load");
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].id, "vod-edge");
        assert!(config.routes[0].upstream.tls.enabled);
    }

    #[test]
    fn rejects_missing_route_id() {
        let raw = RawConfig {
            routes: vec![RawRoute {
                id: "   ".into(),
                listen: RawListener {
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
                upstream: RawUpstream {
                    origin: "http://example.com".into(),
                    connect_timeout_ms: 1000,
                    read_timeout_ms: 1000,
                    tls: RawTls::default(),
                    socks5: RawSocks5::default(),
                },
                hls: None,
            }],
        };

        let err = Config::try_from(raw).expect_err("validation should fail");
        match err {
            ConfigError::Validation { context, .. } => {
                assert_eq!(context, "routes[0].id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
