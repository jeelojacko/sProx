use std::env;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use config as config_rs;
use globset::Glob;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::routing::RouteProtocol;

#[derive(Debug, Clone)]
pub struct Config {
    pub direct_stream: Option<DirectStreamConfig>,
    pub routes: Vec<RouteConfig>,
    pub secrets: SecretsConfig,
    pub sensitive_logging: SensitiveLoggingConfig,
}

#[derive(Debug, Clone)]
pub struct DirectStreamConfig {
    pub proxy_url: Option<Url>,
    pub api_password: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub request_timeout: Duration,
    pub response_buffer_bytes: usize,
    pub allowlist: DirectStreamAllowlist,
    pub retry: RetryConfig,
}

#[derive(Debug, Clone)]
pub struct SecretsConfig {
    pub default_ttl: Duration,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SensitiveLoggingConfig {
    pub log_sensitive_headers: bool,
    pub redact_sensitive_queries: bool,
}

impl DirectStreamConfig {
    pub const DEFAULT_RESPONSE_BUFFER_BYTES: usize = 65_536;

    pub fn default_request_timeout() -> Duration {
        Duration::from_secs(30)
    }

    pub fn allowlist(&self) -> &DirectStreamAllowlist {
        &self.allowlist
    }
}

impl Default for DirectStreamConfig {
    fn default() -> Self {
        Self {
            proxy_url: None,
            api_password: None,
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            request_timeout: Self::default_request_timeout(),
            response_buffer_bytes: Self::DEFAULT_RESPONSE_BUFFER_BYTES,
            allowlist: DirectStreamAllowlist::default(),
            retry: RetryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirectStreamAllowlist {
    pub rules: Vec<DirectStreamAllowRule>,
}

#[derive(Debug, Clone)]
pub struct DirectStreamAllowRule {
    pub domain: String,
    pub schemes: Vec<DirectStreamScheme>,
    pub path_globs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectStreamScheme {
    Http,
    Https,
}

impl DirectStreamScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl std::str::FromStr for DirectStreamScheme {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub id: String,
    pub listen: ListenerConfig,
    pub host_patterns: Vec<String>,
    pub protocols: Vec<RouteProtocol>,
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
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub request_timeout: Option<Duration>,
    pub tls: TlsConfig,
    pub socks5: Socks5Config,
    pub retry: RetryConfig,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: NonZeroU32,
    pub backoff: RetryBackoffConfig,
    pub budget: RetryBudgetConfig,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: NonZeroU32::new(3).expect("static non-zero"),
            backoff: RetryBackoffConfig::default(),
            budget: RetryBudgetConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryBackoffConfig {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter: f64,
}

impl Default for RetryBackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryBudgetConfig {
    pub ttl: Duration,
    pub min_per_sec: u32,
    pub retry_ratio: f32,
}

impl Default for RetryBudgetConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(10),
            min_per_sec: 10,
            retry_ratio: 0.2,
        }
    }
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
    #[serde(default)]
    direct_stream: Option<RawDirectStream>,
    routes: Vec<RawRoute>,
    #[serde(default)]
    secrets: Option<RawSecrets>,
    #[serde(default)]
    sensitive_logging: Option<RawSensitiveLogging>,
}

#[derive(Debug, Deserialize, Default)]
struct RawDirectStream {
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    api_password: Option<String>,
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
    #[serde(default)]
    read_timeout_ms: Option<u64>,
    #[serde(default)]
    request_timeout_ms: Option<u64>,
    #[serde(default)]
    response_buffer_bytes: Option<usize>,
    #[serde(default)]
    allowlist: Vec<RawDirectStreamAllowRule>,
    #[serde(default)]
    retry: Option<RawRetry>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecrets {
    #[serde(default)]
    default_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSensitiveLogging {
    #[serde(default)]
    log_sensitive_headers: Option<bool>,
    #[serde(default)]
    redact_sensitive_queries: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawDirectStreamAllowRule {
    domain: String,
    #[serde(default)]
    schemes: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawRoute {
    id: String,
    listen: RawListener,
    #[serde(default)]
    host_patterns: Vec<String>,
    #[serde(default)]
    protocols: Vec<String>,
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
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
    #[serde(default)]
    read_timeout_ms: Option<u64>,
    #[serde(default)]
    request_timeout_ms: Option<u64>,
    #[serde(default)]
    tls: RawTls,
    #[serde(default)]
    socks5: RawSocks5,
    #[serde(default)]
    retry: Option<RawRetry>,
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

#[derive(Debug, Deserialize, Default)]
struct RawRetry {
    #[serde(default)]
    max_attempts: Option<u32>,
    #[serde(default)]
    backoff: Option<RawRetryBackoff>,
    #[serde(default)]
    budget: Option<RawRetryBudget>,
}

#[derive(Debug, Deserialize, Default)]
struct RawRetryBackoff {
    #[serde(default)]
    initial_delay_ms: Option<u64>,
    #[serde(default)]
    max_delay_ms: Option<u64>,
    #[serde(default)]
    multiplier: Option<f64>,
    #[serde(default)]
    jitter: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
struct RawRetryBudget {
    #[serde(default)]
    ttl_ms: Option<u64>,
    #[serde(default)]
    min_per_sec: Option<u32>,
    #[serde(default)]
    retry_ratio: Option<f32>,
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

        let direct_stream = parse_direct_stream(raw.direct_stream)?;
        let secrets = parse_secrets(raw.secrets)?;
        let sensitive_logging = parse_sensitive_logging(raw.sensitive_logging)?;

        Ok(Self {
            direct_stream,
            routes,
            secrets,
            sensitive_logging,
        })
    }
}

fn parse_direct_stream(
    raw: Option<RawDirectStream>,
) -> Result<Option<DirectStreamConfig>, ConfigError> {
    let mut parsed = raw
        .map(|raw| raw.try_into_config("direct_stream"))
        .transpose()?;

    let env_proxy = env::var("SPROX_DIRECT_PROXY_URL")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let env_password = env::var("SPROX_DIRECT_API_PASSWORD")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let env_timeout = env::var("SPROX_DIRECT_REQUEST_TIMEOUT_MS")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                validation_error(
                    "env.SPROX_DIRECT_REQUEST_TIMEOUT_MS",
                    format!("invalid integer: {err}"),
                )
            })
        })
        .transpose()?;
    let env_buffer = env::var("SPROX_DIRECT_RESPONSE_BUFFER_BYTES")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<usize>().map_err(|err| {
                validation_error(
                    "env.SPROX_DIRECT_RESPONSE_BUFFER_BYTES",
                    format!("invalid integer: {err}"),
                )
            })
        })
        .transpose()?;

    if env_proxy.is_some()
        || env_password.is_some()
        || env_timeout.is_some()
        || env_buffer.is_some()
    {
        let mut effective = parsed.unwrap_or_default();

        if let Some(proxy) = env_proxy {
            let context = "env.SPROX_DIRECT_PROXY_URL";
            let parsed_proxy = Url::parse(&proxy)
                .map_err(|err| validation_error(context, format!("invalid URL: {err}")))?;
            effective.proxy_url = Some(parsed_proxy);
        }

        if let Some(password) = env_password {
            effective.api_password = Some(password);
        }

        if let Some(timeout_ms) = env_timeout {
            effective.request_timeout = duration_from_millis(
                timeout_ms,
                "env.SPROX_DIRECT_REQUEST_TIMEOUT_MS".to_string(),
            )?;
        }

        if let Some(buffer_bytes) = env_buffer {
            effective.response_buffer_bytes = buffer_size_from_bytes(
                buffer_bytes,
                "env.SPROX_DIRECT_RESPONSE_BUFFER_BYTES".to_string(),
            )?;
        }

        parsed = Some(effective);
    }

    Ok(parsed)
}

fn parse_secrets(raw: Option<RawSecrets>) -> Result<SecretsConfig, ConfigError> {
    match raw {
        Some(raw) => raw.try_into_config("secrets"),
        None => Ok(SecretsConfig::default()),
    }
}

fn parse_sensitive_logging(
    raw: Option<RawSensitiveLogging>,
) -> Result<SensitiveLoggingConfig, ConfigError> {
    let mut config = SensitiveLoggingConfig::default();

    if let Some(raw) = raw {
        if let Some(value) = raw.log_sensitive_headers {
            config.log_sensitive_headers = value;
        }

        if let Some(value) = raw.redact_sensitive_queries {
            config.redact_sensitive_queries = value;
        }
    }

    Ok(config)
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
        let host_patterns = parse_host_patterns(self.host_patterns, &context)?;
        let protocols = parse_protocols(self.protocols, &context)?;
        let upstream = parse_upstream(self.upstream, &context)?;
        let hls = match self.hls {
            Some(hls) => Some(parse_hls(hls, &context)?),
            None => None,
        };

        Ok(RouteConfig {
            id: self.id,
            listen,
            host_patterns,
            protocols,
            upstream,
            hls,
        })
    }
}

impl RawDirectStream {
    fn try_into_config(self, context: &str) -> Result<DirectStreamConfig, ConfigError> {
        let mut config = DirectStreamConfig::default();

        if let Some(proxy_url) = self.proxy_url.and_then(|value| {
            let trimmed = value.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }) {
            let parsed = Url::parse(&proxy_url).map_err(|err| {
                validation_error(
                    format!("{context}.proxy_url"),
                    format!("invalid URL: {err}"),
                )
            })?;
            config.proxy_url = Some(parsed);
        }

        config.api_password = self
            .api_password
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());

        config.connect_timeout = optional_duration_from_millis(
            self.connect_timeout_ms,
            format!("{context}.connect_timeout_ms"),
        )?;

        config.read_timeout = optional_duration_from_millis(
            self.read_timeout_ms,
            format!("{context}.read_timeout_ms"),
        )?;

        if let Some(timeout_ms) = self.request_timeout_ms {
            config.request_timeout =
                duration_from_millis(timeout_ms, format!("{context}.request_timeout_ms"))?;
        }

        if let Some(buffer_bytes) = self.response_buffer_bytes {
            config.response_buffer_bytes =
                buffer_size_from_bytes(buffer_bytes, format!("{context}.response_buffer_bytes"))?;
        }

        config.allowlist = parse_direct_stream_allowlist(self.allowlist, context)?;
        config.retry = parse_retry(self.retry, format!("{context}.retry"))?;

        Ok(config)
    }
}

impl RawSecrets {
    fn try_into_config(self, context: &str) -> Result<SecretsConfig, ConfigError> {
        let mut config = SecretsConfig::default();

        if let Some(ttl_secs) = self.default_ttl_secs {
            config.default_ttl =
                duration_from_secs(ttl_secs, format!("{context}.default_ttl_secs"))?;
        }

        Ok(config)
    }
}

fn parse_direct_stream_allowlist(
    rules: Vec<RawDirectStreamAllowRule>,
    context: &str,
) -> Result<DirectStreamAllowlist, ConfigError> {
    let mut parsed = Vec::with_capacity(rules.len());

    for (idx, rule) in rules.into_iter().enumerate() {
        let rule_context = format!("{context}.allowlist[{idx}]");
        let domain = rule.domain.trim();
        if domain.is_empty() {
            return Err(validation_error(
                format!("{rule_context}.domain"),
                "domain must not be empty",
            ));
        }

        let mut schemes = Vec::new();
        if rule.schemes.is_empty() {
            schemes.push(DirectStreamScheme::Https);
        } else {
            for (scheme_idx, scheme) in rule.schemes.into_iter().enumerate() {
                let normalized = scheme.trim().to_ascii_lowercase();
                if normalized.is_empty() {
                    return Err(validation_error(
                        format!("{rule_context}.schemes[{scheme_idx}]"),
                        "scheme must not be empty",
                    ));
                }

                let Ok(value) = normalized.parse::<DirectStreamScheme>() else {
                    return Err(validation_error(
                        format!("{rule_context}.schemes[{scheme_idx}]"),
                        format!("unsupported scheme `{scheme}`"),
                    ));
                };

                if !schemes.contains(&value) {
                    schemes.push(value);
                }
            }
        }

        let mut path_globs = Vec::with_capacity(rule.paths.len());
        for (path_idx, pattern) in rule.paths.into_iter().enumerate() {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(validation_error(
                    format!("{rule_context}.paths[{path_idx}]"),
                    "path glob must not be empty",
                ));
            }

            if !trimmed.starts_with('/') {
                return Err(validation_error(
                    format!("{rule_context}.paths[{path_idx}]"),
                    "path glob must start with `/`",
                ));
            }

            Glob::new(trimmed).map_err(|source| {
                validation_error(
                    format!("{rule_context}.paths[{path_idx}]"),
                    format!("invalid glob `{trimmed}`: {source}"),
                )
            })?;

            path_globs.push(trimmed.to_owned());
        }

        parsed.push(DirectStreamAllowRule {
            domain: domain.to_ascii_lowercase(),
            schemes,
            path_globs,
        });
    }

    Ok(DirectStreamAllowlist { rules: parsed })
}

const MIN_RETRY_BUDGET_TTL_MS: u64 = 1_000;
const MAX_RETRY_BUDGET_TTL_MS: u64 = 60_000;

fn parse_retry(raw: Option<RawRetry>, context: String) -> Result<RetryConfig, ConfigError> {
    let mut retry = RetryConfig::default();

    let Some(raw) = raw else {
        return Ok(retry);
    };

    if let Some(max_attempts) = raw.max_attempts {
        if max_attempts == 0 {
            return Err(validation_error(
                format!("{context}.max_attempts"),
                "max_attempts must be greater than zero",
            ));
        }

        retry.max_attempts = NonZeroU32::new(max_attempts).expect("checked above");
    }

    if let Some(backoff) = raw.backoff {
        if let Some(initial_ms) = backoff.initial_delay_ms {
            retry.backoff.initial_delay =
                duration_from_millis(initial_ms, format!("{context}.backoff.initial_delay_ms"))?;
        }

        if let Some(max_ms) = backoff.max_delay_ms {
            retry.backoff.max_delay =
                duration_from_millis(max_ms, format!("{context}.backoff.max_delay_ms"))?;
        }

        if let Some(multiplier) = backoff.multiplier {
            if multiplier < 1.0 {
                return Err(validation_error(
                    format!("{context}.backoff.multiplier"),
                    "multiplier must be greater than or equal to 1.0",
                ));
            }
            retry.backoff.multiplier = multiplier;
        }

        if let Some(jitter) = backoff.jitter {
            if !(0.0..=1.0).contains(&jitter) {
                return Err(validation_error(
                    format!("{context}.backoff.jitter"),
                    "jitter must be between 0.0 and 1.0",
                ));
            }
            retry.backoff.jitter = jitter;
        }
    }

    if let Some(budget) = raw.budget {
        if let Some(ttl_ms) = budget.ttl_ms {
            if !(MIN_RETRY_BUDGET_TTL_MS..=MAX_RETRY_BUDGET_TTL_MS).contains(&ttl_ms) {
                return Err(validation_error(
                    format!("{context}.budget.ttl_ms"),
                    format!(
                        "ttl_ms must be between {MIN_RETRY_BUDGET_TTL_MS} and {MAX_RETRY_BUDGET_TTL_MS} milliseconds (1-60 seconds)"
                    ),
                ));
            }

            retry.budget.ttl = duration_from_millis(ttl_ms, format!("{context}.budget.ttl_ms"))?;
        }

        if let Some(min_per_sec) = budget.min_per_sec {
            retry.budget.min_per_sec = min_per_sec;
        }

        if let Some(ratio) = budget.retry_ratio {
            if !(0.0..=1000.0).contains(&ratio) {
                return Err(validation_error(
                    format!("{context}.budget.retry_ratio"),
                    "retry_ratio must be between 0.0 and 1000.0",
                ));
            }
            retry.budget.retry_ratio = ratio;
        }
    }

    Ok(retry)
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

    let connect_timeout = optional_duration_from_millis(
        raw.connect_timeout_ms,
        format!("{context}.upstream.connect_timeout_ms"),
    )?;
    let read_timeout = optional_duration_from_millis(
        raw.read_timeout_ms,
        format!("{context}.upstream.read_timeout_ms"),
    )?;
    let request_timeout = optional_duration_from_millis(
        raw.request_timeout_ms,
        format!("{context}.upstream.request_timeout_ms"),
    )?;

    let tls_context = format!("{context}.upstream.tls");
    let tls = parse_tls(raw.tls, &tls_context);
    let socks5 = parse_socks5(raw.socks5, context)?;
    let retry = parse_retry(raw.retry, format!("{context}.upstream.retry"))?;

    Ok(UpstreamConfig {
        origin,
        connect_timeout,
        read_timeout,
        request_timeout,
        tls,
        socks5,
        retry,
    })
}

fn parse_host_patterns(patterns: Vec<String>, context: &str) -> Result<Vec<String>, ConfigError> {
    let mut parsed = Vec::with_capacity(patterns.len());

    for (idx, pattern) in patterns.into_iter().enumerate() {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return Err(validation_error(
                format!("{context}.host_patterns[{idx}]"),
                "host pattern must not be empty",
            ));
        }

        parsed.push(trimmed.to_ascii_lowercase());
    }

    Ok(parsed)
}

fn parse_protocols(
    protocols: Vec<String>,
    context: &str,
) -> Result<Vec<RouteProtocol>, ConfigError> {
    let mut parsed = Vec::with_capacity(protocols.len());

    for (idx, protocol) in protocols.into_iter().enumerate() {
        let trimmed = protocol.trim();
        if trimmed.is_empty() {
            return Err(validation_error(
                format!("{context}.protocols[{idx}]"),
                "protocol must not be empty",
            ));
        }

        let normalized = trimmed.to_ascii_lowercase();
        let Some(value) = RouteProtocol::from_scheme(&normalized) else {
            return Err(validation_error(
                format!("{context}.protocols[{idx}]"),
                format!("unsupported protocol `{trimmed}`"),
            ));
        };

        parsed.push(value);
    }

    Ok(parsed)
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

fn optional_duration_from_millis(
    value: Option<u64>,
    context: String,
) -> Result<Option<Duration>, ConfigError> {
    match value {
        Some(value) => duration_from_millis(value, context).map(Some),
        None => Ok(None),
    }
}

fn duration_from_secs(value: u64, context: String) -> Result<Duration, ConfigError> {
    if value == 0 {
        return Err(validation_error(
            context,
            "duration must be greater than zero",
        ));
    }

    Ok(Duration::from_secs(value))
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

fn buffer_size_from_bytes(value: usize, context: String) -> Result<usize, ConfigError> {
    if value == 0 {
        return Err(validation_error(
            context,
            "buffer size must be greater than zero",
        ));
    }

    if value > u32::MAX as usize {
        return Err(validation_error(
            context,
            format!("buffer size must not exceed {}", u32::MAX),
        ));
    }

    Ok(value)
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
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_route() -> RawRoute {
        RawRoute {
            id: "route".into(),
            listen: RawListener {
                host: "127.0.0.1".into(),
                port: 8080,
            },
            host_patterns: Vec::new(),
            protocols: Vec::new(),
            upstream: RawUpstream {
                origin: "http://example.com".into(),
                connect_timeout_ms: Some(1000),
                read_timeout_ms: Some(1000),
                request_timeout_ms: Some(1000),
                tls: RawTls::default(),
                socks5: RawSocks5::default(),
                retry: None,
            },
            hls: None,
        }
    }

    #[test]
    fn loads_sample_routes_configuration() {
        let config =
            Config::load_from_path("config/routes.yaml").expect("configuration should load");
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].id, "vod-edge");
        assert_eq!(
            config.routes[0].host_patterns,
            vec!["vod-edge.example.com", "*.vod.example.com"]
        );
        assert!(config.routes[0].protocols.is_empty());
        assert!(config.routes[0].upstream.tls.enabled);
        assert_eq!(
            config.routes[0]
                .upstream
                .connect_timeout
                .expect("connect timeout should be parsed"),
            Duration::from_millis(2000)
        );
        assert_eq!(
            config.routes[0]
                .upstream
                .read_timeout
                .expect("read timeout should be parsed"),
            Duration::from_millis(5000)
        );
        assert_eq!(
            config.routes[0]
                .upstream
                .request_timeout
                .expect("request timeout should be parsed"),
            Duration::from_millis(8000)
        );
        let direct = config
            .direct_stream
            .as_ref()
            .expect("direct stream configuration should be present");
        assert!(direct.proxy_url.is_none());
        assert!(direct.api_password.is_none());
        assert_eq!(
            direct.request_timeout,
            DirectStreamConfig::default_request_timeout()
        );
        assert_eq!(
            direct.response_buffer_bytes,
            DirectStreamConfig::DEFAULT_RESPONSE_BUFFER_BYTES
        );
        assert_eq!(config.secrets.default_ttl, Duration::from_secs(300));
        assert!(!config.sensitive_logging.log_sensitive_headers);
        assert!(!config.sensitive_logging.redact_sensitive_queries);
    }

    #[test]
    fn rejects_missing_route_id() {
        let raw = RawConfig {
            direct_stream: None,
            routes: vec![RawRoute {
                id: "   ".into(),
                listen: RawListener {
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
                host_patterns: Vec::new(),
                protocols: Vec::new(),
                upstream: RawUpstream {
                    origin: "http://example.com".into(),
                    connect_timeout_ms: Some(1000),
                    read_timeout_ms: Some(1000),
                    request_timeout_ms: None,
                    tls: RawTls::default(),
                    socks5: RawSocks5::default(),
                    retry: None,
                },
                hls: None,
            }],
            secrets: None,
            sensitive_logging: None,
        };

        let err = Config::try_from(raw).expect_err("validation should fail");
        match err {
            ConfigError::Validation { context, .. } => {
                assert_eq!(context, "routes[0].id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn direct_stream_defaults_to_none_without_overrides() {
        let raw = RawConfig {
            direct_stream: None,
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: None,
        };

        let config = Config::try_from(raw).expect("configuration should load");
        assert!(config.direct_stream.is_none());
    }

    #[test]
    fn direct_stream_parses_configured_values() {
        let raw = RawConfig {
            direct_stream: Some(RawDirectStream {
                proxy_url: Some("http://proxy.local:8080".into()),
                api_password: Some("secret".into()),
                connect_timeout_ms: Some(1500),
                read_timeout_ms: Some(3500),
                request_timeout_ms: Some(4500),
                response_buffer_bytes: Some(32_768),
                allowlist: Vec::new(),
                retry: Some(RawRetry {
                    max_attempts: Some(5),
                    backoff: Some(RawRetryBackoff {
                        initial_delay_ms: Some(25),
                        max_delay_ms: Some(500),
                        multiplier: Some(1.5),
                        jitter: Some(0.1),
                    }),
                    budget: Some(RawRetryBudget {
                        ttl_ms: Some(5_000),
                        min_per_sec: Some(1),
                        retry_ratio: Some(0.5),
                    }),
                }),
            }),
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: None,
        };

        let config = Config::try_from(raw).expect("configuration should load");
        let direct = config
            .direct_stream
            .expect("direct stream configuration should be present");
        assert_eq!(
            direct.proxy_url.unwrap().as_str(),
            "http://proxy.local:8080/"
        );
        assert_eq!(direct.api_password.as_deref(), Some("secret"));
        assert_eq!(direct.connect_timeout, Some(Duration::from_millis(1500)));
        assert_eq!(direct.read_timeout, Some(Duration::from_millis(3500)));
        assert_eq!(direct.request_timeout, Duration::from_millis(4500));
        assert_eq!(direct.response_buffer_bytes, 32_768);
        assert_eq!(direct.retry.max_attempts, NonZeroU32::new(5).unwrap());
        assert_eq!(
            direct.retry.backoff.initial_delay,
            Duration::from_millis(25)
        );
        assert_eq!(direct.retry.backoff.max_delay, Duration::from_millis(500));
        assert!((direct.retry.backoff.multiplier - 1.5).abs() < f64::EPSILON);
        assert!((direct.retry.backoff.jitter - 0.1).abs() < f64::EPSILON);
        assert_eq!(direct.retry.budget.ttl, Duration::from_millis(5_000));
        assert_eq!(direct.retry.budget.min_per_sec, 1);
        assert!((direct.retry.budget.retry_ratio - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn direct_stream_rejects_retry_budget_ttl_below_supported_range() {
        let raw = RawConfig {
            direct_stream: Some(RawDirectStream {
                retry: Some(RawRetry {
                    budget: Some(RawRetryBudget {
                        ttl_ms: Some(MIN_RETRY_BUDGET_TTL_MS - 1),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: None,
        };

        let err = Config::try_from(raw).expect_err("validation should fail");
        match err {
            ConfigError::Validation { context, message } => {
                assert_eq!(context, "direct_stream.retry.budget.ttl_ms");
                assert!(message.contains("between"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn direct_stream_rejects_retry_budget_ttl_above_supported_range() {
        let raw = RawConfig {
            direct_stream: Some(RawDirectStream {
                retry: Some(RawRetry {
                    budget: Some(RawRetryBudget {
                        ttl_ms: Some(MAX_RETRY_BUDGET_TTL_MS + 1),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: None,
        };

        let err = Config::try_from(raw).expect_err("validation should fail");
        match err {
            ConfigError::Validation { context, message } => {
                assert_eq!(context, "direct_stream.retry.budget.ttl_ms");
                assert!(message.contains("between"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn direct_stream_env_overrides_create_configuration() {
        let _guard = env_lock().lock().expect("env lock should be acquired");

        env::remove_var("SPROX_DIRECT_PROXY_URL");
        env::remove_var("SPROX_DIRECT_API_PASSWORD");
        env::remove_var("SPROX_DIRECT_REQUEST_TIMEOUT_MS");
        env::remove_var("SPROX_DIRECT_RESPONSE_BUFFER_BYTES");

        env::set_var("SPROX_DIRECT_PROXY_URL", "http://env-proxy:8080");
        env::set_var("SPROX_DIRECT_API_PASSWORD", "env-secret");
        env::set_var("SPROX_DIRECT_REQUEST_TIMEOUT_MS", "12000");
        env::set_var("SPROX_DIRECT_RESPONSE_BUFFER_BYTES", "131072");

        let raw = RawConfig {
            direct_stream: None,
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: None,
        };

        let config = Config::try_from(raw).expect("configuration should load");
        let direct = config
            .direct_stream
            .expect("direct stream configuration should be present");
        assert_eq!(direct.proxy_url.unwrap().as_str(), "http://env-proxy:8080/");
        assert_eq!(direct.api_password.as_deref(), Some("env-secret"));
        assert_eq!(direct.request_timeout, Duration::from_millis(12_000));
        assert_eq!(direct.response_buffer_bytes, 131_072);

        env::remove_var("SPROX_DIRECT_PROXY_URL");
        env::remove_var("SPROX_DIRECT_API_PASSWORD");
        env::remove_var("SPROX_DIRECT_REQUEST_TIMEOUT_MS");
        env::remove_var("SPROX_DIRECT_RESPONSE_BUFFER_BYTES");
    }

    #[test]
    fn secrets_configuration_respects_custom_ttl() {
        let raw = RawConfig {
            direct_stream: None,
            routes: vec![sample_route()],
            secrets: Some(RawSecrets {
                default_ttl_secs: Some(120),
            }),
            sensitive_logging: None,
        };

        let config = Config::try_from(raw).expect("configuration should load");
        assert_eq!(config.secrets.default_ttl, Duration::from_secs(120));
    }

    #[test]
    fn secrets_configuration_rejects_zero_ttl() {
        let raw = RawConfig {
            direct_stream: None,
            routes: vec![sample_route()],
            secrets: Some(RawSecrets {
                default_ttl_secs: Some(0),
            }),
            sensitive_logging: None,
        };

        let err = Config::try_from(raw).expect_err("validation should fail");
        match err {
            ConfigError::Validation { context, .. } => {
                assert_eq!(context, "secrets.default_ttl_secs");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sensitive_logging_configuration_parses_flags() {
        let raw = RawConfig {
            direct_stream: None,
            routes: vec![sample_route()],
            secrets: None,
            sensitive_logging: Some(RawSensitiveLogging {
                log_sensitive_headers: Some(true),
                redact_sensitive_queries: Some(true),
            }),
        };

        let config = Config::try_from(raw).expect("configuration should load");
        assert!(config.sensitive_logging.log_sensitive_headers);
        assert!(config.sensitive_logging.redact_sensitive_queries);
    }
}
