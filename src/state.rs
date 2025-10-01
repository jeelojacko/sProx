use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use globset::{Glob, GlobMatcher};
use once_cell::sync::OnceCell;
use reqwest::{redirect::Policy as RedirectPolicy, Client, Proxy};
use tokio::sync::RwLock;
use url::Url;

use crate::routing::RoutingEngine;

pub(crate) const DIRECT_STREAM_REQUEST_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "pragma",
    "range",
    "if-range",
    "if-none-match",
    "if-modified-since",
    "user-agent",
    "referer",
    "origin",
];

/// Identifier used to look up cached client metadata.
pub type ClientId = String;

/// Identifier used to look up routing entries.
pub type RouteId = String;

/// Identifier used to look up secret values.
pub type SecretName = String;

/// Representation of a downstream client registered with the proxy.
#[derive(Debug, Clone, Default)]
pub struct ClientMetadata {
    /// Arbitrary metadata describing a client; stored as key-value pairs so
    /// integrators can extend the schema without requiring code changes.
    pub attributes: HashMap<String, String>,
}

/// Representation of an upstream target used when proxying requests.
#[derive(Debug, Clone, Default)]
pub struct RouteTarget {
    /// Endpoint of the upstream target. The placeholder is a bare string until
    /// connection pooling and TLS configuration are implemented.
    pub upstream: String,
    /// Optional timeout applied when establishing new upstream connections.
    pub connect_timeout: Option<Duration>,
    /// Optional timeout applied while waiting for upstream responses.
    pub read_timeout: Option<Duration>,
    /// Optional timeout applied to the full upstream request lifecycle.
    pub request_timeout: Option<Duration>,
    /// When true certificate validation will be skipped for the upstream
    /// request. This should only be enabled for local development.
    pub tls_insecure_skip_verify: bool,
    /// Optional SOCKS5 proxy settings applied to outbound requests.
    pub socks5: Option<Socks5Proxy>,
    /// Optional HLS processing configuration applied to responses.
    pub hls: Option<HlsOptions>,
}

/// Configuration for tunneling outbound requests through a SOCKS5 proxy.
#[derive(Debug, Clone, Default)]
pub struct Socks5Proxy {
    /// Address of the SOCKS5 proxy in host:port format.
    pub address: String,
    /// Optional username used when proxy authentication is required.
    pub username: Option<String>,
    /// Optional password used when proxy authentication is required.
    pub password: Option<String>,
}

/// Response processing settings for HTTP Live Streaming (HLS) manifests.
#[derive(Debug, Clone, Default)]
pub struct HlsOptions {
    /// Toggle to enable HLS-specific manifest processing for the route.
    pub enabled: bool,
    /// When true playlist, segment, and key URIs will be rewritten to the
    /// configured [`base_url`].
    pub rewrite_playlist_urls: bool,
    /// Base public URL that should be advertised within rewritten manifests.
    pub base_url: Option<Url>,
    /// Allow emitting manifest references that use the `http` scheme. This
    /// should generally remain disabled for production traffic.
    pub allow_insecure_segments: bool,
}

/// Representation of an opaque secret loaded from the configuration backend.
#[derive(Debug, Clone, Default)]
pub struct SecretValue {
    /// Raw secret value. Concrete projects may want to wrap this in a
    /// redaction-friendly type but for now a string keeps the placeholder
    /// ergonomic.
    pub value: String,
}

/// In-memory cache used to store client registrations.
pub type ClientsCache = HashMap<ClientId, ClientMetadata>;

/// In-memory routing table mapping proxy routes to upstream targets.
pub type RoutingTable = HashMap<RouteId, RouteTarget>;

/// In-memory secret store shared across the application.
pub type SecretsStore = HashMap<SecretName, SecretValue>;

/// Shared handle to the client cache protected by an asynchronous lock.
pub type SharedClientsCache = Arc<RwLock<ClientsCache>>;

/// Shared handle to the routing table protected by an asynchronous lock.
pub type SharedRoutingTable = Arc<RwLock<RoutingTable>>;

/// Shared handle to the secret store protected by an asynchronous lock.
pub type SharedSecretsStore = Arc<RwLock<SecretsStore>>;

/// Shared handle to the compiled routing engine used when selecting routes.
pub type SharedRoutingEngine = Arc<RoutingEngine>;

/// Configuration applied to the inbound request rate limiter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Maximum number of requests that can be processed during each refill
    /// interval.
    pub capacity: u64,
    /// Interval after which a full set of tokens is made available.
    pub refill_interval: Duration,
}

impl RateLimitConfig {
    /// Creates a new [`RateLimitConfig`] with the provided capacity and refill
    /// interval.
    pub fn new(capacity: u64, refill_interval: Duration) -> Self {
        Self {
            capacity,
            refill_interval,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            refill_interval: Duration::from_secs(1),
        }
    }
}

/// Configuration applied to the direct stream proxy client.
#[derive(Clone, Debug)]
pub struct DirectStreamSettings {
    proxy_url: Option<Url>,
    api_password: Option<String>,
    request_timeout: Duration,
    response_buffer_bytes: usize,
    allowlist: DirectStreamAllowlist,
}

impl DirectStreamSettings {
    pub const DEFAULT_RESPONSE_BUFFER_BYTES: usize = 65_536;

    pub fn default_request_timeout() -> Duration {
        Duration::from_secs(30)
    }

    /// Returns the configured proxy URL when present.
    pub fn proxy_url(&self) -> Option<&Url> {
        self.proxy_url.as_ref()
    }

    /// Returns the configured API password when present.
    pub fn api_password(&self) -> Option<&str> {
        self.api_password.as_deref()
    }

    /// Returns the request timeout applied to outbound direct stream requests.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns the configured HTTP/2 buffer settings in bytes.
    pub fn response_buffer_bytes(&self) -> usize {
        self.response_buffer_bytes
    }

    pub fn allowlist(&self) -> &DirectStreamAllowlist {
        &self.allowlist
    }

    pub fn with_allowlist(mut self, allowlist: DirectStreamAllowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    pub fn is_request_header_allowed(&self, name: &str) -> bool {
        DIRECT_STREAM_REQUEST_HEADER_ALLOWLIST
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
    }
}

impl Default for DirectStreamSettings {
    fn default() -> Self {
        Self {
            proxy_url: None,
            api_password: None,
            request_timeout: Self::default_request_timeout(),
            response_buffer_bytes: Self::DEFAULT_RESPONSE_BUFFER_BYTES,
            allowlist: DirectStreamAllowlist::default(),
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::DirectStreamConfig> for DirectStreamSettings {
    fn from(value: crate::config::DirectStreamConfig) -> Self {
        Self {
            proxy_url: value.proxy_url,
            api_password: value.api_password,
            request_timeout: value.request_timeout,
            response_buffer_bytes: value.response_buffer_bytes,
            allowlist: value.allowlist.into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DirectStreamAllowlist {
    rules: Vec<CompiledDirectStreamAllowRule>,
}

impl DirectStreamAllowlist {
    pub fn allows(&self, url: &Url) -> bool {
        if self.rules.is_empty() {
            return false;
        }

        let Some(host) = url.host_str() else {
            return false;
        };

        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
        let path = url.path();
        let scheme = url.scheme();

        self.rules
            .iter()
            .any(|rule| rule.matches(&normalized_host, path, scheme))
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::DirectStreamAllowlist> for DirectStreamAllowlist {
    fn from(value: crate::config::DirectStreamAllowlist) -> Self {
        let rules = value
            .rules
            .into_iter()
            .map(CompiledDirectStreamAllowRule::from)
            .collect();

        Self { rules }
    }
}

#[derive(Clone, Debug)]
struct CompiledDirectStreamAllowRule {
    domain: String,
    schemes: AllowedSchemes,
    path_matchers: Vec<GlobMatcher>,
}

impl CompiledDirectStreamAllowRule {
    fn matches(&self, host: &str, path: &str, scheme: &str) -> bool {
        if self.domain != host {
            return false;
        }

        if !self.schemes.allows(scheme) {
            return false;
        }

        if self.path_matchers.is_empty() {
            return true;
        }

        self.path_matchers
            .iter()
            .any(|matcher| matcher.is_match(path))
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::DirectStreamAllowRule> for CompiledDirectStreamAllowRule {
    fn from(value: crate::config::DirectStreamAllowRule) -> Self {
        let path_matchers = value
            .path_globs
            .iter()
            .map(|pattern| {
                Glob::new(pattern)
                    .expect("path globs validated during configuration parsing")
                    .compile_matcher()
            })
            .collect();

        Self {
            domain: value.domain,
            schemes: AllowedSchemes::from(value.schemes),
            path_matchers,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct AllowedSchemes {
    http: bool,
    https: bool,
}

impl AllowedSchemes {
    fn allows(&self, scheme: &str) -> bool {
        match scheme {
            "http" => self.http,
            "https" => self.https,
            _ => false,
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<Vec<crate::config::DirectStreamScheme>> for AllowedSchemes {
    fn from(value: Vec<crate::config::DirectStreamScheme>) -> Self {
        let mut schemes = Self::default();

        for scheme in value {
            match scheme {
                crate::config::DirectStreamScheme::Http => schemes.http = true,
                crate::config::DirectStreamScheme::Https => schemes.https = true,
            }
        }

        schemes
    }
}

#[derive(Clone, Debug)]
struct DirectStreamState {
    inner: Arc<DirectStreamStateInner>,
}

#[derive(Debug)]
struct DirectStreamStateInner {
    settings: DirectStreamSettings,
    client: OnceCell<Client>,
}

impl DirectStreamState {
    fn new(settings: DirectStreamSettings) -> Self {
        Self {
            inner: Arc::new(DirectStreamStateInner {
                settings,
                client: OnceCell::new(),
            }),
        }
    }

    fn settings(&self) -> &DirectStreamSettings {
        &self.inner.settings
    }

    fn client(&self) -> Result<Client, reqwest::Error> {
        self.inner
            .client
            .get_or_try_init(|| build_direct_stream_client(self.settings()))
            .cloned()
    }
}

fn build_direct_stream_client(settings: &DirectStreamSettings) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(settings.request_timeout())
        .redirect(RedirectPolicy::none());

    let resolver = Arc::new(crate::stream::direct::RestrictedDnsResolver::new());

    builder = builder.dns_resolver(resolver);

    if let Some(proxy_url) = settings.proxy_url() {
        builder = builder.proxy(Proxy::all(proxy_url.as_str())?);
    }

    if let Ok(window) = u32::try_from(settings.response_buffer_bytes()) {
        builder = builder
            .http2_initial_stream_window_size(Some(window))
            .http2_initial_connection_window_size(Some(window));
    }

    builder.build()
}

/// Top-level application state shared across the Axum router and background
/// workers.
#[derive(Clone, Debug)]
pub struct AppState {
    clients_cache: SharedClientsCache,
    routing_table: SharedRoutingTable,
    secrets: SharedSecretsStore,
    rate_limit: RateLimitConfig,
    routing_engine: SharedRoutingEngine,
    http_client: Client,
    direct_stream: Option<DirectStreamState>,
}

impl AppState {
    /// Constructs a new [`AppState`] using empty caches for each component.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a new [`AppState`] using the provided shared components. This
    /// makes it easy to plug in pre-populated caches during bootstrap while
    /// allowing handlers to share the same view of the data.
    pub fn with_components(
        clients_cache: SharedClientsCache,
        routing_table: SharedRoutingTable,
        secrets: SharedSecretsStore,
        routing_engine: SharedRoutingEngine,
    ) -> Self {
        Self {
            clients_cache,
            routing_table,
            secrets,
            rate_limit: RateLimitConfig::default(),
            routing_engine,
            http_client: Client::new(),
            direct_stream: None,
        }
    }

    /// Returns a clone of the shared clients cache handle.
    pub fn clients_cache(&self) -> SharedClientsCache {
        Arc::clone(&self.clients_cache)
    }

    /// Returns a clone of the shared routing table handle.
    pub fn routing_table(&self) -> SharedRoutingTable {
        Arc::clone(&self.routing_table)
    }

    /// Returns a clone of the shared secrets store handle.
    pub fn secrets(&self) -> SharedSecretsStore {
        Arc::clone(&self.secrets)
    }

    /// Returns a clone of the compiled routing engine handle.
    pub fn routing_engine(&self) -> SharedRoutingEngine {
        Arc::clone(&self.routing_engine)
    }

    /// Returns a clone of the shared HTTP client used for outbound requests.
    pub fn http_client(&self) -> Client {
        self.http_client.clone()
    }

    /// Returns the configured rate limit settings.
    pub fn rate_limit_config(&self) -> RateLimitConfig {
        self.rate_limit.clone()
    }

    /// Applies a direct stream configuration to the state.
    pub fn with_direct_stream_settings(mut self, settings: DirectStreamSettings) -> Self {
        self.direct_stream = Some(DirectStreamState::new(settings));
        self
    }

    /// Returns the configured proxy URL for direct stream requests when present.
    pub fn direct_stream_proxy_url(&self) -> Option<&Url> {
        self.direct_stream
            .as_ref()
            .and_then(|state| state.settings().proxy_url())
    }

    /// Returns the configured API password for direct stream requests when present.
    pub fn direct_stream_api_password(&self) -> Option<&str> {
        self.direct_stream
            .as_ref()
            .and_then(|state| state.settings().api_password())
    }

    /// Returns the configured direct stream settings when available.
    pub fn direct_stream_settings(&self) -> Option<&DirectStreamSettings> {
        self.direct_stream.as_ref().map(|state| state.settings())
    }

    /// Returns the request timeout applied to direct stream requests.
    pub fn direct_stream_request_timeout(&self) -> Duration {
        self.direct_stream
            .as_ref()
            .map(|state| state.settings().request_timeout())
            .unwrap_or_else(DirectStreamSettings::default_request_timeout)
    }

    /// Returns the configured response buffer window in bytes.
    pub fn direct_stream_response_buffer_bytes(&self) -> usize {
        self.direct_stream
            .as_ref()
            .map(|state| state.settings().response_buffer_bytes())
            .unwrap_or(DirectStreamSettings::DEFAULT_RESPONSE_BUFFER_BYTES)
    }

    /// Returns a clone of the reqwest client configured for direct stream requests.
    pub fn direct_stream_client(&self) -> Result<Client, reqwest::Error> {
        match self.direct_stream.as_ref() {
            Some(state) => state.client(),
            None => Ok(self.http_client()),
        }
    }

    /// Applies a custom rate limit configuration to the state.
    pub fn with_rate_limit_config(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Replaces the routing engine backing the state with the provided instance.
    pub fn with_routing_engine(mut self, routing_engine: SharedRoutingEngine) -> Self {
        self.routing_engine = routing_engine;
        self
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            clients_cache: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            secrets: Arc::new(RwLock::new(HashMap::new())),
            rate_limit: RateLimitConfig::default(),
            routing_engine: Arc::new(
                RoutingEngine::new(Vec::new())
                    .expect("routing engine should compile for empty routes"),
            ),
            http_client: Client::new(),
            direct_stream: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_state_exposes_shared_handles() {
        let state = AppState::new();

        state.clients_cache().write().await.insert(
            "client-a".into(),
            ClientMetadata {
                attributes: HashMap::from([(String::from("plan"), String::from("premium"))]),
            },
        );

        let clients_handle = state.clients_cache();
        let cached = clients_handle.read().await;
        assert!(cached.contains_key("client-a"));

        state.routing_table().write().await.insert(
            "route-a".into(),
            RouteTarget {
                upstream: "https://example.com".into(),
                connect_timeout: None,
                read_timeout: None,
                request_timeout: None,
                tls_insecure_skip_verify: false,
                socks5: None,
                hls: None,
            },
        );

        let routing_handle = state.routing_table();
        let routes = routing_handle.read().await;
        assert_eq!(routes["route-a"].upstream, "https://example.com");

        state.secrets().write().await.insert(
            "api_key".into(),
            SecretValue {
                value: "super-secret".into(),
            },
        );

        let secrets_handle = state.secrets();
        let secrets = secrets_handle.read().await;
        assert_eq!(secrets["api_key"].value, "super-secret");
    }

    #[test]
    fn app_state_allows_custom_rate_limit_configuration() {
        let config = RateLimitConfig::new(5, Duration::from_millis(250));
        let state = AppState::new().with_rate_limit_config(config.clone());

        assert_eq!(state.rate_limit_config(), config);
    }

    #[test]
    fn app_state_exposes_direct_stream_configuration() {
        let settings = DirectStreamSettings {
            proxy_url: Some(Url::parse("http://proxy.example:3128").unwrap()),
            api_password: Some("super-secret".into()),
            request_timeout: Duration::from_secs(10),
            response_buffer_bytes: 131_072,
            allowlist: DirectStreamAllowlist::default(),
        };

        let state = AppState::new().with_direct_stream_settings(settings.clone());

        assert_eq!(
            state.direct_stream_proxy_url().map(|url| url.as_str()),
            Some("http://proxy.example:3128/")
        );
        assert_eq!(state.direct_stream_api_password(), Some("super-secret"));
        assert_eq!(
            state.direct_stream_request_timeout(),
            settings.request_timeout()
        );
        assert_eq!(
            state.direct_stream_response_buffer_bytes(),
            settings.response_buffer_bytes()
        );

        let client = state
            .direct_stream_client()
            .expect("client should build successfully");
        let _clone = client.clone();
    }
}
