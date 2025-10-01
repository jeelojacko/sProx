use std::collections::{HashMap, HashSet};
use std::env;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use globset::{Glob, GlobMatcher};
use http::header::HeaderName;
use once_cell::sync::OnceCell;
use reqwest::{redirect::Policy as RedirectPolicy, Client, Method, Proxy};
use tokio::sync::RwLock;
use tower::retry::budget::Budget;
use url::Url;

use crate::config::{Config, CorsConfig};
use crate::routing::{PortRange, RouteDefinition, RoutingEngine};

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
    /// Retry policy used for outbound requests targeting this upstream.
    pub retry: RetryPolicy,
    /// Header forwarding policy applied when proxying requests and responses.
    pub header_policy: HeaderPolicy,
}

/// Strategy applied when constructing the `X-Forwarded-For` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XForwardedFor {
    /// Append the client IP to any existing header chain.
    #[default]
    Append,
    /// Replace the existing header with only the client IP.
    Replace,
}

/// Header forwarding policy for a given route.
#[derive(Debug, Clone, Default)]
pub struct HeaderPolicy {
    allow: HashSet<String>,
    deny: HashSet<String>,
    x_forwarded_for: XForwardedFor,
}

impl HeaderPolicy {
    /// Creates a new header policy with the provided configuration.
    pub fn new(
        allow: HashSet<String>,
        deny: HashSet<String>,
        x_forwarded_for: XForwardedFor,
    ) -> Self {
        Self {
            allow,
            deny,
            x_forwarded_for,
        }
    }

    /// Returns true if the header should be forwarded regardless of other rules.
    pub fn is_explicitly_allowed(&self, header: &HeaderName) -> bool {
        self.allow.contains(header.as_str())
    }

    /// Returns true if the header is explicitly denied by configuration.
    pub fn is_explicitly_denied(&self, header: &HeaderName) -> bool {
        self.deny.contains(header.as_str())
    }

    /// Returns the configured X-Forwarded-For strategy.
    pub fn x_forwarded_for(&self) -> XForwardedFor {
        self.x_forwarded_for
    }
}

/// Retry backoff configuration applied when scheduling retries.
#[derive(Debug, Clone)]
pub struct RetryBackoff {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter: f64,
}

impl RetryBackoff {
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1) as i32;
        let mut delay = self.initial_delay.mul_f64(self.multiplier.powi(exponent));
        if delay > self.max_delay {
            delay = self.max_delay;
        }
        delay
    }
}

impl Default for RetryBackoff {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

#[derive(Debug)]
pub struct RetryBudget {
    ttl: Duration,
    min_per_sec: u32,
    retry_ratio: f32,
    handle: Arc<Budget>,
}

impl RetryBudget {
    pub fn new(ttl: Duration, min_per_sec: u32, retry_ratio: f32) -> Self {
        let handle = Budget::new(ttl, min_per_sec, retry_ratio);
        Self {
            ttl,
            min_per_sec,
            retry_ratio,
            handle: Arc::new(handle),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn min_per_sec(&self) -> u32 {
        self.min_per_sec
    }

    pub fn retry_ratio(&self) -> f32 {
        self.retry_ratio
    }

    pub fn handle(&self) -> Arc<Budget> {
        Arc::clone(&self.handle)
    }
}

impl Clone for RetryBudget {
    fn clone(&self) -> Self {
        Self {
            ttl: self.ttl,
            min_per_sec: self.min_per_sec,
            retry_ratio: self.retry_ratio,
            handle: Arc::clone(&self.handle),
        }
    }
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self::new(Duration::from_secs(10), 10, 0.2)
    }
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    backoff: RetryBackoff,
    budget: RetryBudget,
}

impl RetryPolicy {
    pub fn new(max_attempts: NonZeroU32, backoff: RetryBackoff, budget: RetryBudget) -> Self {
        Self {
            max_attempts,
            backoff,
            budget,
        }
    }

    pub fn max_attempts(&self) -> NonZeroU32 {
        self.max_attempts
    }

    pub fn backoff(&self) -> &RetryBackoff {
        &self.backoff
    }

    pub fn budget(&self) -> &RetryBudget {
        &self.budget
    }

    pub(crate) fn backoff_delay(&self, attempt: u32) -> Duration {
        self.backoff.delay_for_attempt(attempt)
    }

    pub(crate) fn backoff_jitter(&self) -> f64 {
        self.backoff.jitter
    }

    pub(crate) fn budget_handle(&self) -> Arc<Budget> {
        self.budget.handle()
    }

    pub(crate) fn is_method_retryable(&self, method: &Method) -> bool {
        matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: NonZeroU32::new(3).expect("static non-zero"),
            backoff: RetryBackoff::default(),
            budget: RetryBudget::default(),
        }
    }
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

#[derive(Clone, Debug)]
struct SecretEntry {
    value: SecretValue,
    expires_at: Instant,
}

impl SecretEntry {
    fn new(value: SecretValue, ttl: Duration) -> Self {
        let now = Instant::now();
        let expires_at = now.checked_add(ttl).unwrap_or(now);

        Self { value, expires_at }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// In-memory cache used to store client registrations.
pub type ClientsCache = HashMap<ClientId, ClientMetadata>;

/// In-memory routing table mapping proxy routes to upstream targets.
pub type RoutingTable = HashMap<RouteId, RouteTarget>;

/// In-memory secret store shared across the application.
#[derive(Clone, Debug)]
pub struct SecretsStore {
    entries: HashMap<SecretName, SecretEntry>,
    default_ttl: Duration,
}

impl SecretsStore {
    /// Creates a new [`SecretsStore`] with the provided default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            default_ttl,
        }
    }

    /// Returns the default TTL applied to new entries.
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Inserts a secret into the store using the configured default TTL.
    pub fn insert(&mut self, name: SecretName, value: SecretValue) -> Option<SecretValue> {
        self.insert_with_ttl(name, value, self.default_ttl)
    }

    /// Inserts a secret with an explicit TTL overriding the store default.
    pub fn insert_with_ttl(
        &mut self,
        name: SecretName,
        value: SecretValue,
        ttl: Duration,
    ) -> Option<SecretValue> {
        let entry = SecretEntry::new(value, ttl);
        self.entries
            .insert(name, entry)
            .map(|previous| previous.value)
    }

    /// Retrieves a secret by name, removing it if the TTL has elapsed.
    pub fn get(&mut self, name: &str) -> Option<&SecretValue> {
        let now = Instant::now();
        let should_remove = match self.entries.get(name) {
            Some(entry) => entry.is_expired(now),
            None => return None,
        };

        if should_remove {
            self.entries.remove(name);
            return None;
        }

        self.entries.get(name).map(|entry| &entry.value)
    }

    /// Returns the list of active secret identifiers, purging expired entries.
    pub fn keys(&mut self) -> Vec<SecretName> {
        self.purge_expired();
        self.entries.keys().cloned().collect()
    }

    /// Removes any entries whose TTL has elapsed.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| !entry.is_expired(now));
    }
}

impl Default for SecretsStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecretsStore {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "SecretsStore cannot be serialized; persist secrets in a dedicated vault",
        ))
    }
}

/// Shared handle to the client cache protected by an asynchronous lock.
pub type SharedClientsCache = Arc<RwLock<ClientsCache>>;

/// Shared handle to the routing table protected by an asynchronous lock.
pub type SharedRoutingTable = Arc<RwLock<RoutingTable>>;

/// Shared handle to the secret store protected by an asynchronous lock.
pub type SharedSecretsStore = Arc<RwLock<SecretsStore>>;

/// Configuration toggles governing how sensitive data is logged.
#[derive(Clone, Debug, Default)]
pub struct SensitiveLoggingConfig {
    log_sensitive_headers: bool,
    redact_sensitive_queries: bool,
}

impl SensitiveLoggingConfig {
    /// Returns true when sensitive headers should be logged verbatim.
    pub fn log_sensitive_headers(&self) -> bool {
        self.log_sensitive_headers
    }

    /// Returns true when redaction should be disabled for sensitive queries.
    ///
    /// When this value is `false` (the default), DRM-related routes will have
    /// their sensitive query parameters redacted from trace output.
    pub fn redact_sensitive_queries(&self) -> bool {
        self.redact_sensitive_queries
    }

    pub fn with_log_sensitive_headers(mut self, enabled: bool) -> Self {
        self.log_sensitive_headers = enabled;
        self
    }

    pub fn with_redact_sensitive_queries(mut self, disabled: bool) -> Self {
        self.redact_sensitive_queries = disabled;
        self
    }
}

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
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    request_timeout: Duration,
    response_buffer_bytes: usize,
    allowlist: DirectStreamAllowlist,
    retry: RetryPolicy,
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

    pub fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }

    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
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

    pub fn retry(&self) -> &RetryPolicy {
        &self.retry
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
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            request_timeout: Self::default_request_timeout(),
            response_buffer_bytes: Self::DEFAULT_RESPONSE_BUFFER_BYTES,
            allowlist: DirectStreamAllowlist::default(),
            retry: RetryPolicy::default(),
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::DirectStreamConfig> for DirectStreamSettings {
    fn from(value: crate::config::DirectStreamConfig) -> Self {
        Self {
            proxy_url: value.proxy_url,
            api_password: value.api_password,
            connect_timeout: value.connect_timeout,
            read_timeout: value.read_timeout,
            request_timeout: value.request_timeout,
            response_buffer_bytes: value.response_buffer_bytes,
            allowlist: value.allowlist.into(),
            retry: value.retry.into(),
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::RetryConfig> for RetryPolicy {
    fn from(value: crate::config::RetryConfig) -> Self {
        Self::new(
            value.max_attempts,
            value.backoff.into(),
            value.budget.into(),
        )
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::HeaderPolicyConfig> for HeaderPolicy {
    fn from(value: crate::config::HeaderPolicyConfig) -> Self {
        Self::new(
            value
                .allow
                .into_iter()
                .map(|name| name.as_str().to_string())
                .collect(),
            value
                .deny
                .into_iter()
                .map(|name| name.as_str().to_string())
                .collect(),
            value.x_forwarded_for.into(),
        )
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::XForwardedForConfig> for XForwardedFor {
    fn from(value: crate::config::XForwardedForConfig) -> Self {
        match value {
            crate::config::XForwardedForConfig::Append => XForwardedFor::Append,
            crate::config::XForwardedForConfig::Replace => XForwardedFor::Replace,
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::RetryBackoffConfig> for RetryBackoff {
    fn from(value: crate::config::RetryBackoffConfig) -> Self {
        Self {
            initial_delay: value.initial_delay,
            max_delay: value.max_delay,
            multiplier: value.multiplier,
            jitter: value.jitter,
        }
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::RetryBudgetConfig> for RetryBudget {
    fn from(value: crate::config::RetryBudgetConfig) -> Self {
        RetryBudget::new(value.ttl, value.min_per_sec, value.retry_ratio)
    }
}

#[cfg(feature = "config-loader")]
impl From<crate::config::SensitiveLoggingConfig> for SensitiveLoggingConfig {
    fn from(value: crate::config::SensitiveLoggingConfig) -> Self {
        Self {
            log_sensitive_headers: value.log_sensitive_headers,
            redact_sensitive_queries: value.redact_sensitive_queries,
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
    let mut builder = Client::builder().redirect(RedirectPolicy::none());

    let resolver = Arc::new(crate::stream::direct::RestrictedDnsResolver::new());

    builder = builder.dns_resolver(resolver);

    if let Some(connect) = settings.connect_timeout() {
        builder = builder.connect_timeout(connect);
    }

    let read_timeout = settings
        .read_timeout()
        .unwrap_or(settings.request_timeout());
    builder = builder.timeout(read_timeout);

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
    sensitive_logging: SensitiveLoggingConfig,
    cors: Option<CorsConfig>,
}

/// Shared handle that allows the application state to be swapped atomically at runtime.
#[derive(Clone, Debug)]
pub struct SharedAppState {
    inner: Arc<ArcSwap<AppState>>,
}

impl SharedAppState {
    /// Wraps the provided [`AppState`] in a reloadable handle.
    pub fn new(state: AppState) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(state)),
        }
    }

    /// Returns a clone of the current [`AppState`] snapshot.
    pub fn snapshot(&self) -> Arc<AppState> {
        self.inner.load_full()
    }

    /// Replaces the current [`AppState`] with the provided instance.
    pub fn replace(&self, next: AppState) {
        self.inner.store(Arc::new(next));
    }

    /// Executes the provided closure with a reference to the current [`AppState`].
    pub fn with_current<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&AppState) -> R,
    {
        let snapshot = self.inner.load();
        f(&snapshot)
    }
}

impl From<AppState> for SharedAppState {
    fn from(value: AppState) -> Self {
        Self::new(value)
    }
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
            sensitive_logging: SensitiveLoggingConfig::default(),
            cors: None,
        }
    }

    /// Constructs an [`AppState`] from the provided configuration.
    pub fn from_config(config: &Config) -> Result<Self> {
        let mut routing_table = HashMap::new();
        let mut route_definitions = Vec::with_capacity(config.routes.len());
        let socks5_override = env::var("SPROX_PROXY_URL")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());

        for route in &config.routes {
            let socks5 = if let Some(override_address) = socks5_override.as_ref() {
                Some(Socks5Proxy {
                    address: override_address.clone(),
                    username: route.upstream.socks5.username.clone(),
                    password: route.upstream.socks5.password.clone(),
                })
            } else if route.upstream.socks5.enabled {
                route
                    .upstream
                    .socks5
                    .address
                    .as_ref()
                    .map(|address| Socks5Proxy {
                        address: address.clone(),
                        username: route.upstream.socks5.username.clone(),
                        password: route.upstream.socks5.password.clone(),
                    })
            } else {
                None
            };

            let hls = route.hls.as_ref().map(|hls| HlsOptions {
                enabled: hls.enabled,
                rewrite_playlist_urls: hls.rewrite_playlist_urls,
                base_url: hls.base_url.clone(),
                allow_insecure_segments: hls.allow_insecure_segments,
            });

            let target = RouteTarget {
                upstream: route.upstream.origin.to_string(),
                connect_timeout: route.upstream.connect_timeout,
                read_timeout: route.upstream.read_timeout,
                request_timeout: route.upstream.request_timeout,
                tls_insecure_skip_verify: route.upstream.tls.insecure_skip_verify,
                socks5,
                hls,
                retry: route.upstream.retry.clone().into(),
                header_policy: route.upstream.header_policy.clone().into(),
            };

            routing_table.insert(route.id.clone(), target);

            let port_range = PortRange::new(route.listen.port, route.listen.port)?;
            route_definitions.push(RouteDefinition {
                id: route.id.clone(),
                host_patterns: route.host_patterns.clone(),
                protocols: route.protocols.clone(),
                ports: vec![port_range],
            });
        }

        let routing_engine = Arc::new(RoutingEngine::new(route_definitions)?);

        let mut state = AppState::with_components(
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(routing_table)),
            Arc::new(RwLock::new(SecretsStore::new(config.secrets.default_ttl))),
            routing_engine,
        );

        if let Some(direct_stream) = config.direct_stream.clone() {
            state = state.with_direct_stream_settings(direct_stream.into());
        }

        state = state.with_sensitive_logging(config.sensitive_logging.clone().into());
        state = state.with_cors(config.cors.clone());

        Ok(state)
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

    /// Returns the configured logging redaction settings.
    pub fn sensitive_logging(&self) -> &SensitiveLoggingConfig {
        &self.sensitive_logging
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

    /// Applies sensitive logging configuration.
    pub fn with_sensitive_logging(mut self, config: SensitiveLoggingConfig) -> Self {
        self.sensitive_logging = config;
        self
    }

    /// Applies CORS configuration to the state.
    pub fn with_cors(mut self, cors: Option<CorsConfig>) -> Self {
        self.cors = cors;
        self
    }

    /// Returns the configured CORS settings, when available.
    pub fn cors_config(&self) -> Option<&CorsConfig> {
        self.cors.as_ref()
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
            secrets: Arc::new(RwLock::new(SecretsStore::default())),
            rate_limit: RateLimitConfig::default(),
            routing_engine: Arc::new(
                RoutingEngine::new(Vec::new())
                    .expect("routing engine should compile for empty routes"),
            ),
            http_client: Client::new(),
            direct_stream: None,
            sensitive_logging: SensitiveLoggingConfig::default(),
            cors: None,
        }
    }
}

/// Reloads application state from the provided configuration path.
pub fn reload_app_state_from_path(path: impl AsRef<Path>, state: &SharedAppState) -> Result<()> {
    let path = path.as_ref();
    let config = Config::load_from_path(path)
        .with_context(|| format!("failed to load configuration from `{}`", path.display()))?;
    let next_state = AppState::from_config(&config).with_context(|| {
        format!(
            "failed to rebuild application state from `{}`",
            path.display()
        )
    })?;
    state.replace(next_state);
    Ok(())
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
                retry: RetryPolicy::default(),
                header_policy: HeaderPolicy::default(),
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
        let mut secrets = secrets_handle.write().await;
        assert_eq!(
            secrets.get("api_key").map(|secret| secret.value.as_str()),
            Some("super-secret"),
        );
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
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(20)),
            request_timeout: Duration::from_secs(10),
            response_buffer_bytes: 131_072,
            allowlist: DirectStreamAllowlist::default(),
            retry: RetryPolicy::default(),
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
