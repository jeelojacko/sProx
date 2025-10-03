use super::*;

use std::{
    collections::HashMap, convert::Infallible, env, io, net::SocketAddr, sync::Arc, time::Duration,
};

use axum::{
    body::{Body as AxumBody, Bytes as AxumBytes},
    extract::State as AxumState,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode as AxumStatusCode, Uri},
    response::Response as AxumResponse,
    routing::get,
    Router,
};
use futures::stream;
use reqwest::{header as reqwest_header, StatusCode};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex, Notify},
    task::JoinHandle,
};
use url::Url;

use sProx::config::{
    Config, DirectStreamAllowRule, DirectStreamAllowlist, DirectStreamConfig, DirectStreamScheme,
    HeaderPolicyConfig, ListenerConfig, RedirectConfig, RetryConfig, RouteConfig, SecretsConfig,
    SensitiveLoggingConfig, Socks5Config, TlsConfig, UpstreamConfig, XForwardedForConfig,
};
use sProx::state::{AppState, DirectStreamSettings, SharedAppState};
use sProx::stream::direct;

#[cfg(feature = "telemetry")]
fn ensure_telemetry_initialized() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        sProx::init().expect("telemetry initialization should succeed");
    });
}

#[cfg(feature = "telemetry")]
fn metric_value(metrics: &str, metric: &str, label_fragment: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        if line.starts_with(metric) && line.contains(label_fragment) {
            line.split_whitespace().last()?.parse().ok()
        } else {
            None
        }
    })
}

#[derive(Clone)]
struct RouteProxyUpstreamState {
    log: Arc<Mutex<Vec<RecordedRequest>>>,
    response_headers: Arc<Vec<(String, String)>>,
}

impl RouteProxyUpstreamState {
    fn new(response_headers: Vec<(String, String)>) -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            response_headers: Arc::new(response_headers),
        }
    }

    fn log(&self) -> Arc<Mutex<Vec<RecordedRequest>>> {
        Arc::clone(&self.log)
    }

    fn response_headers(&self) -> Arc<Vec<(String, String)>> {
        Arc::clone(&self.response_headers)
    }
}

struct RouteProxyContext {
    proxy_addr: SocketAddr,
    upstream_log: Arc<Mutex<Vec<RecordedRequest>>>,
    proxy_shutdown: Option<oneshot::Sender<()>>,
    upstream_shutdown: Option<oneshot::Sender<()>>,
    proxy_handle: JoinHandle<()>,
    upstream_handle: JoinHandle<()>,
}

impl RouteProxyContext {
    fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    fn upstream_log(&self) -> Arc<Mutex<Vec<RecordedRequest>>> {
        Arc::clone(&self.upstream_log)
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.proxy_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.upstream_shutdown.take() {
            let _ = tx.send(());
        }

        let _ = self.proxy_handle.await;
        let _ = self.upstream_handle.await;
    }
}

async fn spawn_route_proxy_context(
    header_policy: HeaderPolicyConfig,
    response_headers: Vec<(String, String)>,
) -> RouteProxyContext {
    let upstream_state = RouteProxyUpstreamState::new(response_headers);
    let upstream_log = upstream_state.log();
    let upstream_router = Router::new()
        .route("/asset", get(route_upstream_handler))
        .with_state(upstream_state.clone());

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream should expose local address");
    let (upstream_shutdown, upstream_rx) = oneshot::channel();
    let upstream_handle = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_router)
            .with_graceful_shutdown(async {
                let _ = upstream_rx.await;
            })
            .await;
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("proxy should bind");
    let proxy_addr = proxy_listener
        .local_addr()
        .expect("proxy should expose local address");

    let config = Config {
        direct_stream: None,
        routes: vec![RouteConfig {
            id: "proxy-route".into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: proxy_addr.port(),
                tls: None,
            },
            host_patterns: vec!["127.0.0.1".into()],
            protocols: Vec::new(),
            upstream: UpstreamConfig {
                origin: Url::parse(&format!("http://{upstream_addr}"))
                    .expect("origin should parse"),
                connect_timeout: Some(Duration::from_secs(1)),
                read_timeout: Some(Duration::from_secs(1)),
                request_timeout: Some(Duration::from_secs(1)),
                tls: TlsConfig {
                    enabled: false,
                    sni_hostname: None,
                    insecure_skip_verify: false,
                },
                socks5: Socks5Config {
                    enabled: false,
                    address: None,
                    username: None,
                    password: None,
                },
                retry: RetryConfig::default(),
                header_policy,
                redirect: RedirectConfig::default(),
            },
            hls: None,
        }],
        secrets: SecretsConfig::default(),
        sensitive_logging: SensitiveLoggingConfig::default(),
        cors: None,
    };

    let state = AppState::from_config(&config).expect("app state should build");
    let router = app::build_router(SharedAppState::new(state));
    let (proxy_shutdown, proxy_rx) = oneshot::channel();
    let proxy_handle = tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, router)
            .with_graceful_shutdown(async {
                let _ = proxy_rx.await;
            })
            .await;
    });

    RouteProxyContext {
        proxy_addr,
        upstream_log,
        proxy_shutdown: Some(proxy_shutdown),
        upstream_shutdown: Some(upstream_shutdown),
        proxy_handle,
        upstream_handle,
    }
}

async fn route_upstream_handler(
    AxumState(state): AxumState<RouteProxyUpstreamState>,
    method: Method,
    headers: HeaderMap,
) -> AxumResponse {
    let mut recorded_headers = Vec::new();
    for (name, value) in headers.iter() {
        if let Ok(value) = value.to_str() {
            recorded_headers.push((name.as_str().to_string(), value.to_string()));
        }
    }
    state.log.lock().await.push(RecordedRequest {
        method,
        headers: recorded_headers,
    });

    let mut builder = AxumResponse::builder().status(AxumStatusCode::OK);
    for (name, value) in state.response_headers().iter() {
        builder = builder.header(name, value);
    }

    builder
        .body(AxumBody::empty())
        .expect("response should build")
}

#[tokio::test]
async fn health_endpoint_returns_success() {
    let config = Config {
        direct_stream: None,
        routes: vec![RouteConfig {
            id: "health-check".into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                tls: None,
            },
            host_patterns: Vec::new(),
            protocols: Vec::new(),
            upstream: UpstreamConfig {
                origin: Url::parse("http://127.0.0.1:65535").expect("url should parse"),
                connect_timeout: Some(Duration::from_secs(1)),
                read_timeout: Some(Duration::from_secs(1)),
                request_timeout: Some(Duration::from_secs(1)),
                tls: TlsConfig {
                    enabled: false,
                    sni_hostname: None,
                    insecure_skip_verify: false,
                },
                socks5: Socks5Config {
                    enabled: false,
                    address: None,
                    username: None,
                    password: None,
                },
                retry: RetryConfig::default(),
                header_policy: HeaderPolicyConfig::default(),
                redirect: RedirectConfig::default(),
            },
            hls: None,
        }],
        secrets: SecretsConfig::default(),
        sensitive_logging: SensitiveLoggingConfig::default(),
        cors: None,
    };

    let state = AppState::from_config(&config).expect("app state should build");
    let router = app::build_router(SharedAppState::new(state));

    let listener_cfg = primary_listener(&config).expect("listener should be available");
    let addr = resolve_listener_addr(listener_cfg).expect("listener address should resolve");

    let listener = TcpListener::bind(addr)
        .await
        .expect("listener should bind successfully");
    let local_addr = listener
        .local_addr()
        .expect("listener should expose local address");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = axum::serve(listener, router).with_graceful_shutdown(async {
        let _ = shutdown_rx.await;
    });
    let server_handle = tokio::spawn(async move { server.await });

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{local_addr}/health"))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let _ = shutdown_tx.send(());

    server_handle
        .await
        .expect("server task should join")
        .expect("server should shut down cleanly");
}

#[cfg(feature = "telemetry")]
#[tokio::test]
async fn prometheus_metrics_report_proxy_counters() {
    ensure_telemetry_initialized();

    let response_headers = vec![
        ("content-length".to_string(), "13".to_string()),
        ("etag".to_string(), "test".to_string()),
    ];
    let context = spawn_route_proxy_context(HeaderPolicyConfig::default(), response_headers).await;
    let _loopback = sProx::proxy::ssrf::allow_loopback_for_tests();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/asset", context.proxy_addr()))
        .send()
        .await
        .expect("proxy request should succeed");
    assert_eq!(response.status(), StatusCode::OK);

    let metrics = client
        .get(format!("http://{}/metrics", context.proxy_addr()))
        .send()
        .await
        .expect("metrics request should succeed")
        .text()
        .await
        .expect("metrics body should decode");

    let requests = metric_value(&metrics, "sprox_requests_total", "route=\"proxy-route\"")
        .expect("request counter should be present");
    assert!(requests >= 1.0, "request counter should increment");

    let latency_count = metric_value(
        &metrics,
        "sprox_upstream_latency_seconds_count",
        "route=\"proxy-route\"",
    )
    .expect("latency count should be present");
    assert!(latency_count >= 1.0, "latency count should increment");

    if let Some(bytes) = metric_value(
        &metrics,
        "sprox_bytes_streamed_total",
        "route=\"proxy-route\"",
    ) {
        assert!(
            bytes >= 0.0,
            "byte counter should be present even for empty bodies"
        );
    } else {
        panic!("byte counter should be present");
    }

    context.shutdown().await;
}

fn socks5_override_test_config() -> Config {
    let route_template =
        |id: &str, socks5_enabled: bool, socks5_address: Option<&str>| RouteConfig {
            id: id.into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                tls: None,
            },
            host_patterns: Vec::new(),
            protocols: Vec::new(),
            upstream: UpstreamConfig {
                origin: Url::parse("http://127.0.0.1:65535").expect("url should parse"),
                connect_timeout: Some(Duration::from_secs(1)),
                read_timeout: Some(Duration::from_secs(1)),
                request_timeout: Some(Duration::from_secs(1)),
                tls: TlsConfig {
                    enabled: false,
                    sni_hostname: None,
                    insecure_skip_verify: false,
                },
                socks5: Socks5Config {
                    enabled: socks5_enabled,
                    address: socks5_address.map(|value| value.to_string()),
                    username: Some("user".into()),
                    password: Some("secret".into()),
                },
                retry: RetryConfig::default(),
                header_policy: HeaderPolicyConfig::default(),
                redirect: RedirectConfig::default(),
            },
            hls: None,
        };

    Config {
        direct_stream: None,
        routes: vec![
            route_template("disabled-proxy", false, None),
            route_template("enabled-proxy", true, Some("10.0.0.1:9000")),
        ],
        secrets: SecretsConfig::default(),
        sensitive_logging: SensitiveLoggingConfig::default(),
        cors: None,
    }
}

#[tokio::test]
async fn socks5_proxy_env_override_applies_to_all_routes() {
    env::remove_var("SPROX_PROXY_URL");
    let proxy_address = "127.0.0.1:1081";
    env::set_var("SPROX_PROXY_URL", proxy_address);

    let config = socks5_override_test_config();
    let state = AppState::from_config(&config).expect("app state should build");
    let routing_table = state.routing_table();
    let table = routing_table.read().await;

    for target in table.values() {
        let socks5 = target
            .socks5
            .as_ref()
            .expect("proxy should be enabled by override");
        assert_eq!(socks5.address, proxy_address);
        assert_eq!(socks5.username.as_deref(), Some("user"));
        assert_eq!(socks5.password.as_deref(), Some("secret"));
        assert!(
            target.socks5_overridden,
            "override marker should be set when proxy env var is provided"
        );
    }

    env::remove_var("SPROX_PROXY_URL");
}

#[test]
fn socks5_proxy_override_emits_startup_log() {
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct BufferWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
        type Writer = BufferGuard;

        fn make_writer(&'a self) -> Self::Writer {
            BufferGuard {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct BufferGuard {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BufferGuard {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut output = self.buffer.lock().expect("buffer lock should not poison");
            output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    env::remove_var("SPROX_PROXY_URL");
    let proxy_address = "127.0.0.1:1081";
    env::set_var("SPROX_PROXY_URL", proxy_address);

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = BufferWriter {
        buffer: Arc::clone(&buffer),
    };

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .json()
        .with_writer(writer)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let config = socks5_override_test_config();
        AppState::from_config(&config).expect("app state should build");
    });

    env::remove_var("SPROX_PROXY_URL");

    let contents = {
        let buffer = buffer.lock().expect("buffer lock should not poison");
        String::from_utf8(buffer.clone()).expect("log buffer should be valid UTF-8")
    };

    assert!(
        !contents.is_empty(),
        "expected log output when proxy override is set"
    );

    let line = contents
        .lines()
        .find(|line| line.contains("proxy override"))
        .expect("override log should be present");
    let event: serde_json::Value =
        serde_json::from_str(line).expect("log line should be valid JSON");
    let fields = event
        .get("fields")
        .expect("json log should contain fields object");

    assert_eq!(
        fields.get("message").and_then(|value| value.as_str()),
        Some("applying SOCKS5 proxy override from environment")
    );
    assert_eq!(
        fields
            .get("override_target")
            .and_then(|value| value.as_str()),
        Some(proxy_address)
    );
    assert_eq!(
        fields.get("routes").and_then(|value| value.as_u64()),
        Some(2)
    );

    let route_ids = fields
        .get("route_ids")
        .and_then(|value| value.as_str())
        .expect("route ids should be present");
    let mut routes: Vec<_> = route_ids.split(',').collect();
    routes.sort();
    assert_eq!(routes, vec!["disabled-proxy", "enabled-proxy"]);
}

#[tokio::test]
async fn proxy_strips_hop_by_hop_headers_and_normalizes_forwarders() {
    let response_headers = vec![
        ("Connection".to_string(), "keep-alive".to_string()),
        (
            "Proxy-Authenticate".to_string(),
            "Basic realm=\"upstream\"".to_string(),
        ),
        ("Via".to_string(), "1.0 upstream-proxy".to_string()),
        ("X-Upstream-Header".to_string(), "preserved".to_string()),
    ];
    let context = spawn_route_proxy_context(HeaderPolicyConfig::default(), response_headers).await;
    let _loopback = sProx::proxy::ssrf::allow_loopback_for_tests();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/asset", context.proxy_addr()))
        .header("Connection", "keep-alive")
        .header("Proxy-Connection", "close")
        .header("TE", "trailers")
        .header("Trailer", "Expires")
        .header("Via", "1.0 downstream-proxy")
        .header("Authorization", "Bearer very-secret")
        .header("Proxy-Authorization", "Basic dXNlcjpzZWNyZXQ=")
        .header("X-Forwarded-For", "10.0.0.1")
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers();
    assert!(headers.get("connection").is_none());
    assert!(headers.get("proxy-connection").is_none());
    assert!(headers.get("transfer-encoding").is_none());
    assert!(headers.get("te").is_none());
    assert!(headers.get("trailer").is_none());
    assert!(headers.get("proxy-authenticate").is_none());
    assert_eq!(
        headers.get("via").and_then(|value| value.to_str().ok()),
        Some("1.0 upstream-proxy, 1.1 sProx")
    );
    assert_eq!(
        headers
            .get("x-upstream-header")
            .and_then(|value| value.to_str().ok()),
        Some("preserved")
    );

    let log = context.upstream_log();
    let recorded = log.lock().await;
    let request = recorded
        .last()
        .expect("upstream should record at least one request");
    let mut header_map = HashMap::new();
    for (name, value) in &request.headers {
        header_map.insert(name.to_ascii_lowercase(), value.clone());
    }

    assert!(!header_map.contains_key("connection"));
    assert!(!header_map.contains_key("proxy-connection"));
    assert!(!header_map.contains_key("te"));
    assert!(!header_map.contains_key("trailer"));
    assert!(!header_map.contains_key("authorization"));
    assert!(!header_map.contains_key("proxy-authorization"));
    assert_eq!(
        header_map.get("x-forwarded-host"),
        Some(&"127.0.0.1".to_string())
    );
    assert_eq!(
        header_map.get("x-forwarded-for"),
        Some(&"10.0.0.1".to_string())
    );
    assert_eq!(
        header_map.get("via"),
        Some(&"1.0 downstream-proxy, 1.1 sProx".to_string())
    );

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_replaces_x_forwarded_for_when_configured() {
    let policy = HeaderPolicyConfig {
        x_forwarded_for: XForwardedForConfig::Replace,
        ..HeaderPolicyConfig::default()
    };
    let context = spawn_route_proxy_context(policy, Vec::new()).await;
    let _loopback = sProx::proxy::ssrf::allow_loopback_for_tests();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/asset", context.proxy_addr()))
        .header("X-Forwarded-For", "198.18.0.1")
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("via")
            .and_then(|value| value.to_str().ok()),
        Some("1.1 sProx")
    );

    let log = context.upstream_log();
    let recorded = log.lock().await;
    let request = recorded
        .last()
        .expect("upstream should record at least one request");
    let mut header_map = HashMap::new();
    for (name, value) in &request.headers {
        header_map.insert(name.to_ascii_lowercase(), value.clone());
    }

    assert!(!header_map.contains_key("x-forwarded-for"));

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_forwards_authorization_when_allowed() {
    let mut policy = HeaderPolicyConfig::default();
    policy
        .allow
        .push(header::HeaderName::from_static("authorization"));
    let context = spawn_route_proxy_context(policy, Vec::new()).await;
    let _loopback = sProx::proxy::ssrf::allow_loopback_for_tests();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/asset", context.proxy_addr()))
        .header("Authorization", "Bearer delegated-secret")
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let log = context.upstream_log();
    let recorded = log.lock().await;
    let request = recorded
        .last()
        .expect("upstream should record at least one request");
    let mut header_map = HashMap::new();
    for (name, value) in &request.headers {
        header_map.insert(name.to_ascii_lowercase(), value.clone());
    }

    assert_eq!(
        header_map.get("authorization"),
        Some(&"Bearer delegated-secret".to_string())
    );
    assert!(!header_map.contains_key("proxy-authorization"));

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_returns_full_body_and_injects_accept_ranges() {
    let body = b"0123456789abcdef".to_vec();
    let context = spawn_stream_test(body.clone()).await;
    let upstream_log = context.upstream_log();

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes, body);

    assert_eq!(
        headers
            .get("accept-ranges")
            .and_then(|value| value.to_str().ok()),
        Some("bytes")
    );
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .expect("content length should be set");
    assert_eq!(content_length, body.len().to_string());
    assert!(headers.get("x-unwanted").is_none());

    let requests = upstream_log
        .lock()
        .await
        .iter()
        .map(|entry| entry.method.clone())
        .collect::<Vec<_>>();
    assert!(requests.contains(&Method::HEAD));
    assert!(requests.contains(&Method::GET));

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_returns_401_without_authorization_token() {
    let body = b"auth-required".to_vec();
    let context = spawn_stream_test_with_config_and_state_builder(
        body,
        |addr| DirectStreamConfig {
            allowlist: DirectStreamAllowlist {
                rules: vec![DirectStreamAllowRule {
                    domain: addr.ip().to_string(),
                    schemes: vec![DirectStreamScheme::Http],
                    path_globs: vec!["/**".into()],
                }],
            },
            ..DirectStreamConfig::default()
        },
        |state| state.with_api_password(Some("shared-secret".into())),
    )
    .await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_returns_403_for_invalid_authorization_token() {
    let body = b"auth-invalid".to_vec();
    let context = spawn_stream_test_with_config_and_state_builder(
        body,
        |addr| DirectStreamConfig {
            allowlist: DirectStreamAllowlist {
                rules: vec![DirectStreamAllowRule {
                    domain: addr.ip().to_string(),
                    schemes: vec![DirectStreamScheme::Http],
                    path_globs: vec!["/**".into()],
                }],
            },
            ..DirectStreamConfig::default()
        },
        |state| state.with_api_password(Some("shared-secret".into())),
    )
    .await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .header(reqwest_header::AUTHORIZATION, "Bearer wrong-secret")
        .send()
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_supports_open_ended_range_requests() {
    let body = vec![0x5au8; 1_200_000];
    let context = spawn_stream_test(body.clone()).await;
    let upstream_log = context.upstream_log();

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .header(reqwest_header::RANGE, "bytes=0-")
        .send()
        .await
        .expect("range request should succeed");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let headers = response.headers();
    let expected_content_range = format!("bytes 0-{}/{}", body.len() - 1, body.len());
    assert_eq!(
        headers
            .get(reqwest_header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some(expected_content_range.as_str())
    );
    assert_eq!(
        headers
            .get(reqwest_header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok()),
        Some(body.len())
    );
    assert_eq!(
        headers
            .get(reqwest_header::ACCEPT_RANGES)
            .and_then(|value| value.to_str().ok()),
        Some("bytes")
    );

    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes.len(), body.len());
    assert_eq!(bytes, body);

    let log = upstream_log.lock().await;
    for method in [Method::HEAD, Method::GET] {
        let entry = log
            .iter()
            .find(|record| record.method == method)
            .expect("request should be recorded");
        let range_header = entry
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("range"))
            .map(|(_, value)| value.as_str());
        assert_eq!(range_header, Some("bytes=0-"));
    }

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_supports_large_offset_range_requests() {
    let body = vec![0xabu8; 1_500_000];
    let offset = 1_000_000usize;
    let context = spawn_stream_test(body.clone()).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .header(reqwest_header::RANGE, "bytes=1000000-")
        .send()
        .await
        .expect("range request should succeed");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let headers = response.headers();
    let expected_content_range = format!("bytes {}-{}/{}", offset, body.len() - 1, body.len());
    assert_eq!(
        headers
            .get(reqwest_header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some(expected_content_range.as_str())
    );
    let expected_length = body.len() - offset;
    assert_eq!(
        headers
            .get(reqwest_header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok()),
        Some(expected_length)
    );
    assert_eq!(
        headers
            .get(reqwest_header::ACCEPT_RANGES)
            .and_then(|value| value.to_str().ok()),
        Some("bytes")
    );

    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes.len(), expected_length);
    assert_eq!(bytes.as_ref(), &body[offset..]);

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_enforces_concurrency_limit() {
    let body = vec![0x42u8; 16 * 1024];
    let context = spawn_stream_test(body).await;

    let blocker = Arc::new(Notify::new());
    let upstream_state = context.upstream_state();
    upstream_state
        .set_stream_blocker(Some(blocker.clone()))
        .await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();

    let concurrency_limit = direct::direct_stream_concurrency_limit_for_tests();
    let mut stream_handles = Vec::with_capacity(concurrency_limit);
    for _ in 0..concurrency_limit {
        let url = proxy_url.clone();
        let client = client.clone();
        stream_handles.push(tokio::spawn(async move {
            let response = client
                .get(url)
                .send()
                .await
                .expect("stream request should start");
            let status = response.status();
            let _ = response
                .bytes()
                .await
                .expect("streaming response should complete once unblocked");
            status
        }));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let overflow = client
        .get(proxy_url.clone())
        .send()
        .await
        .expect("concurrency probe should complete");
    assert_eq!(overflow.status(), StatusCode::TOO_MANY_REQUESTS);

    drop(overflow);

    blocker.notify_waiters();
    upstream_state.set_stream_blocker(None).await;

    let mut success = 0usize;
    let mut rejected = 0usize;
    for handle in stream_handles {
        match handle
            .await
            .expect("stream task should complete without panicking")
        {
            StatusCode::OK => success += 1,
            StatusCode::TOO_MANY_REQUESTS => rejected += 1,
            other => panic!("unexpected status from stream task: {other}"),
        }
    }

    assert!(
        success > 0,
        "expected at least one stream to acquire a permit"
    );
    assert_eq!(success + rejected, concurrency_limit);

    let recovery = client
        .get(proxy_url.clone())
        .send()
        .await
        .expect("recovery request should complete");
    assert_eq!(recovery.status(), StatusCode::OK);
    let _ = recovery.bytes().await.expect("recovery body should stream");

    context.shutdown().await;
}

#[cfg(feature = "telemetry")]
#[tokio::test]
async fn prometheus_metrics_report_direct_stream_counters() {
    ensure_telemetry_initialized();

    let body = b"stream-metrics".to_vec();
    let context = spawn_stream_test(body.clone()).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("direct stream request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = client
        .get(format!("http://{}/metrics", context.app_addr()))
        .send()
        .await
        .expect("metrics request should succeed")
        .text()
        .await
        .expect("metrics body should decode");

    let requests = metric_value(&metrics, "sprox_requests_total", "route=\"direct_stream\"")
        .expect("request counter should be present");
    assert!(requests >= 1.0, "request counter should increment");

    let proxy_requests = metric_value(
        &metrics,
        "sprox_proxy_stream_requests_total",
        "route=\"direct_stream\",status=\"200\"",
    )
    .expect("proxy stream requests counter should be present");
    assert!(
        proxy_requests >= 1.0,
        "proxy stream requests should increment"
    );

    let upstream_status = metric_value(
        &metrics,
        "sprox_proxy_stream_upstream_status_total",
        "route=\"direct_stream\",status=\"200\"",
    )
    .expect("upstream status counter should be present");
    assert!(
        upstream_status >= 1.0,
        "upstream status counter should increment"
    );

    let latency_count = metric_value(
        &metrics,
        "sprox_upstream_latency_seconds_count",
        "route=\"direct_stream\"",
    )
    .expect("latency count should be present");
    assert!(latency_count >= 1.0, "latency count should increment");

    let bytes = metric_value(
        &metrics,
        "sprox_bytes_streamed_total",
        "route=\"direct_stream\"",
    )
    .expect("byte counter should be present");
    assert!(
        bytes >= body.len() as f64,
        "byte counter should track streamed size"
    );

    let proxy_bytes = metric_value(
        &metrics,
        "sprox_proxy_stream_bytes_out_total",
        "route=\"direct_stream\",status=\"200\"",
    )
    .expect("proxy stream byte counter should be present");
    assert!(
        proxy_bytes >= body.len() as f64,
        "proxy stream byte counter should track streamed size"
    );

    let first_byte_count = metric_value(
        &metrics,
        "sprox_proxy_stream_first_byte_latency_seconds_count",
        "route=\"direct_stream\",status=\"200\"",
    )
    .expect("first byte histogram count should be present");
    assert!(
        first_byte_count >= 1.0,
        "first byte latency should record samples"
    );

    let duration_count = metric_value(
        &metrics,
        "sprox_proxy_stream_duration_seconds_count",
        "route=\"direct_stream\",status=\"200\"",
    )
    .expect("duration histogram count should be present");
    assert!(
        duration_count >= 1.0,
        "duration histogram should record samples"
    );

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_retries_transient_failures() {
    let body = b"abcdef".to_vec();
    let context = spawn_stream_test(body.clone()).await;
    context.upstream_state().set_transient_failures(2).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should succeed despite transient failures");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes, body);

    let upstream_log = context.upstream_log();
    let log = upstream_log.lock().await;
    let head_attempts = log
        .iter()
        .filter(|entry| entry.method == Method::HEAD)
        .count();
    let get_attempts = log
        .iter()
        .filter(|entry| entry.method == Method::GET)
        .count();
    assert_eq!(head_attempts, 1);
    assert_eq!(get_attempts, 3);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_reports_retry_budget_exhaustion() {
    let body = b"failure".to_vec();
    let context = spawn_stream_test_with_config_builder(body.clone(), |addr| {
        let domain = addr.ip().to_string();
        let mut retry = RetryConfig::default();
        retry.budget.min_per_sec = 0;
        retry.budget.retry_ratio = 0.0;

        DirectStreamConfig {
            allowlist: DirectStreamAllowlist {
                rules: vec![DirectStreamAllowRule {
                    domain,
                    schemes: vec![DirectStreamScheme::Http],
                    path_globs: vec!["/**".into()],
                }],
            },
            retry,
            ..Default::default()
        }
    })
    .await;
    context.upstream_state().set_transient_failures(1).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let message = response.text().await.expect("body should decode");
    assert!(message.contains("retry budget exhausted"));

    let upstream_log = context.upstream_log();
    let log = upstream_log.lock().await;
    let head_attempts = log
        .iter()
        .filter(|entry| entry.method == Method::HEAD)
        .count();
    let get_attempts = log
        .iter()
        .filter(|entry| entry.method == Method::GET)
        .count();
    assert_eq!(head_attempts, 1);
    assert_eq!(get_attempts, 1, "budget should prevent retry attempts");

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_respects_range_and_header_overrides() {
    let body = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    let context = spawn_stream_test(body.clone()).await;
    let upstream_log = context.upstream_log();

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()))
        .append_pair("h_referer", "https://player.example.com/watch");

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .header("range", "bytes=5-9")
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let headers = response.headers().clone();
    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes, body[5..=9]);

    assert_eq!(
        headers
            .get("content-range")
            .and_then(|value| value.to_str().ok()),
        Some("bytes 5-9/26")
    );
    assert_eq!(
        headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );

    let requests = upstream_log.lock().await.clone();
    let get_request = requests
        .into_iter()
        .rev()
        .find(|entry| entry.method == Method::GET)
        .expect("upstream should record GET");

    let header_map = get_request.headers.into_iter().collect::<HashMap<_, _>>();
    assert_eq!(
        header_map.get("range").map(String::as_str),
        Some("bytes=5-9")
    );
    assert_eq!(
        header_map.get("referer").map(String::as_str),
        Some("https://player.example.com/watch")
    );

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_handles_if_range_semantics() {
    let body = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    let context = spawn_stream_test(body.clone()).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let initial = client
        .get(proxy_url.clone())
        .send()
        .await
        .expect("initial request should succeed");

    assert_eq!(initial.status(), StatusCode::OK);
    let initial_headers = initial.headers().clone();
    let etag = initial_headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .expect("upstream should include etag")
        .to_string();
    let last_modified = initial_headers
        .get("last-modified")
        .and_then(|value| value.to_str().ok())
        .expect("upstream should include last-modified")
        .to_string();
    let initial_bytes = initial.bytes().await.expect("initial body should stream");
    assert_eq!(initial_bytes, body);

    let etag_response = client
        .get(proxy_url.clone())
        .header("range", "bytes=5-9")
        .header("if-range", etag.clone())
        .send()
        .await
        .expect("etag range request should succeed");
    assert_eq!(etag_response.status(), StatusCode::PARTIAL_CONTENT);
    let etag_headers = etag_response.headers().clone();
    let expected_etag_range = format!("bytes 5-9/{}", body.len());
    assert_eq!(
        etag_headers
            .get("content-range")
            .and_then(|value| value.to_str().ok()),
        Some(expected_etag_range.as_str())
    );
    assert_eq!(
        etag_headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        etag_headers
            .get("etag")
            .and_then(|value| value.to_str().ok()),
        Some(etag.as_str())
    );
    assert_eq!(
        etag_headers
            .get("last-modified")
            .and_then(|value| value.to_str().ok()),
        Some(last_modified.as_str())
    );
    let etag_bytes = etag_response
        .bytes()
        .await
        .expect("etag range body should stream");
    assert_eq!(etag_bytes, body[5..=9]);

    let last_modified_response = client
        .get(proxy_url.clone())
        .header("range", "bytes=10-14")
        .header("if-range", last_modified.clone())
        .send()
        .await
        .expect("last-modified range request should succeed");
    assert_eq!(last_modified_response.status(), StatusCode::PARTIAL_CONTENT);
    let last_headers = last_modified_response.headers().clone();
    let expected_last_range = format!("bytes 10-14/{}", body.len());
    assert_eq!(
        last_headers
            .get("content-range")
            .and_then(|value| value.to_str().ok()),
        Some(expected_last_range.as_str())
    );
    let last_bytes = last_modified_response
        .bytes()
        .await
        .expect("last-modified range body should stream");
    assert_eq!(last_bytes, body[10..=14]);

    let mismatch_response = client
        .get(proxy_url)
        .header("range", "bytes=15-19")
        .header("if-range", "invalid-token")
        .send()
        .await
        .expect("mismatch range request should succeed");
    assert_eq!(mismatch_response.status(), StatusCode::OK);
    assert!(mismatch_response.headers().get("content-range").is_none());
    let mismatch_bytes = mismatch_response
        .bytes()
        .await
        .expect("mismatch range body should stream");
    assert_eq!(mismatch_bytes, body);

    context.shutdown().await;
}

#[tokio::test]
async fn proxy_stream_streams_chunked_responses() {
    let body = b"chunked-response-body-0123456789".to_vec();
    let context = spawn_stream_test(body.clone()).await;
    let upstream_state = context.upstream_state();
    upstream_state.set_chunked(true).await;
    upstream_state.set_chunk_size(3).await;

    let mut proxy_url = Url::parse(&format!("http://{}/proxy/stream", context.app_addr()))
        .expect("proxy url should parse");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("chunked request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let transfer_encoding = headers
        .get("transfer-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase());
    assert_eq!(transfer_encoding.as_deref(), Some("chunked"));
    assert!(headers.get("content-length").is_none());
    assert_eq!(
        headers
            .get("accept-ranges")
            .and_then(|value| value.to_str().ok()),
        Some("bytes")
    );
    assert!(headers.get("etag").is_some());
    assert!(headers.get("last-modified").is_some());

    let bytes = response.bytes().await.expect("chunked body should stream");
    assert_eq!(bytes, body);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_rejects_non_allowlisted_destination() {
    let context = spawn_stream_test_with_allowlist(b"abcdef".to_vec(), |_addr| {
        DirectStreamAllowlist { rules: Vec::new() }
    })
    .await;

    let mut proxy_url =
        Url::parse(&format!("http://{}/proxy/stream", context.app_addr())).expect("proxy url");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/asset", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_blocks_private_ipv4_destination() {
    let context =
        spawn_stream_test_with_allowlist(b"1234567890".to_vec(), |_addr| DirectStreamAllowlist {
            rules: vec![DirectStreamAllowRule {
                domain: "192.168.0.1".into(),
                schemes: vec![DirectStreamScheme::Http],
                path_globs: vec!["/**".into()],
            }],
        })
        .await;

    let mut proxy_url =
        Url::parse(&format!("http://{}/proxy/stream", context.app_addr())).expect("proxy url");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", "http://192.168.0.1/asset");

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_follows_allowlisted_redirect_chain() {
    let body = b"redirect-body".to_vec();
    let context = spawn_stream_test(body.clone()).await;

    let redirect_target = format!("http://{}/asset", context.upstream_addr());
    context
        .add_upstream_redirect("/redirect", redirect_target)
        .await;

    let mut proxy_url =
        Url::parse(&format!("http://{}/proxy/stream", context.app_addr())).expect("proxy url");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/redirect", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await.expect("body should stream");
    assert_eq!(bytes, body);

    context.shutdown().await;
}

#[tokio::test]
async fn direct_stream_blocks_redirect_outside_allowlist() {
    let body = b"block-redirect".to_vec();
    let context = spawn_stream_test(body).await;

    context
        .add_upstream_redirect("/redirect", "http://blocked.example/asset".into())
        .await;

    let mut proxy_url =
        Url::parse(&format!("http://{}/proxy/stream", context.app_addr())).expect("proxy url");
    proxy_url
        .query_pairs_mut()
        .append_pair("d", &format!("http://{}/redirect", context.upstream_addr()));

    let client = reqwest::Client::new();
    let response = client
        .get(proxy_url)
        .send()
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    context.shutdown().await;
}

struct StreamTestContext {
    app_addr: SocketAddr,
    upstream_addr: SocketAddr,
    upstream_state: UpstreamState,
    upstream_log: Arc<Mutex<Vec<RecordedRequest>>>,
    app_shutdown: Option<oneshot::Sender<()>>,
    upstream_shutdown: Option<oneshot::Sender<()>>,
    app_handle: JoinHandle<Result<(), io::Error>>,
    upstream_handle: JoinHandle<Result<(), io::Error>>,
}

impl StreamTestContext {
    fn app_addr(&self) -> SocketAddr {
        self.app_addr
    }

    fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    fn upstream_log(&self) -> Arc<Mutex<Vec<RecordedRequest>>> {
        Arc::clone(&self.upstream_log)
    }

    fn upstream_state(&self) -> UpstreamState {
        self.upstream_state.clone()
    }

    async fn add_upstream_redirect(&self, path: &str, target: String) {
        self.upstream_state.add_redirect(path, target).await;
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.app_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.upstream_shutdown.take() {
            let _ = tx.send(());
        }

        let _ = self.app_handle.await;
        let _ = self.upstream_handle.await;
    }
}

async fn spawn_stream_test(body: Vec<u8>) -> StreamTestContext {
    spawn_stream_test_with_allowlist(body, |addr| {
        let domain = addr.ip().to_string();
        DirectStreamAllowlist {
            rules: vec![DirectStreamAllowRule {
                domain,
                schemes: vec![DirectStreamScheme::Http],
                path_globs: vec!["/**".into()],
            }],
        }
    })
    .await
}

async fn spawn_stream_test_with_config_builder<F>(
    body: Vec<u8>,
    config_builder: F,
) -> StreamTestContext
where
    F: Fn(SocketAddr) -> DirectStreamConfig,
{
    spawn_stream_test_with_config_and_state_builder(body, config_builder, |state| state).await
}

async fn spawn_stream_test_with_config_and_state_builder<F, S>(
    body: Vec<u8>,
    config_builder: F,
    state_builder: S,
) -> StreamTestContext
where
    F: Fn(SocketAddr) -> DirectStreamConfig,
    S: Fn(AppState) -> AppState,
{
    let upstream_state = UpstreamState::new(body);
    let upstream_log = upstream_state.log.clone();
    let upstream_router = Router::new()
        .route("/*path", get(upstream_handler).head(upstream_handler))
        .with_state(upstream_state.clone());

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream should expose local address");
    let (upstream_shutdown, upstream_rx) = oneshot::channel();
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .with_graceful_shutdown(async {
                let _ = upstream_rx.await;
            })
            .await
    });

    let direct_stream = config_builder(upstream_addr);
    let settings: DirectStreamSettings = direct_stream.into();

    let app_state = state_builder(AppState::new().with_direct_stream_settings(settings));
    let router = app::build_router(SharedAppState::new(app_state));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("proxy should bind");
    let app_addr = listener
        .local_addr()
        .expect("proxy should expose local address");
    let (app_shutdown, app_rx) = oneshot::channel();
    let app_handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = app_rx.await;
            })
            .await
    });

    StreamTestContext {
        app_addr,
        upstream_addr,
        upstream_state,
        upstream_log,
        app_shutdown: Some(app_shutdown),
        upstream_shutdown: Some(upstream_shutdown),
        app_handle,
        upstream_handle,
    }
}

async fn spawn_stream_test_with_allowlist<F>(
    body: Vec<u8>,
    allowlist_builder: F,
) -> StreamTestContext
where
    F: Fn(SocketAddr) -> DirectStreamAllowlist,
{
    spawn_stream_test_with_config_builder(body, |addr| DirectStreamConfig {
        allowlist: allowlist_builder(addr),
        ..DirectStreamConfig::default()
    })
    .await
}

#[derive(Clone)]
struct UpstreamState {
    body: Arc<Vec<u8>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
    redirects: Arc<Mutex<HashMap<String, String>>>,
    config: Arc<Mutex<TestUpstreamConfig>>,
}

impl UpstreamState {
    fn new(body: Vec<u8>) -> Self {
        Self {
            body: Arc::new(body),
            log: Arc::new(Mutex::new(Vec::new())),
            redirects: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(TestUpstreamConfig::default())),
        }
    }

    async fn add_redirect(&self, path: &str, target: String) {
        self.redirects.lock().await.insert(path.to_string(), target);
    }

    async fn set_transient_failures(&self, attempts: usize) {
        self.config.lock().await.fail_get_attempts = attempts;
    }

    async fn redirect_target(&self, path: &str) -> Option<String> {
        self.redirects.lock().await.get(path).cloned()
    }

    async fn set_chunked(&self, chunked: bool) {
        self.config.lock().await.chunked = chunked;
    }

    async fn set_chunk_size(&self, chunk_size: usize) {
        self.config.lock().await.chunk_size = chunk_size.max(1);
    }

    async fn set_stream_blocker(&self, blocker: Option<Arc<Notify>>) {
        self.config.lock().await.stream_blocker = blocker;
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: Method,
    headers: Vec<(String, String)>,
}

#[derive(Clone)]
struct TestUpstreamConfig {
    chunked: bool,
    chunk_size: usize,
    etag: String,
    last_modified: String,
    fail_get_attempts: usize,
    stream_blocker: Option<Arc<Notify>>,
}

impl Default for TestUpstreamConfig {
    fn default() -> Self {
        Self {
            chunked: false,
            chunk_size: 4,
            etag: "test-etag".to_string(),
            last_modified: "Tue, 20 Feb 2024 10:00:00 GMT".to_string(),
            fail_get_attempts: 0,
            stream_blocker: None,
        }
    }
}

async fn upstream_handler(
    AxumState(state): AxumState<UpstreamState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> AxumResponse {
    let mut recorded_headers = Vec::new();
    for (name, value) in headers.iter() {
        if let Ok(value) = value.to_str() {
            recorded_headers.push((name.as_str().to_string(), value.to_string()));
        }
    }
    let path = uri.path().to_string();
    state.log.lock().await.push(RecordedRequest {
        method: method.clone(),
        headers: recorded_headers,
    });

    if let Some(target) = state.redirect_target(&path).await {
        let mut builder = AxumResponse::builder().status(AxumStatusCode::FOUND);
        builder = builder.header(header::LOCATION, target);
        return builder
            .body(AxumBody::empty())
            .expect("redirect response should build");
    }

    if path != "/asset" {
        return AxumResponse::builder()
            .status(AxumStatusCode::NOT_FOUND)
            .body(AxumBody::empty())
            .expect("not found response should build");
    }

    let full = state.body.clone();
    let total_len = full.len() as u64;
    let requested_range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_header);

    let if_range = headers
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok());

    let mut config_guard = state.config.lock().await;
    if method != Method::HEAD && config_guard.fail_get_attempts > 0 {
        config_guard.fail_get_attempts -= 1;
        drop(config_guard);

        let error_stream = stream::once(async {
            Err::<AxumBytes, axum::Error>(axum::Error::new(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "transient failure",
            )))
        });

        return AxumResponse::builder()
            .status(AxumStatusCode::OK)
            .body(AxumBody::from_stream(error_stream))
            .expect("transient failure response should build");
    }

    let config = config_guard.clone();
    drop(config_guard);

    let allow_partial = match if_range {
        Some(token) => token == config.etag || token == config.last_modified,
        None => true,
    };

    let effective_range = if allow_partial { requested_range } else { None };

    let (status, slice, length, range_metadata) = if let Some((start, maybe_end)) = effective_range
    {
        let max_index = full.len().saturating_sub(1);
        let end = maybe_end.unwrap_or(max_index).min(max_index);
        let start = start.min(end);
        let length = end - start + 1;
        (
            AxumStatusCode::PARTIAL_CONTENT,
            full[start..=end].to_vec(),
            length,
            Some((start as u64, end as u64, total_len)),
        )
    } else {
        (AxumStatusCode::OK, full.to_vec(), full.len(), None)
    };

    let mut builder = AxumResponse::builder().status(status);
    builder = builder.header(header::CONTENT_TYPE, "video/mp4");
    if !config.chunked || method == Method::HEAD {
        builder = builder.header(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).expect("valid content length"),
        );
    }
    builder = builder.header(header::ETAG, config.etag.clone());
    builder = builder.header(header::LAST_MODIFIED, config.last_modified.clone());
    builder = builder.header("x-unwanted", "true");

    if let Some((start, end, total)) = range_metadata {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, total),
        );
    }

    if method == Method::HEAD {
        builder
            .body(AxumBody::empty())
            .expect("head response should build")
    } else if let Some(blocker) = config.stream_blocker.clone() {
        let stream_body = slice;
        let stream = stream::once(async move {
            blocker.notified().await;
            Ok::<AxumBytes, axum::Error>(AxumBytes::from(stream_body))
        });
        builder
            .body(AxumBody::from_stream(stream))
            .expect("blocked stream response should build")
    } else if config.chunked {
        let chunk_size = config.chunk_size;
        let chunks = slice
            .chunks(chunk_size)
            .map(AxumBytes::copy_from_slice)
            .collect::<Vec<_>>();
        let stream = stream::iter(chunks.into_iter().map(Ok::<_, Infallible>));
        builder
            .body(AxumBody::from_stream(stream))
            .expect("chunked response should build")
    } else {
        builder
            .body(AxumBody::from(slice))
            .expect("get response should build")
    }
}

fn parse_range_header(value: &str) -> Option<(usize, Option<usize>)> {
    let value = value.strip_prefix("bytes=")?;
    let mut parts = value.splitn(2, '-');
    let start = parts.next()?.parse().ok()?;
    let end = parts.next()?;

    if end.is_empty() {
        Some((start, None))
    } else {
        let end = end.parse().ok()?;
        if start <= end {
            Some((start, Some(end)))
        } else {
            None
        }
    }
}
