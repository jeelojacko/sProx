use super::*;

use std::{collections::HashMap, env, io, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Body as AxumBody,
    extract::State as AxumState,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode as AxumStatusCode, Uri},
    response::Response as AxumResponse,
    routing::get,
    Router,
};
use reqwest::StatusCode;
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex},
    task::JoinHandle,
};
use url::Url;

use sProx::config::{
    Config, DirectStreamAllowRule, DirectStreamAllowlist, DirectStreamConfig, DirectStreamScheme,
    ListenerConfig, RouteConfig, Socks5Config, TlsConfig, UpstreamConfig,
};
use sProx::state::{AppState, DirectStreamSettings};

#[tokio::test]
async fn health_endpoint_returns_success() {
    let config = Config {
        direct_stream: None,
        routes: vec![RouteConfig {
            id: "health-check".into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: 0,
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
            },
            hls: None,
        }],
    };

    let state = build_app_state(&config).expect("app state should build");
    let router = app::build_router(state);

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

#[tokio::test]
async fn socks5_proxy_env_override_applies_to_all_routes() {
    env::remove_var("SPROX_PROXY_URL");
    let proxy_address = "127.0.0.1:1081";
    env::set_var("SPROX_PROXY_URL", proxy_address);

    let route_template =
        |id: &str, socks5_enabled: bool, socks5_address: Option<&str>| RouteConfig {
            id: id.into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: 0,
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
            },
            hls: None,
        };

    let config = Config {
        direct_stream: None,
        routes: vec![
            route_template("disabled-proxy", false, None),
            route_template("enabled-proxy", true, Some("10.0.0.1:9000")),
        ],
    };

    let state = build_app_state(&config).expect("app state should build");
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
    }

    env::remove_var("SPROX_PROXY_URL");
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

async fn spawn_stream_test_with_allowlist<F>(
    body: Vec<u8>,
    allowlist_builder: F,
) -> StreamTestContext
where
    F: Fn(SocketAddr) -> DirectStreamAllowlist,
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

    let direct_stream = DirectStreamConfig {
        allowlist: allowlist_builder(upstream_addr),
        ..DirectStreamConfig::default()
    };
    let settings: DirectStreamSettings = direct_stream.into();

    let app_state = AppState::new().with_direct_stream_settings(settings);
    let router = app::build_router(app_state);
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

#[derive(Clone)]
struct UpstreamState {
    body: Arc<Vec<u8>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
    redirects: Arc<Mutex<HashMap<String, String>>>,
}

impl UpstreamState {
    fn new(body: Vec<u8>) -> Self {
        Self {
            body: Arc::new(body),
            log: Arc::new(Mutex::new(Vec::new())),
            redirects: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn add_redirect(&self, path: &str, target: String) {
        self.redirects.lock().await.insert(path.to_string(), target);
    }

    async fn redirect_target(&self, path: &str) -> Option<String> {
        self.redirects.lock().await.get(path).cloned()
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: Method,
    headers: Vec<(String, String)>,
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
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_header);

    let (status, slice, length, range_metadata) = if let Some((start, end)) = range {
        let end = end.min(full.len().saturating_sub(1));
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
    builder = builder.header(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).expect("valid content length"),
    );
    builder = builder.header(header::ETAG, "test-etag");
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
    } else {
        builder
            .body(AxumBody::from(slice))
            .expect("get response should build")
    }
}

fn parse_range_header(value: &str) -> Option<(usize, usize)> {
    let value = value.strip_prefix("bytes=")?;
    let mut parts = value.splitn(2, '-');
    let start = parts.next()?.parse().ok()?;
    let end = parts.next()?.parse().ok()?;
    if start <= end {
        Some((start, end))
    } else {
        None
    }
}
