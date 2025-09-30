//! Axum application builder utilities.
//!
//! This module wires together the top-level router used by the proxy. The
//! implementation intentionally keeps the handlers lightweight; most of the
//! logic is expected to live in dedicated modules that will be added in later
//! steps of the project plan.

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
#[cfg(feature = "telemetry")]
use tower_http::trace::{DefaultOnResponse, TraceLayer};
#[cfg(feature = "telemetry")]
use tower_http::LatencyUnit;
#[cfg(feature = "telemetry")]
use tracing::Level;

use crate::{
    proxy::{self, ProxyError},
    state::AppState,
    stream::dash,
};
#[cfg(feature = "telemetry")]
use tracing::error;

/// Constructs the Axum router used by the proxy.
///
/// The router currently exposes placeholder handlers that keep the
/// application compiling while the downstream proxying logic is being
/// implemented. Middlewares that are part of the final design, such as request
/// tracing and rate limiting, are already attached so that the surrounding
/// wiring can be validated ahead of time.
pub fn build_router(state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(health_check))
        .route("/ip", get(report_client_ip))
        .route("/speedtest", get(speedtest))
        .route("/keys", get(list_registered_keys))
        .route("/keys/clearkey", get(dash::clearkey_jwks))
        .fallback(proxy_fallback)
        .with_state(state)
        .layer(RateLimitLayer);

    #[cfg(feature = "telemetry")]
    let router = router.route("/metrics", get(prometheus_metrics));

    #[cfg(feature = "telemetry")]
    let router = router.layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<Body>| {
                let user_agent = request
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("-");

                tracing::info_span!(
                    "http.request",
                    method = %request.method(),
                    uri = %request.uri(),
                    version = ?request.version(),
                    user_agent = %user_agent,
                )
            })
            .on_response(
                DefaultOnResponse::new()
                    .level(Level::INFO)
                    .latency_unit(LatencyUnit::Millis),
            ),
    );

    router
}

/// Basic health-check handler used for readiness probes.
async fn health_check() -> impl IntoResponse {
    #[cfg(feature = "telemetry")]
    metrics::counter!("sprox_health_checks_total").increment(1);

    StatusCode::OK
}

/// Resolves the caller's IP address from connection metadata and common proxy
/// headers.
async fn report_client_ip(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let resolved = resolve_client_ip(&headers, remote_addr);

    (StatusCode::OK, resolved.to_string())
}

const SPEEDTEST_TOTAL_BYTES: usize = 8 * 1024 * 1024; // 8 MiB
const SPEEDTEST_CHUNK_SIZE: usize = 64 * 1024; // 64 KiB
const SPEEDTEST_PATTERN: &[u8] = b"sprox-speedtest-data-";

/// Streams deterministic bytes to the caller while logging the observed
/// throughput.
async fn speedtest() -> impl IntoResponse {
    let stream = SpeedtestStream::new(SPEEDTEST_TOTAL_BYTES, SPEEDTEST_CHUNK_SIZE);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )
        .header(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&SPEEDTEST_TOTAL_BYTES.to_string())
                .expect("valid content length"),
        )
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(body)
        .expect("valid speedtest response")
}

fn resolve_client_ip(headers: &HeaderMap, remote_addr: SocketAddr) -> IpAddr {
    forwarded_header_ip(headers)
        .or_else(|| header_ip(headers, "x-forwarded-for"))
        .or_else(|| header_ip(headers, "x-real-ip"))
        .or_else(|| header_ip(headers, "cf-connecting-ip"))
        .or_else(|| header_ip(headers, "x-client-ip"))
        .unwrap_or_else(|| remote_addr.ip())
}

fn forwarded_header_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(header::FORWARDED)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|segment| {
                segment
                    .split(';')
                    .find_map(|pair| match pair.trim().strip_prefix("for=") {
                        Some(ip) => parse_ip_candidate(ip),
                        None => None,
                    })
            })
        })
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(',')
                .map(|item| item.trim())
                .find_map(parse_ip_candidate)
        })
}

fn parse_ip_candidate(value: &str) -> Option<IpAddr> {
    let trimmed = value.trim().trim_matches('"');

    if trimmed.is_empty() || trimmed == "_" {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Some(ip);
        }
    }

    None
}

struct SpeedtestStream {
    remaining: usize,
    chunk: Bytes,
    sent: usize,
    start: Instant,
    finished: bool,
}

impl SpeedtestStream {
    fn new(total_bytes: usize, chunk_size: usize) -> Self {
        assert!(total_bytes > 0, "total bytes must be positive");
        assert!(chunk_size > 0, "chunk size must be positive");

        let mut pattern = Vec::with_capacity(chunk_size);
        while pattern.len() < chunk_size {
            let remaining = chunk_size - pattern.len();
            let slice_len = remaining.min(SPEEDTEST_PATTERN.len());
            pattern.extend_from_slice(&SPEEDTEST_PATTERN[..slice_len]);
        }

        Self {
            remaining: total_bytes,
            chunk: Bytes::from(pattern),
            sent: 0,
            start: Instant::now(),
            finished: false,
        }
    }
}

impl futures::Stream for SpeedtestStream {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.remaining == 0 {
            if !this.finished {
                this.finished = true;
                let elapsed = this.start.elapsed();
                let seconds = elapsed.as_secs_f64();
                let throughput = if seconds > 0.0 {
                    this.sent as f64 / seconds
                } else {
                    f64::INFINITY
                };

                #[cfg(feature = "telemetry")]
                tracing::info!(
                    target = "speedtest",
                    total_bytes = this.sent,
                    elapsed_seconds = seconds,
                    throughput_bytes_per_second = throughput,
                    "completed speedtest stream"
                );
            }

            return Poll::Ready(None);
        }

        let len = this.chunk.len().min(this.remaining);
        let chunk = if len == this.chunk.len() {
            this.chunk.clone()
        } else {
            this.chunk.slice(0..len)
        };

        this.remaining -= len;
        this.sent += len;

        Poll::Ready(Some(Ok(chunk)))
    }
}

/// Lists the keys currently registered in the application's secret store.
async fn list_registered_keys(State(state): State<AppState>) -> impl IntoResponse {
    let secrets_store = state.secrets();
    let secrets = secrets_store.read().await;
    let mut keys: Vec<_> = secrets.keys().cloned().collect();
    keys.sort();

    if keys.is_empty() {
        (
            StatusCode::OK,
            "No keys have been registered with the proxy at this time.".into(),
        )
    } else {
        let response = format!("Registered keys: {}", keys.join(", "));
        (StatusCode::OK, response)
    }
}

/// Catch-all proxy handler used for routes that have not been explicitly
/// registered.
async fn proxy_fallback(
    State(state): State<AppState>,
    request: Request<Body>,
) -> impl IntoResponse {
    #[cfg(feature = "telemetry")]
    let start = Instant::now();

    match proxy::forward(state, request).await {
        Ok(response) => {
            #[cfg(feature = "telemetry")]
            record_http_metrics("proxy_fallback", response.status(), start.elapsed());

            response
        }
        Err(error) => {
            let response = map_proxy_error(error);

            #[cfg(feature = "telemetry")]
            record_http_metrics("proxy_fallback", response.status(), start.elapsed());

            response
        }
    }
}

fn map_proxy_error(error: ProxyError) -> axum::http::Response<Body> {
    let status = match error {
        ProxyError::MissingHost => StatusCode::BAD_REQUEST,
        ProxyError::RouteNotFound { .. } => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_GATEWAY,
    };

    #[cfg(feature = "telemetry")]
    error!(status = status.as_u16(), error = ?error, "proxy error encountered");

    let message = match status.as_u16() {
        400..=499 => "The request could not be processed.",
        500..=599 => "The service encountered an upstream error.",
        _ => "An unexpected error occurred.",
    };

    (status, message).into_response()
}

#[cfg(feature = "telemetry")]
async fn prometheus_metrics() -> impl IntoResponse {
    match crate::scrape_metrics() {
        Some(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4"),
            )],
            body,
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics recorder unavailable",
        )
            .into_response(),
    }
}

#[cfg(feature = "telemetry")]
fn record_http_metrics(route: &str, status: StatusCode, latency: std::time::Duration) {
    let status_label = status.as_u16().to_string();

    metrics::counter!(
        "sprox_http_responses_total",
        "route" => route.to_owned(),
        "status" => status_label.clone(),
    )
    .increment(1);
    metrics::histogram!(
        "sprox_http_response_duration_seconds",
        "route" => route.to_owned(),
        "status" => status_label,
    )
    .record(latency.as_secs_f64());
}

/// Placeholder layer representing the future rate-limiting middleware.
#[derive(Clone, Default)]
struct RateLimitLayer;

impl<S> tower::Layer<S> for RateLimitLayer {
    type Service = S;

    fn layer(&self, service: S) -> Self::Service {
        service
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, HeaderValue, Request};
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt; // for `oneshot`
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;
    use url::Url;

    #[tokio::test]
    async fn health_route_returns_success() {
        let app = build_router(AppState::new());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn report_client_ip_uses_connect_info_when_no_headers_present() {
        let remote_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let headers = HeaderMap::new();

        let response = report_client_ip(ConnectInfo(remote_addr), headers)
            .await
            .into_response();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        let body = to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"203.0.113.10");
    }

    #[tokio::test]
    async fn report_client_ip_prefers_forwarded_header() {
        let remote_addr: SocketAddr = "198.51.100.24:8080".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::FORWARDED,
            HeaderValue::from_static("for=192.0.2.44;proto=https"),
        );

        let response = report_client_ip(ConnectInfo(remote_addr), headers)
            .await
            .into_response();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        let body = to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"192.0.2.44");
    }

    #[tokio::test]
    async fn report_client_ip_falls_back_to_x_forwarded_for() {
        let remote_addr: SocketAddr = "198.51.100.50:9000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.8, 203.0.113.9"),
        );

        let response = report_client_ip(ConnectInfo(remote_addr), headers)
            .await
            .into_response();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        let body = to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"203.0.113.8");
    }

    #[tokio::test]
    async fn speedtest_streams_expected_payload() {
        let app = build_router(AppState::new());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/speedtest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );

        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        assert_eq!(bytes.len(), SPEEDTEST_TOTAL_BYTES);
        let payload = bytes.as_ref();
        assert!(payload
            .windows(SPEEDTEST_PATTERN.len())
            .any(|window| window == SPEEDTEST_PATTERN));
    }

    #[tokio::test]
    async fn map_proxy_error_sanitizes_client_facing_response() {
        let log_writer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log_writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();

        let error = ProxyError::RouteNotFound {
            host: "secret.internal".into(),
        };

        let response = with_default(subscriber, || map_proxy_error(error));
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::NOT_FOUND);

        let bytes = to_bytes(body, usize::MAX).await.expect("body to bytes");
        let body_text = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert_eq!(body_text, "The request could not be processed.");
        assert!(!body_text.contains("secret.internal"));

        let logs = log_writer.contents();
        assert!(logs.contains("secret.internal"));
    }

    #[tokio::test]
    async fn map_proxy_error_logs_details_for_server_errors() {
        let log_writer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log_writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();

        let source = Url::parse("::invalid::").unwrap_err();
        let error = ProxyError::InvalidUpstreamUrl {
            url: "http://upstream".into(),
            source,
        };

        let response = with_default(subscriber, || map_proxy_error(error));
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::BAD_GATEWAY);

        let bytes = to_bytes(body, usize::MAX).await.expect("body to bytes");
        let body_text = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert_eq!(body_text, "The service encountered an upstream error.");

        let logs = log_writer.contents();
        assert!(logs.contains("InvalidUpstreamUrl"), "logs: {logs}");
    }

    #[derive(Clone, Default)]
    struct SharedLogBuffer {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedLogBuffer {
        fn contents(&self) -> String {
            let data = self.inner.lock().expect("log buffer lock").clone();
            String::from_utf8_lossy(&data).into_owned()
        }
    }

    struct SharedWriter {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut guard = self.inner.lock().expect("log buffer lock");
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriter {
                inner: Arc::clone(&self.inner),
            }
        }
    }
}
