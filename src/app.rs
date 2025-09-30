//! Axum application builder utilities.
//!
//! This module wires together the top-level router used by the proxy. The
//! implementation intentionally keeps the handlers lightweight; most of the
//! logic is expected to live in dedicated modules that will be added in later
//! steps of the project plan.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

#[cfg(feature = "telemetry")]
use axum::http::{header, HeaderValue};
#[cfg(feature = "telemetry")]
use std::time::Instant;
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
        .route("/speedtest", get(speedtest_placeholder))
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

/// Returns a placeholder message for the caller's IP address.
async fn report_client_ip() -> impl IntoResponse {
    (
        StatusCode::OK,
        "IP discovery is not yet implemented. This is a placeholder response.",
    )
}

/// Placeholder speed-test handler.
async fn speedtest_placeholder() -> impl IntoResponse {
    (
        StatusCode::OK,
        "Speedtest endpoint is not yet available. Please try again later.",
    )
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
    use axum::http::Request;
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
