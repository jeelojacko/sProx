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

    (status, error.to_string()).into_response()
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
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

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
}
