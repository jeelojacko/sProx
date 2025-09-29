//! Axum application builder utilities.
//!
//! This module wires together the top-level router used by the proxy. The
//! implementation intentionally keeps the handlers lightweight; most of the
//! logic is expected to live in dedicated modules that will be added in later
//! steps of the project plan.

use axum::{
    extract::State,
    http::{StatusCode, Uri},
    response::IntoResponse,
    routing::get,
    Router,
};

#[cfg(feature = "telemetry")]
use tower_http::trace::TraceLayer;

use crate::state::AppState;

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
        .fallback(proxy_fallback)
        .with_state(state)
        .layer(RateLimitLayer::default());

    #[cfg(feature = "telemetry")]
    let router = router.layer(TraceLayer::new_for_http());

    router
}

/// Basic health-check handler used for readiness probes.
async fn health_check() -> impl IntoResponse {
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
async fn proxy_fallback(State(state): State<AppState>, uri: Uri) -> impl IntoResponse {
    let _ = state; // The state will be used once proxying is implemented.
    (
        StatusCode::NOT_IMPLEMENTED,
        format!("Proxying for `{uri}` has not been implemented yet."),
    )
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
