//! Telemetry and observability primitives for the proxy.
//!
//! This module is responsible for wiring structured tracing and the global
//! metrics recorder used across the application. The Prometheus exporter is
//! kept process-wide so that handlers can easily expose the scrape endpoint
//! without juggling additional state.

use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initializes the telemetry stack used by the application.
pub(crate) fn init() -> Result<()> {
    init_tracing()?;
    init_metrics()?;

    Ok(())
}

fn init_tracing() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to construct tracing filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize tracing subscriber: {err}"))?;

    Ok(())
}

fn init_metrics() -> Result<()> {
    let recorder = PrometheusBuilder::new()
        .install_recorder()
        .context("failed to install Prometheus recorder")?;

    PROMETHEUS_HANDLE
        .set(recorder)
        .map_err(|_| anyhow!("Prometheus recorder has already been initialized"))?;

    metrics::describe_counter!(
        "sprox_http_responses_total",
        "Total number of HTTP responses emitted by the proxy."
    );
    metrics::describe_histogram!(
        "sprox_http_response_duration_seconds",
        "Latency histogram (in seconds) for HTTP responses emitted by the proxy."
    );
    metrics::describe_counter!(
        "sprox_requests_total",
        "Total number of upstream requests issued by the proxy, labelled by route."
    );
    metrics::describe_histogram!(
        "sprox_upstream_latency_seconds",
        "Latency histogram (in seconds) for upstream requests grouped by route."
    );
    metrics::describe_counter!(
        "sprox_bytes_streamed_total",
        "Total number of response bytes streamed back to clients from upstream services."
    );
    metrics::describe_counter!(
        "sprox_health_checks_total",
        "Total number of successful /health responses served."
    );
    metrics::describe_counter!(
        "sprox_proxy_stream_requests_total",
        "Total number of /proxy/stream responses emitted grouped by HTTP status."
    );
    metrics::describe_counter!(
        "sprox_proxy_stream_upstream_status_total",
        "Total number of upstream responses observed by /proxy/stream grouped by status."
    );
    metrics::describe_counter!(
        "sprox_proxy_stream_bytes_out_total",
        "Total bytes streamed to clients via /proxy/stream grouped by status."
    );
    metrics::describe_histogram!(
        "sprox_proxy_stream_first_byte_latency_seconds",
        "Latency histogram (in seconds) for time-to-first-byte observed by /proxy/stream."
    );
    metrics::describe_histogram!(
        "sprox_proxy_stream_duration_seconds",
        "Latency histogram (in seconds) for full request duration of /proxy/stream."
    );

    Ok(())
}

/// Returns the Prometheus metrics encoded in the text exposition format.
pub(crate) fn prometheus_metrics() -> Option<String> {
    PROMETHEUS_HANDLE.get().map(|handle| handle.render())
}
