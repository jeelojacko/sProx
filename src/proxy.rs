use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{connect_info::ConnectInfo, OriginalUri};
use axum::http::{
    self,
    header::{HeaderName, HeaderValue, CONTENT_LENGTH, FORWARDED, HOST},
    HeaderMap, Request, Response, Uri,
};
use futures::TryStreamExt;
use reqwest::{
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue,
    },
    redirect::Policy,
    Body as ReqwestBody, Client, ClientBuilder, Method as ReqwestMethod, Proxy as ReqwestProxy,
};
use thiserror::Error;
use tracing::{error, info};
use url::Url;

use crate::retry::{self, RetryError};
use crate::routing::{RouteProtocol, RouteRequest};
use crate::state::{AppState, RouteTarget};
use crate::stream::hls;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const VIA_HEADER_VALUE: &str = "1.1 sProx";

/// Errors that can occur while proxying a request.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("downstream request is missing a host header")]
    MissingHost,

    #[error("no upstream route registered for host `{host}`")]
    RouteNotFound { host: String },

    #[error("no upstream target configured for route `{route_id}`")]
    RouteTargetNotFound { route_id: String },

    #[error("invalid upstream url `{url}`: {source}")]
    InvalidUpstreamUrl {
        url: String,
        #[source]
        source: url::ParseError,
    },

    #[error("failed to build upstream client: {source}")]
    ClientBuild {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to create SOCKS5 proxy: {source}")]
    Socks5Proxy {
        #[source]
        source: reqwest::Error,
    },

    #[error("error sending request upstream: {source}")]
    UpstreamRequest {
        #[source]
        source: reqwest::Error,
    },

    #[error("retry budget exhausted for upstream request: {source}")]
    CircuitOpen {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to construct downstream response: {source}")]
    ResponseBuild {
        #[source]
        source: http::Error,
    },

    #[error("unsupported HTTP method `{method}`")]
    UnsupportedMethod { method: String },

    #[error("invalid header name while preparing upstream request: {source}")]
    InvalidOutboundHeaderName {
        #[source]
        source: reqwest::header::InvalidHeaderName,
    },

    #[error("invalid header value while preparing upstream request: {source}")]
    InvalidOutboundHeaderValue {
        #[source]
        source: reqwest::header::InvalidHeaderValue,
    },

    #[error("invalid header encoding on downstream request: {0}")]
    InvalidHeaderEncoding(#[from] http::header::ToStrError),

    #[error("invalid header name returned by upstream: {source}")]
    InvalidInboundHeaderName {
        #[source]
        source: http::header::InvalidHeaderName,
    },

    #[error("invalid header value returned by upstream: {source}")]
    InvalidInboundHeaderValue {
        #[source]
        source: http::header::InvalidHeaderValue,
    },

    #[error("invalid status code returned by upstream: {code}")]
    InvalidStatusCode {
        code: u16,
        #[source]
        source: http::status::InvalidStatusCode,
    },

    #[error("failed to read upstream response body: {source}")]
    UpstreamBody {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to process HLS manifest: {source}")]
    HlsProcessing {
        #[source]
        source: hls::HlsError,
    },
}

/// Top-level entry point used by handlers to forward requests to the upstream target.
#[tracing::instrument(
    name = "proxy.forward",
    skip(state, request),
    fields(
        route.id = tracing::field::Empty,
        route.host = tracing::field::Empty,
        upstream.url = tracing::field::Empty,
        client.scheme = tracing::field::Empty
    )
)]
pub async fn forward(
    state: AppState,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let host = extract_host(request.uri(), request.headers()).ok_or(ProxyError::MissingHost)?;
    let span = tracing::Span::current();
    span.record("route.host", &tracing::field::display(&host));

    let protocol = determine_route_protocol(&request);
    let port = extract_port(request.uri(), request.headers(), protocol);
    let route_request = RouteRequest {
        host: Some(host.as_str()),
        protocol,
        port,
    };

    let (route_id, route) = lookup_route(&state, &host, &route_request).await?;
    span.record("route.id", &tracing::field::display(&route_id));
    let upstream_url = build_upstream_url(&route, request.uri())?;
    span.record("upstream.url", &tracing::field::display(&upstream_url));
    let manifest_url = upstream_url.clone();
    let upstream_scheme = upstream_url.scheme().to_string();
    let client_scheme =
        determine_client_scheme(&request).unwrap_or_else(|| upstream_scheme.clone());
    span.record("client.scheme", &tracing::field::display(&client_scheme));

    let client = build_client(&route)?;
    let remote_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let headers = prepare_upstream_headers(
        request.headers(),
        remote_addr,
        &host,
        &client_scheme,
        &route,
    )?;

    let method = ReqwestMethod::from_bytes(request.method().as_str().as_bytes()).map_err(|_| {
        ProxyError::UnsupportedMethod {
            method: request.method().to_string(),
        }
    })?;

    let mut builder = client.request(method, upstream_url.clone());
    builder = builder.headers(headers);

    let request_timeout = route
        .request_timeout
        .or(route.read_timeout)
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT);
    builder = builder.timeout(request_timeout);

    let body_stream = request
        .into_body()
        .into_data_stream()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .into_stream();
    builder = builder.body(ReqwestBody::wrap_stream(body_stream));

    let request = builder
        .build()
        .map_err(|source| ProxyError::UpstreamRequest { source })?;

    let request_start = Instant::now();
    let retry_policy = route.retry.clone();
    let upstream_response =
        match retry::execute_with_retry(client.clone(), request, retry_policy).await {
            Ok(response) => response,
            Err(RetryError::BudgetExhausted { source }) => {
                let latency_ms = request_start.elapsed().as_millis() as u64;
                error!(
                    latency_ms,
                    error = %source,
                    "retry budget exhausted while forwarding request"
                );
                return Err(ProxyError::CircuitOpen { source });
            }
            Err(RetryError::Request(source)) => {
                let latency_ms = request_start.elapsed().as_millis() as u64;
                error!(
                    latency_ms,
                    error = %source,
                    "failed to forward request to upstream"
                );
                return Err(ProxyError::UpstreamRequest { source });
            }
        };

    let latency = request_start.elapsed();
    let latency_ms = latency.as_millis() as u64;

    let upstream_status = upstream_response.status();
    let status = match http::StatusCode::from_u16(upstream_status.as_u16()) {
        Ok(status) => status,
        Err(source) => {
            error!(
                latency_ms,
                status_code = upstream_status.as_u16(),
                "invalid status returned by upstream"
            );
            return Err(ProxyError::InvalidStatusCode {
                code: upstream_status.as_u16(),
                source,
            });
        }
    };

    info!(status = %status, latency_ms, "forwarded upstream response");

    let upstream_headers = upstream_response.headers().clone();
    let mut header_entries = Vec::with_capacity(upstream_headers.len());
    let mut response_via_values = Vec::new();
    for (name, value) in upstream_headers.iter() {
        if name.as_str() == "via" {
            if let Ok(via) = value.to_str() {
                let via = via.trim();
                if !via.is_empty() {
                    response_via_values.push(via.to_string());
                }
            }
            continue;
        }

        let header_name = HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|source| ProxyError::InvalidInboundHeaderName { source })?;

        if should_strip_response_header(&header_name, &route.header_policy) {
            continue;
        }

        let header_value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|source| ProxyError::InvalidInboundHeaderValue { source })?;
        header_entries.push((header_name, header_value));
    }

    response_via_values.push(VIA_HEADER_VALUE.to_string());
    if let Some(via_value) = join_values(&response_via_values) {
        header_entries.push((
            HeaderName::from_static("via"),
            HeaderValue::from_str(&via_value)
                .map_err(|source| ProxyError::InvalidInboundHeaderValue { source })?,
        ));
    }

    let should_process_hls = route
        .hls
        .as_ref()
        .map(|cfg| cfg.enabled && is_hls_manifest(&upstream_headers, &manifest_url))
        .unwrap_or(false);

    let response_body = if should_process_hls {
        let hls_config = route.hls.as_ref().expect("checked above");
        let body_bytes = upstream_response
            .bytes()
            .await
            .map_err(|source| ProxyError::UpstreamBody { source })?;

        let rewritten = hls::rewrite_playlist(
            &body_bytes,
            &manifest_url,
            hls_config.base_url.as_ref(),
            hls_config.rewrite_playlist_urls,
            hls_config.allow_insecure_segments,
        )
        .map_err(|source| ProxyError::HlsProcessing { source })?;

        header_entries.retain(|(name, _)| name != CONTENT_LENGTH);

        Body::from(rewritten)
    } else {
        let response_stream = upstream_response
            .bytes_stream()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .into_stream();
        Body::from_stream(response_stream)
    };

    let mut response_builder = Response::builder().status(status);
    if let Some(headers) = response_builder.headers_mut() {
        for (name, value) in header_entries {
            headers.append(name, value);
        }
    }

    response_builder
        .body(response_body)
        .map_err(|source| ProxyError::ResponseBuild { source })
}

fn extract_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    if let Some(authority) = uri.authority() {
        if let Some(host) = normalize_host(authority.host()) {
            return Some(host);
        }
    } else if let Some(host) = uri.host() {
        if let Some(host) = normalize_host(host) {
            return Some(host);
        }
    }

    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_authority_host)
}

fn parse_authority_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(authority) = trimmed.parse::<http::uri::Authority>() {
        return normalize_host(authority.host());
    }

    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            return normalize_host(host);
        }
    }

    let host = trimmed
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(trimmed);

    normalize_host(host)
}

fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        if stripped.is_empty() {
            return None;
        }
        return Some(stripped.to_ascii_lowercase());
    }

    Some(trimmed.to_ascii_lowercase())
}

fn determine_route_protocol(request: &Request<Body>) -> RouteProtocol {
    if let Some(protocol) = request
        .uri()
        .scheme_str()
        .and_then(RouteProtocol::from_scheme)
    {
        return protocol;
    }

    if let Some(original_uri) = request.extensions().get::<OriginalUri>() {
        if let Some(protocol) = original_uri
            .0
            .scheme_str()
            .and_then(RouteProtocol::from_scheme)
        {
            return protocol;
        }
    }

    RouteProtocol::Http
}

fn extract_port(uri: &Uri, headers: &HeaderMap, protocol: RouteProtocol) -> u16 {
    if let Some(port) = uri.port_u16() {
        return port;
    }

    if let Some(authority) = uri.authority() {
        if let Some(port) = authority.port_u16() {
            return port;
        }
    }

    if let Some(value) = headers.get(HOST).and_then(|value| value.to_str().ok()) {
        if let Ok(authority) = value.trim().parse::<http::uri::Authority>() {
            if let Some(port) = authority.port_u16() {
                return port;
            }
        }
    }

    default_port(protocol)
}

fn default_port(protocol: RouteProtocol) -> u16 {
    match protocol {
        RouteProtocol::Http => 80,
        RouteProtocol::Https => 443,
    }
}

fn determine_client_scheme(request: &Request<Body>) -> Option<String> {
    if let Some(scheme) = request.uri().scheme_str() {
        if let Some(normalized) = normalize_scheme(scheme) {
            return Some(normalized);
        }
    }

    if let Some(original_uri) = request.extensions().get::<OriginalUri>() {
        if let Some(scheme) = original_uri.0.scheme_str() {
            if let Some(normalized) = normalize_scheme(scheme) {
                return Some(normalized);
            }
        }
    }

    if let Some(value) = request.headers().get(FORWARDED) {
        if let Ok(value) = value.to_str() {
            if let Some(scheme) = parse_forwarded_proto(value) {
                return Some(scheme);
            }
        }
    }

    let forwarded_proto = HeaderName::from_static("x-forwarded-proto");
    if let Some(value) = request.headers().get(&forwarded_proto) {
        if let Ok(value) = value.to_str() {
            if let Some(scheme) = parse_x_forwarded_proto(value) {
                return Some(scheme);
            }
        }
    }

    None
}

fn normalize_scheme(value: &str) -> Option<String> {
    if value.eq_ignore_ascii_case("http") {
        Some(String::from("http"))
    } else if value.eq_ignore_ascii_case("https") {
        Some(String::from("https"))
    } else {
        None
    }
}

fn parse_forwarded_proto(header: &str) -> Option<String> {
    header.split(',').find_map(|segment| {
        segment.split(';').find_map(|pair| match pair.trim() {
            value if value.len() >= 6 && value[..6].eq_ignore_ascii_case("proto=") => {
                let proto = value[6..].trim_matches('"');
                normalize_scheme(proto)
            }
            _ => None,
        })
    })
}

fn parse_x_forwarded_proto(header: &str) -> Option<String> {
    header
        .split(',')
        .map(|value| value.trim())
        .find_map(normalize_scheme)
}

async fn lookup_route(
    state: &AppState,
    host: &str,
    request: &RouteRequest<'_>,
) -> Result<(String, RouteTarget), ProxyError> {
    let routing_engine = state.routing_engine();
    let definition =
        routing_engine
            .match_request(request)
            .ok_or_else(|| ProxyError::RouteNotFound {
                host: host.to_string(),
            })?;

    let route_id = definition.id.clone();
    let routing_table = state.routing_table();
    let table = routing_table.read().await;
    let target = table
        .get(&route_id)
        .cloned()
        .ok_or_else(|| ProxyError::RouteTargetNotFound {
            route_id: route_id.clone(),
        })?;

    Ok((route_id, target))
}

fn build_client(route: &RouteTarget) -> Result<Client, ProxyError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(route.tls_insecure_skip_verify);
    builder = apply_client_timeouts(builder, route);

    if let Some(proxy) = &route.socks5 {
        if !proxy.address.is_empty() {
            let proxy_url = format!("socks5h://{}", proxy.address);
            let mut req_proxy = ReqwestProxy::all(proxy_url)
                .map_err(|source| ProxyError::Socks5Proxy { source })?;
            if let Some(username) = &proxy.username {
                req_proxy = req_proxy.basic_auth(username, proxy.password.as_deref().unwrap_or(""));
            }
            builder = builder.proxy(req_proxy);
        }
    }

    builder
        .build()
        .map_err(|source| ProxyError::ClientBuild { source })
}

fn apply_client_timeouts(builder: ClientBuilder, route: &RouteTarget) -> ClientBuilder {
    let connect_timeout = route.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
    let read_timeout = route.read_timeout.unwrap_or(DEFAULT_READ_TIMEOUT);

    builder
        .connect_timeout(connect_timeout)
        .timeout(read_timeout)
}

fn build_upstream_url(route: &RouteTarget, uri: &Uri) -> Result<Url, ProxyError> {
    let mut base =
        Url::parse(&route.upstream).map_err(|source| ProxyError::InvalidUpstreamUrl {
            url: route.upstream.clone(),
            source,
        })?;

    let mut path = String::new();
    let base_path = base.path().trim_end_matches('/');
    if !base_path.is_empty() {
        path.push_str(base_path);
    }

    let request_path = uri.path();
    if !request_path.is_empty() {
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(request_path.trim_start_matches('/'));
    }

    if path.is_empty() {
        path.push('/');
    }

    base.set_path(&path);
    base.set_query(uri.query());

    Ok(base)
}

fn is_hls_manifest(headers: &reqwest::header::HeaderMap, url: &Url) -> bool {
    if let Some(content_type) = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        if matches_hls_content_type(content_type) {
            return true;
        }
    }

    url.path()
        .rsplit_once('.')
        .map(|(_, ext)| ext.eq_ignore_ascii_case("m3u8"))
        .unwrap_or(false)
}

fn matches_hls_content_type(value: &str) -> bool {
    let normalized = value.trim();
    normalized.eq_ignore_ascii_case("application/vnd.apple.mpegurl")
        || normalized.eq_ignore_ascii_case("application/x-mpegurl")
        || normalized.eq_ignore_ascii_case("audio/mpegurl")
}

fn prepare_upstream_headers(
    downstream: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    host: &str,
    scheme: &str,
    route: &RouteTarget,
) -> Result<ReqwestHeaderMap, ProxyError> {
    let mut headers = ReqwestHeaderMap::new();
    let forwarded_host_req = ReqwestHeaderName::from_static("x-forwarded-host");
    let forwarded_proto_req = ReqwestHeaderName::from_static("x-forwarded-proto");
    let forwarded_for_req = ReqwestHeaderName::from_static("x-forwarded-for");
    let forwarded_for_lookup = HeaderName::from_static("x-forwarded-for");
    let via_lookup = HeaderName::from_static("via");
    let policy = &route.header_policy;

    for (name, value) in downstream.iter() {
        if name == HOST || is_reserved_request_header(name) {
            continue;
        }

        if should_strip_request_header(name, policy) {
            continue;
        }

        let header_name = ReqwestHeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|source| ProxyError::InvalidOutboundHeaderName { source })?;
        let header_value = ReqwestHeaderValue::from_bytes(value.as_bytes())
            .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
        headers.append(header_name, header_value);
    }

    let host_value = ReqwestHeaderValue::from_str(host)
        .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
    headers.insert(forwarded_host_req, host_value);

    let proto_value = ReqwestHeaderValue::from_str(scheme)
        .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
    headers.insert(forwarded_proto_req, proto_value);

    let existing_forwarded_for =
        collect_header_values(downstream.get_all(&forwarded_for_lookup).iter())?;
    let forwarded_for_value =
        build_forwarded_for(join_values(&existing_forwarded_for), remote_addr, policy);
    if let Some(value) = forwarded_for_value {
        let forwarded_value = ReqwestHeaderValue::from_str(&value)
            .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
        headers.insert(forwarded_for_req, forwarded_value);
    }

    let mut via_values = collect_header_values(downstream.get_all(&via_lookup).iter())?;
    via_values.push(VIA_HEADER_VALUE.to_string());
    if let Some(via_value) = join_values(&via_values) {
        let via_header = ReqwestHeaderName::from_static("via");
        let via_value = ReqwestHeaderValue::from_str(&via_value)
            .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
        headers.insert(via_header, via_value);
    }

    Ok(headers)
}

fn collect_header_values<'a, I>(values: I) -> Result<Vec<String>, ProxyError>
where
    I: IntoIterator<Item = &'a HeaderValue>,
{
    let mut parts = Vec::new();
    for value in values {
        let value = value.to_str()?.trim();
        if !value.is_empty() {
            parts.push(value.to_string());
        }
    }

    Ok(parts)
}

fn join_values(values: &[String]) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

fn build_forwarded_for(
    existing: Option<String>,
    remote_addr: Option<SocketAddr>,
    policy: &crate::state::HeaderPolicy,
) -> Option<String> {
    let client_ip = remote_addr.map(|addr| addr.ip().to_string());
    match policy.x_forwarded_for() {
        crate::state::XForwardedFor::Replace => client_ip,
        crate::state::XForwardedFor::Append => match (existing, client_ip) {
            (Some(existing), Some(ip)) => Some(format!("{existing}, {ip}")),
            (None, Some(ip)) => Some(ip),
            (existing, None) => existing,
        },
    }
}

fn should_strip_request_header(name: &HeaderName, policy: &crate::state::HeaderPolicy) -> bool {
    if is_sensitive_request_header(name) && policy.is_explicitly_allowed(name) {
        return false;
    }

    if policy.is_explicitly_allowed(name) {
        return false;
    }

    if policy.is_explicitly_denied(name) {
        return true;
    }

    if is_sensitive_request_header(name) {
        return true;
    }

    is_hop_by_hop_request_header(name.as_str())
}

fn should_strip_response_header(name: &HeaderName, policy: &crate::state::HeaderPolicy) -> bool {
    if policy.is_explicitly_allowed(name) {
        return false;
    }

    if policy.is_explicitly_denied(name) {
        return true;
    }

    is_hop_by_hop_response_header(name.as_str())
}

fn is_reserved_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded" | "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "via"
    )
}

fn is_sensitive_request_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "authorization" | "proxy-authorization")
}

fn is_hop_by_hop_request_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn is_hop_by_hop_response_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{PortRange, RouteDefinition, RouteProtocol, RouteRequest, RoutingEngine};
    use crate::state::{RetryPolicy, SecretsStore};
    use axum::http::header::HeaderValue;
    use axum::http::{HeaderMap, Request, Uri};
    use reqwest::header::HeaderName as ReqHeaderName;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{oneshot, RwLock};
    use tokio::time::sleep;
    use tracing::field::{Field, Visit};
    use tracing::span::Id;
    use tracing::subscriber::set_default;
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::Registry;

    async fn spawn_delayed_http_server(
        delay: Duration,
    ) -> (std::net::SocketAddr, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test server should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose local addr");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept = listener.accept() => {
                        let (mut stream, _) = match accept {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };

                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            match stream.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buffer.extend_from_slice(&chunk[..n]);
                                    if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    return;
                                }
                            }
                        }

                        sleep(delay).await;
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                }
            }
        });

        (addr, shutdown_tx)
    }

    async fn spawn_static_response_server(
        body: &'static [u8],
        content_type: &'static str,
    ) -> (std::net::SocketAddr, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("static server should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose local addr");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept = listener.accept() => {
                        let (mut stream, _) = match accept {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };

                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            match stream.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buffer.extend_from_slice(&chunk[..n]);
                                    if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    return;
                                }
                            }
                        }

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            content_type
                        );
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = stream.write_all(body).await;
                    }
                }
            }
        });

        (addr, shutdown_tx)
    }

    fn build_state_with_routes(
        definitions: Vec<RouteDefinition>,
        targets: HashMap<String, RouteTarget>,
    ) -> AppState {
        AppState::with_components(
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(targets)),
            Arc::new(RwLock::new(SecretsStore::default())),
            Arc::new(
                RoutingEngine::new(definitions).expect("routing engine should compile for tests"),
            ),
        )
    }

    fn state_with_single_route(definition: RouteDefinition, target: RouteTarget) -> AppState {
        let mut targets = HashMap::new();
        targets.insert(definition.id.clone(), target);
        build_state_with_routes(vec![definition], targets)
    }

    #[test]
    fn extract_host_from_uri_with_port() {
        let uri: Uri = "https://Example.COM:8443/stream".parse().unwrap();
        let headers = HeaderMap::new();

        let host = extract_host(&uri, &headers).expect("host should be extracted");

        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_from_header_with_port() {
        let uri: Uri = "/stream".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("Example.COM:8080"));

        let host = extract_host(&uri, &headers).expect("host should be extracted");

        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_from_ipv6_header() {
        let uri: Uri = "/stream".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("[2001:db8::1]:443"));

        let host = extract_host(&uri, &headers).expect("host should be extracted");

        assert_eq!(host, "2001:db8::1");
    }

    #[test]
    fn build_upstream_url_joins_paths() {
        let target = RouteTarget {
            upstream: "https://example.com/vod".to_string(),
            connect_timeout: None,
            read_timeout: None,
            request_timeout: None,
            tls_insecure_skip_verify: false,
            socks5: None,
            hls: None,
            retry: RetryPolicy::default(),
            header_policy: crate::state::HeaderPolicy::default(),
        };
        let uri: Uri = "/playlist.m3u8".parse().unwrap();
        let url = build_upstream_url(&target, &uri).unwrap();
        assert_eq!(url.as_str(), "https://example.com/vod/playlist.m3u8");
    }

    #[test]
    fn prepare_headers_adds_forwarding() {
        let mut downstream = HeaderMap::new();
        downstream.insert(HOST, HeaderValue::from_static("cdn.example.com"));
        downstream.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.1"),
        );
        let route = RouteTarget {
            header_policy: crate::state::HeaderPolicy::default(),
            ..RouteTarget::default()
        };
        let headers = prepare_upstream_headers(
            &downstream,
            Some("198.51.100.10:1234".parse().unwrap()),
            "cdn.example.com",
            "https",
            &route,
        )
        .unwrap();

        assert_eq!(
            headers
                .get(ReqHeaderName::from_static("x-forwarded-host"))
                .unwrap()
                .to_str()
                .unwrap(),
            "cdn.example.com"
        );
        assert_eq!(
            headers
                .get(ReqHeaderName::from_static("x-forwarded-proto"))
                .unwrap()
                .to_str()
                .unwrap(),
            "https"
        );
        assert_eq!(
            headers
                .get(ReqHeaderName::from_static("x-forwarded-for"))
                .unwrap()
                .to_str()
                .unwrap(),
            "203.0.113.1, 198.51.100.10"
        );
    }

    #[test]
    fn client_scheme_prefers_request_uri() {
        let request = Request::builder()
            .uri("https://cdn.example.com/video")
            .body(Body::empty())
            .unwrap();

        let scheme = determine_client_scheme(&request).expect("scheme should be detected");
        assert_eq!(scheme, "https");
    }

    #[test]
    fn client_scheme_falls_back_to_original_uri_extension() {
        let mut request = Request::builder()
            .uri("/playlist.m3u8")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(OriginalUri(Uri::from_static(
                "https://cdn.example.com/playlist.m3u8",
            )));

        let scheme = determine_client_scheme(&request).expect("scheme should be detected");
        assert_eq!(scheme, "https");
    }

    #[test]
    fn client_scheme_reads_forwarded_header() {
        let request = Request::builder()
            .uri("/video")
            .header(FORWARDED, "for=198.51.100.10; proto=https")
            .body(Body::empty())
            .unwrap();

        let scheme = determine_client_scheme(&request).expect("scheme should be detected");
        assert_eq!(scheme, "https");
    }

    #[test]
    fn client_scheme_reads_x_forwarded_proto_header() {
        let request = Request::builder()
            .uri("/video")
            .header("x-forwarded-proto", "https, http")
            .body(Body::empty())
            .unwrap();

        let scheme = determine_client_scheme(&request).expect("scheme should be detected");
        assert_eq!(scheme, "https");
    }

    #[test]
    fn client_scheme_ignores_unknown_values() {
        let request = Request::builder()
            .uri("/video")
            .header("x-forwarded-proto", "ftp")
            .body(Body::empty())
            .unwrap();

        assert!(determine_client_scheme(&request).is_none());
    }

    #[test]
    fn client_builder_applies_configured_timeouts() {
        let route = RouteTarget {
            upstream: "http://example.com".into(),
            connect_timeout: Some(Duration::from_millis(150)),
            read_timeout: Some(Duration::from_millis(450)),
            request_timeout: None,
            tls_insecure_skip_verify: false,
            socks5: None,
            hls: None,
            retry: RetryPolicy::default(),
            header_policy: crate::state::HeaderPolicy::default(),
        };

        let builder = apply_client_timeouts(Client::builder(), &route);
        let debug = format!("{builder:?}");
        assert!(debug.contains("connect_timeout"));
        assert!(debug.contains("150ms"));
        assert!(debug.contains("timeout"));
        assert!(debug.contains("450ms"));
    }

    #[tokio::test]
    async fn lookup_route_matches_host_glob() {
        let definition = RouteDefinition {
            id: "glob-route".into(),
            host_patterns: vec!["*.example.net".into()],
            protocols: vec![RouteProtocol::Http],
            ports: vec![PortRange::new(80, 80).unwrap()],
        };
        let target = RouteTarget {
            upstream: "http://example.com".into(),
            ..Default::default()
        };
        let state = state_with_single_route(definition, target);

        let request = RouteRequest {
            host: Some("api.example.net"),
            protocol: RouteProtocol::Http,
            port: 80,
        };

        let (route_id, _) = lookup_route(&state, "api.example.net", &request)
            .await
            .expect("glob route should match");
        assert_eq!(route_id, "glob-route");
    }

    #[tokio::test]
    async fn lookup_route_considers_protocol() {
        let definition = RouteDefinition {
            id: "secure-route".into(),
            host_patterns: vec!["secure.test".into()],
            protocols: vec![RouteProtocol::Https],
            ports: vec![PortRange::new(443, 443).unwrap()],
        };
        let target = RouteTarget {
            upstream: "https://example.com".into(),
            ..Default::default()
        };
        let state = state_with_single_route(definition, target);

        let https_request = RouteRequest {
            host: Some("secure.test"),
            protocol: RouteProtocol::Https,
            port: 443,
        };
        let (route_id, _) = lookup_route(&state, "secure.test", &https_request)
            .await
            .expect("https route should match");
        assert_eq!(route_id, "secure-route");

        let http_request = RouteRequest {
            host: Some("secure.test"),
            protocol: RouteProtocol::Http,
            port: 443,
        };
        let error = lookup_route(&state, "secure.test", &http_request)
            .await
            .expect_err("http request should not match https route");
        match error {
            ProxyError::RouteNotFound { host } => assert_eq!(host, "secure.test"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn lookup_route_considers_port() {
        let definition = RouteDefinition {
            id: "port-route".into(),
            host_patterns: vec!["edge.test".into()],
            protocols: vec![RouteProtocol::Http],
            ports: vec![PortRange::new(8000, 8005).unwrap()],
        };
        let target = RouteTarget {
            upstream: "http://example.com".into(),
            ..Default::default()
        };
        let state = state_with_single_route(definition, target);

        let matching = RouteRequest {
            host: Some("edge.test"),
            protocol: RouteProtocol::Http,
            port: 8003,
        };
        lookup_route(&state, "edge.test", &matching)
            .await
            .expect("port within range should match");

        let mismatch = RouteRequest {
            host: Some("edge.test"),
            protocol: RouteProtocol::Http,
            port: 9000,
        };
        let error = lookup_route(&state, "edge.test", &mismatch)
            .await
            .expect_err("port outside range should not match");
        match error {
            ProxyError::RouteNotFound { host } => assert_eq!(host, "edge.test"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_timeout_is_enforced_for_slow_upstream() {
        let delay = Duration::from_millis(250);
        let (addr, shutdown) = spawn_delayed_http_server(delay).await;

        let route = RouteTarget {
            upstream: format!("http://{}", addr),
            connect_timeout: Some(Duration::from_secs(1)),
            read_timeout: Some(Duration::from_millis(500)),
            request_timeout: Some(Duration::from_millis(100)),
            tls_insecure_skip_verify: false,
            socks5: None,
            hls: None,
            retry: RetryPolicy::default(),
            header_policy: crate::state::HeaderPolicy::default(),
        };

        let definition = RouteDefinition {
            id: "timeout-route".into(),
            host_patterns: vec!["timeout.test".into()],
            protocols: vec![RouteProtocol::Http],
            ports: vec![PortRange::new(80, 80).unwrap()],
        };
        let state = state_with_single_route(definition, route);

        let request = Request::builder()
            .uri("http://timeout.test/playlist.m3u8")
            .header(HOST, "timeout.test")
            .body(Body::empty())
            .unwrap();

        let error = forward(state.clone(), request)
            .await
            .expect_err("upstream call should time out");

        match error {
            ProxyError::UpstreamRequest { source } => {
                assert!(source.is_timeout(), "unexpected error: {source:?}");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn read_timeout_is_used_when_request_timeout_missing() {
        let delay = Duration::from_millis(250);
        let (addr, shutdown) = spawn_delayed_http_server(delay).await;

        let route = RouteTarget {
            upstream: format!("http://{}", addr),
            connect_timeout: Some(Duration::from_secs(1)),
            read_timeout: Some(Duration::from_millis(120)),
            request_timeout: None,
            tls_insecure_skip_verify: false,
            socks5: None,
            hls: None,
            retry: RetryPolicy::default(),
            header_policy: crate::state::HeaderPolicy::default(),
        };

        let definition = RouteDefinition {
            id: "read-timeout-route".into(),
            host_patterns: vec!["timeout.test".into()],
            protocols: vec![RouteProtocol::Http],
            ports: vec![PortRange::new(80, 80).unwrap()],
        };
        let state = state_with_single_route(definition, route);

        let request = Request::builder()
            .uri("http://timeout.test/index.m3u8")
            .header(HOST, "timeout.test")
            .body(Body::empty())
            .unwrap();

        let error = forward(state.clone(), request)
            .await
            .expect_err("upstream call should respect read timeout");

        match error {
            ProxyError::UpstreamRequest { source } => {
                assert!(source.is_timeout(), "unexpected error: {source:?}");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn forward_records_tracing_metadata() {
        let (addr, shutdown) = spawn_delayed_http_server(Duration::from_millis(0)).await;

        let route = RouteTarget {
            upstream: format!("http://{}", addr),
            connect_timeout: Some(Duration::from_secs(1)),
            read_timeout: Some(Duration::from_secs(1)),
            request_timeout: Some(Duration::from_secs(1)),
            tls_insecure_skip_verify: false,
            socks5: None,
            hls: None,
            retry: RetryPolicy::default(),
            header_policy: crate::state::HeaderPolicy::default(),
        };

        let definition = RouteDefinition {
            id: "trace-route".into(),
            host_patterns: vec!["trace.test".into()],
            protocols: vec![RouteProtocol::Http],
            ports: vec![PortRange::new(80, 80).unwrap()],
        };
        let state = state_with_single_route(definition, route);

        let request = Request::builder()
            .uri("http://trace.test/")
            .header(HOST, "trace.test")
            .body(Body::empty())
            .unwrap();

        let spans: Arc<Mutex<HashMap<u64, RecordedSpan>>> = Arc::new(Mutex::new(HashMap::new()));
        let events: Arc<Mutex<Vec<RecordedEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let layer = TestLayer::new(Arc::clone(&spans), Arc::clone(&events));
        let subscriber = Registry::default().with(layer);
        let _guard = set_default(subscriber);

        let response = forward(state.clone(), request)
            .await
            .expect("forward should succeed");

        assert_eq!(response.status(), http::StatusCode::OK);

        let spans_guard = spans.lock().expect("span collection should be accessible");
        let forward_span = spans_guard
            .values()
            .find(|span| span.name == "proxy.forward")
            .expect("forward span should be recorded");

        assert!(forward_span
            .fields
            .get("route.id")
            .map(|value| value.contains("trace-route"))
            .unwrap_or(false));
        assert!(forward_span
            .fields
            .get("route.host")
            .map(|value| value.contains("trace.test"))
            .unwrap_or(false));

        let expected_upstream = format!("http://{}/", addr);
        assert!(forward_span
            .fields
            .get("upstream.url")
            .map(|value| value.contains(&expected_upstream))
            .unwrap_or(false));
        assert!(forward_span
            .fields
            .get("client.scheme")
            .map(|value| value.contains("http"))
            .unwrap_or(false));
        drop(spans_guard);

        let events_guard = events
            .lock()
            .expect("event collection should be accessible");
        let response_event = events_guard
            .iter()
            .find(|event| {
                event
                    .fields
                    .get("message")
                    .map(|message| message == "forwarded upstream response")
                    .unwrap_or(false)
            })
            .expect("response event should be recorded");

        assert!(response_event
            .fields
            .get("status")
            .map(|value| value.contains("200"))
            .unwrap_or(false));

        response_event
            .fields
            .get("latency_ms")
            .expect("latency should be recorded")
            .parse::<u64>()
            .expect("latency should be numeric");
        drop(events_guard);

        let _ = shutdown.send(());
    }

    struct RecordedSpan {
        name: String,
        fields: HashMap<String, String>,
    }

    struct RecordedEvent {
        fields: HashMap<String, String>,
    }

    #[derive(Default)]
    struct FieldVisitor {
        fields: HashMap<String, String>,
    }

    impl Visit for FieldVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone)]
    struct TestLayer {
        spans: Arc<Mutex<HashMap<u64, RecordedSpan>>>,
        events: Arc<Mutex<Vec<RecordedEvent>>>,
    }

    impl TestLayer {
        fn new(
            spans: Arc<Mutex<HashMap<u64, RecordedSpan>>>,
            events: Arc<Mutex<Vec<RecordedEvent>>>,
        ) -> Self {
            Self { spans, events }
        }
    }

    impl<S> tracing_subscriber::layer::Layer<S> for TestLayer
    where
        S: tracing::Subscriber,
    {
        fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, _: Context<'_, S>) {
            let mut visitor = FieldVisitor::default();
            attrs.record(&mut visitor);
            let recorded = RecordedSpan {
                name: attrs.metadata().name().to_string(),
                fields: visitor.fields,
            };
            if let Ok(mut spans) = self.spans.lock() {
                spans.insert(id.into_u64(), recorded);
            }
        }

        fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, _: Context<'_, S>) {
            if let Ok(mut spans) = self.spans.lock() {
                if let Some(span) = spans.get_mut(&id.into_u64()) {
                    let mut visitor = FieldVisitor::default();
                    values.record(&mut visitor);
                    span.fields.extend(visitor.fields);
                }
            }
        }

        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            if let Ok(mut events) = self.events.lock() {
                events.push(RecordedEvent {
                    fields: visitor.fields,
                });
            }
        }
    }

    #[cfg(feature = "telemetry")]
    mod telemetry_integration {
        use super::*;
        use crate::state::HlsOptions;
        use axum::body::to_bytes;

        const SAMPLE_VARIANT_MANIFEST: &str = "#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-MAP:URI=\"init/init.mp4\",BYTERANGE=\"720@0\"\n#EXT-X-KEY:METHOD=AES-128,URI=\"keys/key.key\",IV=0x1ABC\n#EXT-X-STREAM-INF:BANDWIDTH=1280000,AVERAGE-BANDWIDTH=1100000,CODECS=\"avc1.640029,mp4a.40.2\"\nvideo/main.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=640000,RESOLUTION=640x360\nhttp://origin.example.com/video/low.m3u8\n";

        #[tokio::test]
        async fn hls_manifests_are_rewritten_without_mixed_content() {
            let (addr, shutdown) = spawn_static_response_server(
                SAMPLE_VARIANT_MANIFEST.as_bytes(),
                "application/vnd.apple.mpegurl",
            )
            .await;

            let hls_options = HlsOptions {
                enabled: true,
                rewrite_playlist_urls: true,
                base_url: Some(Url::parse("https://cdn.example.com/hls/").unwrap()),
                allow_insecure_segments: false,
            };

            let route = RouteTarget {
                upstream: format!("http://{}", addr),
                connect_timeout: Some(Duration::from_secs(1)),
                read_timeout: Some(Duration::from_secs(1)),
                request_timeout: Some(Duration::from_secs(1)),
                tls_insecure_skip_verify: false,
                socks5: None,
                hls: Some(hls_options),
                retry: RetryPolicy::default(),
                header_policy: crate::state::HeaderPolicy::default(),
            };

            let definition = RouteDefinition {
                id: "hls-route".into(),
                host_patterns: vec!["cdn.test".into()],
                protocols: vec![RouteProtocol::Http],
                ports: vec![PortRange::new(80, 80).unwrap()],
            };
            let state = state_with_single_route(definition, route);

            let request = Request::builder()
                .uri("http://cdn.test/master.m3u8")
                .header(HOST, "cdn.test")
                .body(Body::empty())
                .unwrap();

            let response = forward(state.clone(), request)
                .await
                .expect("forward should succeed");

            assert_eq!(response.status(), http::StatusCode::OK);

            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should be readable");
            let output = String::from_utf8(body.to_vec()).expect("manifest should remain UTF-8");

            assert!(output.contains(
                "#EXT-X-MAP:URI=\"https://cdn.example.com/hls/init/init.mp4\",BYTERANGE=\"720@0\""
            ));
            assert!(output.contains(
                "#EXT-X-KEY:METHOD=AES-128,URI=\"https://cdn.example.com/hls/keys/key.key\",IV=0x1ABC"
            ));
            assert!(output.contains(
                "#EXT-X-STREAM-INF:BANDWIDTH=1280000,AVERAGE-BANDWIDTH=1100000,CODECS=\"avc1.640029,mp4a.40.2\""
            ));
            assert!(output.contains("https://cdn.example.com/hls/video/main.m3u8"));
            assert!(output.contains("https://cdn.example.com/hls/video/low.m3u8"));
            assert!(
                !output.contains("http://"),
                "rewritten manifest should not include insecure URLs"
            );

            let _ = shutdown.send(());
        }
    }
}
