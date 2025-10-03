use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{
        header::{
            self, InvalidHeaderName as HttpInvalidHeaderName,
            InvalidHeaderValue as HttpInvalidHeaderValue,
        },
        Error as HttpError, HeaderMap, HeaderName as HttpHeaderName, HeaderValue, Response,
        StatusCode, Uri,
    },
};
use futures::{FutureExt, TryStream, TryStreamExt};
use hyper::body::Bytes;
use hyper::{
    client::connect::dns::{GaiResolver as HyperGaiResolver, Name},
    service::Service,
};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use reqwest::{
    dns::{Addrs as DnsAddrs, Resolve as DnsResolve, Resolving as DnsResolving},
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue, InvalidHeaderName as ReqwestInvalidHeaderName,
        InvalidHeaderValue as ReqwestInvalidHeaderValue, CONTENT_LENGTH, CONTENT_RANGE, LOCATION,
    },
    Client, Method, Url,
};
use serde::Deserialize;
use thiserror::Error;
use url::form_urlencoded;

use crate::retry;
use crate::state::{DirectStreamSettings, SharedAppState};
use crate::util;
use tracing::{error, info};

const DIRECT_STREAM_PASSWORD_HEADER: &str = "x-sprox-api-password";
const DIRECT_STREAM_PASSWORD_QUERY_KEY: &str = "api_password";

const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "etag",
    "last-modified",
    "cache-control",
    "expires",
    "pragma",
];

const STREAM_CHUNK_SIZE: usize = 64 * 1024;

const MAX_REDIRECTS: usize = 10;

static RESTRICTED_NETWORKS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    vec![
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    ]
    .into_iter()
    .map(|entry| {
        entry
            .parse()
            .expect("static IP network definitions are valid")
    })
    .collect()
});

#[derive(Debug, Deserialize)]
pub struct DirectStreamQuery {
    pub d: String,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Error)]
enum DirectStreamError {
    #[error("missing destination url")]
    MissingDestination,

    #[error("missing direct stream password")]
    MissingApiPassword,

    #[error("direct stream password is invalid")]
    InvalidApiPassword,

    #[error("invalid destination url: {source}")]
    InvalidDestination {
        #[source]
        source: url::ParseError,
    },

    #[error("destination url uses unsupported scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },

    #[error("destination url `{url}` is missing a host component")]
    MissingHost { url: String },

    #[error("destination `{url}` is not allowlisted")]
    DestinationNotAllowlisted { url: String },

    #[error("destination `{url}` resolved to restricted address `{ip}`")]
    DestinationAddressRestricted { url: String, ip: IpAddr },

    #[error("invalid override header name `{name}`")]
    InvalidOverrideHeaderName { name: String },

    #[error("invalid override header value for `{name}`")]
    InvalidOverrideHeaderValue {
        name: String,
        #[source]
        source: ReqwestInvalidHeaderValue,
    },

    #[error("override header `{name}` is not allowlisted")]
    OverrideHeaderNotAllowed { name: String },

    #[error("invalid downstream header name `{name}`")]
    InvalidForwardHeaderName {
        name: String,
        #[source]
        source: ReqwestInvalidHeaderName,
    },

    #[error("invalid downstream header value for `{name}`")]
    InvalidForwardHeaderValue {
        name: String,
        #[source]
        source: ReqwestInvalidHeaderValue,
    },

    #[error("invalid upstream header name: {source}")]
    InvalidInboundHeaderName {
        #[source]
        source: HttpInvalidHeaderName,
    },

    #[error("invalid upstream header value: {source}")]
    InvalidInboundHeaderValue {
        #[source]
        source: HttpInvalidHeaderValue,
    },

    #[error("failed to build response: {source}")]
    ResponseBuild {
        #[from]
        source: HttpError,
    },

    #[error("upstream request failed: {source}")]
    UpstreamRequest { source: reqwest::Error },

    #[error("retry budget exhausted for upstream request: {source}")]
    RetryBudgetExhausted { source: reqwest::Error },

    #[error("upstream returned status {status}")]
    UpstreamStatus { status: StatusCode },

    #[error("upstream responded with status {status} but did not include required range headers")]
    InvalidRangeResponse { status: StatusCode },

    #[error("failed to initialize direct stream client: {source}")]
    ClientBuild { source: reqwest::Error },

    #[error("redirect chain exceeded {limit} hops")]
    RedirectLimitExceeded { limit: usize },

    #[error("redirect response missing location header")]
    RedirectLocationMissing,

    #[error("redirect target `{location}` is invalid: {source}")]
    InvalidRedirectLocation {
        location: String,
        #[source]
        source: url::ParseError,
    },

    #[error("redirect target contains invalid characters")]
    InvalidRedirectEncoding,
}

impl DirectStreamError {
    fn into_response(self) -> (StatusCode, String) {
        match self {
            Self::MissingDestination => (
                StatusCode::BAD_REQUEST,
                "query parameter `d` is required".to_string(),
            ),
            Self::InvalidDestination { source } => (
                StatusCode::BAD_REQUEST,
                format!("invalid destination url: {source}"),
            ),
            Self::UnsupportedScheme { scheme } => (
                StatusCode::BAD_REQUEST,
                format!("destination url uses unsupported scheme `{scheme}`"),
            ),
            Self::MissingHost { url } => (
                StatusCode::BAD_REQUEST,
                format!("destination url `{url}` must include a host"),
            ),
            Self::DestinationNotAllowlisted { url } => (
                StatusCode::FORBIDDEN,
                format!("destination `{url}` is not allowlisted"),
            ),
            Self::DestinationAddressRestricted { url, ip } => (
                StatusCode::FORBIDDEN,
                format!("destination `{url}` resolved to restricted address `{ip}`"),
            ),
            Self::InvalidOverrideHeaderName { name } => (
                StatusCode::BAD_REQUEST,
                format!("header override `{name}` is not allowed"),
            ),
            Self::InvalidOverrideHeaderValue { name, .. } => (
                StatusCode::BAD_REQUEST,
                format!("header override `{name}` has an invalid value"),
            ),
            Self::OverrideHeaderNotAllowed { name } => (
                StatusCode::BAD_REQUEST,
                format!("header override `{name}` is not allowlisted"),
            ),
            Self::InvalidForwardHeaderName { name, .. } => (
                StatusCode::BAD_REQUEST,
                format!("header `{name}` on downstream request is not allowed"),
            ),
            Self::InvalidForwardHeaderValue { name, .. } => (
                StatusCode::BAD_REQUEST,
                format!("header `{name}` on downstream request has an invalid value"),
            ),
            Self::InvalidInboundHeaderName { source } => (
                StatusCode::BAD_GATEWAY,
                format!("upstream returned an invalid header name: {source}"),
            ),
            Self::InvalidInboundHeaderValue { source } => (
                StatusCode::BAD_GATEWAY,
                format!("upstream returned an invalid header value: {source}"),
            ),
            Self::ResponseBuild { source } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to construct response: {source}"),
            ),
            Self::MissingApiPassword => (
                StatusCode::UNAUTHORIZED,
                "direct stream password is required".to_string(),
            ),
            Self::InvalidApiPassword => (
                StatusCode::FORBIDDEN,
                "direct stream password is invalid".to_string(),
            ),
            Self::ClientBuild { source } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to initialize direct stream client: {source}"),
            ),
            Self::UpstreamRequest { source } => {
                if source.is_timeout() {
                    (
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream request timed out".to_string(),
                    )
                } else {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("upstream request failed: {source}"),
                    )
                }
            }
            Self::RetryBudgetExhausted { source } => (
                StatusCode::BAD_GATEWAY,
                format!("retry budget exhausted for upstream request: {source}"),
            ),
            Self::UpstreamStatus { status } => {
                (status, format!("upstream responded with status {status}"))
            }
            Self::InvalidRangeResponse { status } => (
                StatusCode::BAD_GATEWAY,
                format!(
                    "upstream responded with status {status} but omitted required range headers"
                ),
            ),
            Self::RedirectLimitExceeded { limit } => (
                StatusCode::BAD_GATEWAY,
                format!("redirect chain exceeded {limit} hops"),
            ),
            Self::RedirectLocationMissing => (
                StatusCode::BAD_GATEWAY,
                "upstream redirect did not include a location header".to_string(),
            ),
            Self::InvalidRedirectLocation { location, source } => (
                StatusCode::BAD_GATEWAY,
                format!("redirect location `{location}` is invalid: {source}"),
            ),
            Self::InvalidRedirectEncoding => (
                StatusCode::BAD_GATEWAY,
                "redirect location header is not valid UTF-8".to_string(),
            ),
        }
    }
}

#[tracing::instrument(
    name = "stream.direct",
    skip(state, downstream_headers),
    fields(
        request.id = tracing::field::Empty,
        upstream.url = tracing::field::Empty
    )
)]
pub async fn handle_proxy_stream(
    State(state): State<SharedAppState>,
    downstream_headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DirectStreamQuery>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let request_id = util::extract_request_id(&downstream_headers);
    let span = tracing::Span::current();
    span.record("request.id", tracing::field::display(&request_id));

    if query.d.trim().is_empty() {
        return Err(DirectStreamError::MissingDestination.into_response());
    }

    if let Some(expected_password) = state.with_current(|state| {
        state
            .direct_stream_api_password()
            .map(|value| value.to_owned())
    }) {
        let provided_password = extract_api_password(&downstream_headers, &query);
        match provided_password {
            Some(value) if value == expected_password => {}
            Some(_) => {
                return Err(DirectStreamError::InvalidApiPassword.into_response());
            }
            None => {
                return Err(DirectStreamError::MissingApiPassword.into_response());
            }
        }
    }

    let upstream_url = Url::parse(&query.d)
        .map_err(|source| DirectStreamError::InvalidDestination { source }.into_response())?;
    span.record("upstream.url", tracing::field::display(&upstream_url));

    let settings = state
        .with_current(|state| state.direct_stream_settings().cloned())
        .unwrap_or_default();

    let overrides = extract_header_overrides(&uri);
    let upstream_headers = prepare_upstream_headers(&downstream_headers, &overrides, &settings)
        .map_err(|error| error.into_response())?;

    let client = state
        .with_current(|state| state.direct_stream_client())
        .map_err(|source| DirectStreamError::ClientBuild { source }.into_response())?;
    let service = DirectStreamService::new(client, settings);

    let start = Instant::now();
    let stream_result = match service.stream(upstream_url, upstream_headers).await {
        Ok(result) => result,
        Err(error) => {
            error!(request.id = %request_id, error = %error, "direct stream request failed");
            return Err(error.into_response());
        }
    };
    let latency = start.elapsed();

    let StreamResult {
        response,
        final_url,
        head_attempts,
        get_attempts,
        response_bytes,
    } = stream_result;

    span.record("upstream.url", tracing::field::display(&final_url));

    let status = response.status();
    let response_bytes = response_bytes.unwrap_or_default();
    let head_retries = head_attempts.saturating_sub(1);
    let get_retries = get_attempts.saturating_sub(1);
    let total_retries = head_retries + get_retries;
    let latency_ms = latency.as_millis() as u64;

    info!(
        request.id = %request_id,
        upstream.url = %final_url,
        status = %status,
        latency_ms,
        retry.count.head = head_retries,
        retry.count.get = get_retries,
        retry.count.total = total_retries,
        response.bytes = response_bytes,
        "completed direct stream"
    );

    #[cfg(feature = "telemetry")]
    {
        metrics::counter!("sprox_requests_total", "route" => "direct_stream").increment(1);
        metrics::histogram!(
            "sprox_upstream_latency_seconds",
            "route" => "direct_stream",
        )
        .record(latency.as_secs_f64());
        metrics::counter!(
            "sprox_bytes_streamed_total",
            "route" => "direct_stream",
        )
        .increment(response_bytes);
    }

    Ok(response)
}

fn extract_api_password(headers: &HeaderMap, query: &DirectStreamQuery) -> Option<String> {
    headers
        .get(DIRECT_STREAM_PASSWORD_HEADER)
        .and_then(|value| value.to_str().ok().map(|value| value.to_owned()))
        .or_else(|| query.extra.get(DIRECT_STREAM_PASSWORD_QUERY_KEY).cloned())
}

fn extract_header_overrides(uri: &Uri) -> Vec<(String, String)> {
    uri.query()
        .map(|query| {
            form_urlencoded::parse(query.as_bytes())
                .filter_map(|(key, value)| {
                    key.strip_prefix("h_")
                        .map(|name| (name.replace('_', "-"), value.into_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn prepare_upstream_headers(
    downstream: &HeaderMap,
    overrides: &[(String, String)],
    settings: &DirectStreamSettings,
) -> Result<ReqwestHeaderMap, DirectStreamError> {
    let mut sanitized = ReqwestHeaderMap::new();

    for (name, value) in downstream.iter() {
        if !settings.is_request_header_allowed(name.as_str()) {
            continue;
        }

        let header_name =
            ReqwestHeaderName::from_bytes(name.as_str().as_bytes()).map_err(|source| {
                DirectStreamError::InvalidForwardHeaderName {
                    name: name.to_string(),
                    source,
                }
            })?;

        let header_value = ReqwestHeaderValue::from_bytes(value.as_bytes()).map_err(|source| {
            DirectStreamError::InvalidForwardHeaderValue {
                name: name.to_string(),
                source,
            }
        })?;

        sanitized.append(header_name, header_value);
    }

    for (raw_name, raw_value) in overrides {
        let header_name = ReqwestHeaderName::from_bytes(raw_name.as_bytes()).map_err(|_| {
            DirectStreamError::InvalidOverrideHeaderName {
                name: raw_name.clone(),
            }
        })?;

        if !settings.is_request_header_allowed(header_name.as_str()) {
            return Err(DirectStreamError::OverrideHeaderNotAllowed {
                name: header_name.to_string(),
            });
        }

        let header_value = ReqwestHeaderValue::from_str(raw_value).map_err(|source| {
            DirectStreamError::InvalidOverrideHeaderValue {
                name: header_name.to_string(),
                source,
            }
        })?;

        sanitized.insert(header_name, header_value);
    }

    Ok(sanitized)
}

fn is_response_header_allowed(name: &str) -> bool {
    RESPONSE_HEADER_ALLOWLIST
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

#[derive(Clone)]
struct DirectStreamService {
    client: Client,
    settings: DirectStreamSettings,
}

impl DirectStreamService {
    fn new(client: Client, settings: DirectStreamSettings) -> Self {
        Self { client, settings }
    }

    async fn stream(
        &self,
        url: Url,
        headers: ReqwestHeaderMap,
    ) -> Result<StreamResult, DirectStreamError> {
        let head_outcome = self
            .send_with_redirects(Method::HEAD, url, headers.clone())
            .await?;
        let head_attempts = head_outcome.attempts;
        let head_status = head_outcome.response.status();

        if !matches!(
            head_status,
            reqwest::StatusCode::METHOD_NOT_ALLOWED | reqwest::StatusCode::NOT_IMPLEMENTED
        ) {
            validate_upstream_status(head_status)?;
        }

        let get_outcome = self
            .send_with_redirects(Method::GET, head_outcome.final_url, headers)
            .await?;
        let get_attempts = get_outcome.attempts;

        validate_upstream_status(get_outcome.response.status())?;

        let mut response_headers = HeaderMap::new();
        let mut has_accept_ranges = false;
        let mut content_length_value: Option<HeaderValue> = None;
        let mut content_range_value: Option<HeaderValue> = None;

        for (name, value) in get_outcome.response.headers().iter() {
            if !is_response_header_allowed(name.as_str()) {
                continue;
            }

            if name == CONTENT_LENGTH {
                let header_value = HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|source| DirectStreamError::InvalidInboundHeaderValue { source })?;
                content_length_value = Some(header_value);
                continue;
            }

            if name == CONTENT_RANGE {
                let header_value = HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|source| DirectStreamError::InvalidInboundHeaderValue { source })?;
                content_range_value = Some(header_value);
                continue;
            }

            let header_name = HttpHeaderName::from_bytes(name.as_str().as_bytes())
                .map_err(|source| DirectStreamError::InvalidInboundHeaderName { source })?;

            let header_value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|source| DirectStreamError::InvalidInboundHeaderValue { source })?;

            if header_name == header::ACCEPT_RANGES {
                has_accept_ranges = true;
            }

            response_headers.append(header_name, header_value);
        }

        let upstream_status = get_outcome.response.status();
        let status =
            StatusCode::from_u16(upstream_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let expects_partial = upstream_status == reqwest::StatusCode::PARTIAL_CONTENT;

        if expects_partial && content_range_value.is_none() {
            return Err(DirectStreamError::InvalidRangeResponse { status });
        }

        if !expects_partial && content_range_value.is_some() {
            return Err(DirectStreamError::InvalidRangeResponse { status });
        }

        if let Some(value) = content_range_value {
            response_headers.insert(header::CONTENT_RANGE, value);
        }

        let known_length = get_outcome.response.content_length();
        let response_bytes = known_length;

        if let Some(length) = known_length {
            let header_value = if let Some(value) = content_length_value {
                value
            } else {
                HeaderValue::from_str(&length.to_string())
                    .map_err(|source| DirectStreamError::InvalidInboundHeaderValue { source })?
            };
            response_headers.insert(header::CONTENT_LENGTH, header_value);
        }

        if !has_accept_ranges {
            response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        }

        let stream = get_outcome
            .response
            .bytes_stream()
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error));
        let chunked_stream = ChunkedBody::new(stream);

        let body = Body::from_stream(chunked_stream);

        let mut response = Response::builder().status(status).body(body)?;
        *response.headers_mut() = response_headers;

        Ok(StreamResult {
            response,
            final_url: get_outcome.final_url,
            head_attempts,
            get_attempts,
            response_bytes,
        })
    }

    async fn send_with_redirects(
        &self,
        method: Method,
        url: Url,
        headers: ReqwestHeaderMap,
    ) -> Result<RequestOutcome, DirectStreamError> {
        let mut current_url = url;
        let mut redirects = 0;
        let mut total_attempts = 0;

        loop {
            self.validate_destination(&current_url).await?;

            let request = self
                .client
                .request(method.clone(), current_url.clone())
                .headers(headers.clone())
                .timeout(self.settings.request_timeout())
                .build()
                .map_err(|source| DirectStreamError::UpstreamRequest { source })?;

            let retry_policy = self.settings.retry().clone();
            let retry_outcome =
                retry::execute_with_retry(self.client.clone(), request, retry_policy).await;
            let attempts = retry_outcome.attempts();
            total_attempts += attempts;
            let response = match retry_outcome.into_result() {
                Ok(response) => response,
                Err(error) => {
                    let budget_exhausted = error.is_budget_exhausted();
                    let source = error.into_source();
                    if let Some(ip) = extract_restricted_ip(&source) {
                        return Err(DirectStreamError::DestinationAddressRestricted {
                            url: current_url.to_string(),
                            ip,
                        });
                    }

                    if budget_exhausted {
                        return Err(DirectStreamError::RetryBudgetExhausted { source });
                    }

                    return Err(DirectStreamError::UpstreamRequest { source });
                }
            };

            if let Some(next_url) = self.extract_redirect(&current_url, &response)? {
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(DirectStreamError::RedirectLimitExceeded {
                        limit: MAX_REDIRECTS,
                    });
                }

                current_url = next_url;
                continue;
            }

            return Ok(RequestOutcome {
                response,
                final_url: current_url,
                attempts: total_attempts,
            });
        }
    }

    async fn validate_destination(&self, url: &Url) -> Result<(), DirectStreamError> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(DirectStreamError::UnsupportedScheme {
                scheme: scheme.to_string(),
            });
        }

        if !self.settings.allowlist().allows(url) {
            return Err(DirectStreamError::DestinationNotAllowlisted {
                url: url.to_string(),
            });
        }

        match url.host() {
            Some(url::Host::Domain(_)) => {}
            Some(url::Host::Ipv4(addr)) => {
                self.ensure_ip_allowed(url, IpAddr::V4(addr))?;
            }
            Some(url::Host::Ipv6(addr)) => {
                self.ensure_ip_allowed(url, IpAddr::V6(addr))?;
            }
            None => {
                return Err(DirectStreamError::MissingHost {
                    url: url.to_string(),
                })
            }
        }

        Ok(())
    }

    fn ensure_ip_allowed(&self, url: &Url, ip: IpAddr) -> Result<(), DirectStreamError> {
        if is_ip_restricted(&ip) {
            return Err(DirectStreamError::DestinationAddressRestricted {
                url: url.to_string(),
                ip,
            });
        }

        Ok(())
    }

    fn extract_redirect(
        &self,
        current: &Url,
        response: &reqwest::Response,
    ) -> Result<Option<Url>, DirectStreamError> {
        if !response.status().is_redirection() {
            return Ok(None);
        }

        let location = response
            .headers()
            .get(LOCATION)
            .ok_or(DirectStreamError::RedirectLocationMissing)?
            .to_str()
            .map_err(|_| DirectStreamError::InvalidRedirectEncoding)?
            .to_owned();

        let next = current
            .join(&location)
            .map_err(|source| DirectStreamError::InvalidRedirectLocation { location, source })?;

        Ok(Some(next))
    }
}

struct ChunkedBody<S> {
    inner: S,
    buffer: Vec<u8>,
    finished: bool,
}

impl<S> ChunkedBody<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            finished: false,
        }
    }

    fn flush_chunk(&mut self, limit: usize) -> Option<Bytes> {
        if self.buffer.is_empty() {
            return None;
        }

        let chunk = if self.buffer.len() > limit {
            let remainder = self.buffer.split_off(limit);
            std::mem::replace(&mut self.buffer, remainder)
        } else {
            std::mem::take(&mut self.buffer)
        };

        Some(Bytes::from(chunk))
    }
}

impl<S> futures::Stream for ChunkedBody<S>
where
    S: TryStream<Ok = Bytes, Error = io::Error> + Unpin,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            if let Some(chunk) = self.flush_chunk(STREAM_CHUNK_SIZE) {
                return std::task::Poll::Ready(Some(Ok(chunk)));
            }

            if self.finished {
                return if let Some(chunk) = self.flush_chunk(STREAM_CHUNK_SIZE) {
                    std::task::Poll::Ready(Some(Ok(chunk)))
                } else {
                    std::task::Poll::Ready(None)
                };
            }

            match std::pin::Pin::new(&mut self.inner).try_poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(bytes))) => {
                    if !bytes.is_empty() {
                        self.buffer.extend_from_slice(&bytes);
                    }
                }
                std::task::Poll::Ready(Some(Err(error))) => {
                    return std::task::Poll::Ready(Some(Err(error)))
                }
                std::task::Poll::Ready(None) => {
                    self.finished = true;
                }
                std::task::Poll::Pending => {
                    return if let Some(chunk) = self.flush_chunk(STREAM_CHUNK_SIZE) {
                        std::task::Poll::Ready(Some(Ok(chunk)))
                    } else {
                        std::task::Poll::Pending
                    };
                }
            }
        }
    }
}

struct RequestOutcome {
    response: reqwest::Response,
    final_url: Url,
    attempts: u32,
}

struct StreamResult {
    response: Response<Body>,
    final_url: Url,
    head_attempts: u32,
    get_attempts: u32,
    response_bytes: Option<u64>,
}

fn validate_upstream_status(status: reqwest::StatusCode) -> Result<(), DirectStreamError> {
    if status.is_success() || status == reqwest::StatusCode::PARTIAL_CONTENT {
        Ok(())
    } else {
        Err(DirectStreamError::UpstreamStatus {
            status: StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
        })
    }
}

fn is_ip_restricted(ip: &IpAddr) -> bool {
    if RESTRICTED_NETWORKS.iter().any(|net| net.contains(ip)) {
        return true;
    }

    match ip {
        IpAddr::V4(addr) => {
            addr.is_private()
                || addr.is_link_local()
                || addr.is_broadcast()
                || addr.is_documentation()
                || addr.is_unspecified()
        }
        IpAddr::V6(addr) => addr.is_multicast() || addr.is_unspecified(),
    }
}

fn extract_restricted_ip(error: &reqwest::Error) -> Option<IpAddr> {
    let mut current: &(dyn std::error::Error + 'static) = error;

    loop {
        if let Some(restricted) = current.downcast_ref::<RestrictedIpError>() {
            return Some(restricted.ip());
        }

        match current.source() {
            Some(source) => current = source,
            None => return None,
        }
    }
}

#[derive(Debug)]
struct RestrictedIpError {
    host: String,
    ip: IpAddr,
}

impl RestrictedIpError {
    fn new(host: String, ip: IpAddr) -> Self {
        Self { host, ip }
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }
}

impl fmt::Display for RestrictedIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS resolution for host `{}` returned restricted address `{}`",
            self.host, self.ip
        )
    }
}

impl std::error::Error for RestrictedIpError {}

#[derive(Clone)]
pub(crate) struct RestrictedDnsResolver {
    inner: HyperGaiResolver,
}

impl RestrictedDnsResolver {
    pub(crate) fn new() -> Self {
        Self {
            inner: HyperGaiResolver::new(),
        }
    }
}

impl DnsResolve for RestrictedDnsResolver {
    fn resolve(&self, name: Name) -> DnsResolving {
        let mut resolver = self.inner.clone();
        let host = name.as_str().to_owned();

        Box::pin(
            Service::<Name>::call(&mut resolver, name).map(move |result| match result {
                Ok(addrs) => {
                    let addrs: Vec<SocketAddr> = addrs.collect();

                    if let Some(restricted) = addrs.iter().find(|addr| is_ip_restricted(&addr.ip()))
                    {
                        Err(Box::new(RestrictedIpError::new(host, restricted.ip())) as _)
                    } else {
                        Ok(Box::new(addrs.into_iter()) as DnsAddrs)
                    }
                }
                Err(err) => Err(Box::new(err) as _),
            }),
        )
    }
}
