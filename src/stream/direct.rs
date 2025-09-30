use std::{collections::HashMap, io, time::Duration};

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
use futures::TryStreamExt;
use reqwest::{
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue, InvalidHeaderName as ReqwestInvalidHeaderName,
        InvalidHeaderValue as ReqwestInvalidHeaderValue,
    },
    Client, Url,
};
use serde::Deserialize;
use thiserror::Error;
use url::form_urlencoded;

use crate::state::AppState;

const STREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const REQUEST_HEADER_ALLOWLIST: &[&str] = &[
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

const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "content-length",
    "content-range",
    "content-disposition",
    "content-encoding",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "date",
    "vary",
    "pragma",
    "accept-ranges",
];

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

    #[error("invalid destination url: {source}")]
    InvalidDestination {
        #[source]
        source: url::ParseError,
    },

    #[error("invalid override header name `{name}`")]
    InvalidOverrideHeaderName { name: String },

    #[error("invalid override header value for `{name}`")]
    InvalidOverrideHeaderValue {
        name: String,
        #[source]
        source: ReqwestInvalidHeaderValue,
    },

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
    UpstreamRequest {
        #[from]
        source: reqwest::Error,
    },

    #[error("upstream returned status {status}")]
    UpstreamStatus { status: StatusCode },
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
            Self::InvalidOverrideHeaderName { name } => (
                StatusCode::BAD_REQUEST,
                format!("header override `{name}` is not allowed"),
            ),
            Self::InvalidOverrideHeaderValue { name, .. } => (
                StatusCode::BAD_REQUEST,
                format!("header override `{name}` has an invalid value"),
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
            Self::UpstreamStatus { status } => {
                (status, format!("upstream responded with status {status}"))
            }
        }
    }
}

#[tracing::instrument(name = "stream.direct", skip(state, downstream_headers))]
pub async fn handle_proxy_stream(
    State(state): State<AppState>,
    downstream_headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DirectStreamQuery>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if query.d.trim().is_empty() {
        return Err(DirectStreamError::MissingDestination.into_response());
    }

    let upstream_url = Url::parse(&query.d)
        .map_err(|source| DirectStreamError::InvalidDestination { source }.into_response())?;

    let overrides = extract_header_overrides(&uri);
    let upstream_headers = prepare_upstream_headers(&downstream_headers, &overrides)
        .map_err(|error| error.into_response())?;

    let service = DirectStreamService::new(state.http_client());

    service
        .stream(upstream_url, upstream_headers)
        .await
        .map_err(|error| error.into_response())
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
) -> Result<ReqwestHeaderMap, DirectStreamError> {
    let mut sanitized = ReqwestHeaderMap::new();

    for (name, value) in downstream.iter() {
        if !is_request_header_allowed(name.as_str()) {
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

        if !is_request_header_allowed(header_name.as_str()) {
            continue;
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

fn is_request_header_allowed(name: &str) -> bool {
    REQUEST_HEADER_ALLOWLIST
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

fn is_response_header_allowed(name: &str) -> bool {
    RESPONSE_HEADER_ALLOWLIST
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

#[derive(Clone)]
struct DirectStreamService {
    client: Client,
}

impl DirectStreamService {
    fn new(client: Client) -> Self {
        Self { client }
    }

    async fn stream(
        &self,
        url: Url,
        headers: ReqwestHeaderMap,
    ) -> Result<Response<Body>, DirectStreamError> {
        let head_response = self
            .client
            .head(url.clone())
            .headers(headers.clone())
            .timeout(STREAM_REQUEST_TIMEOUT)
            .send()
            .await?;

        validate_upstream_status(head_response.status())?;

        let get_response = self
            .client
            .get(url)
            .headers(headers)
            .timeout(STREAM_REQUEST_TIMEOUT)
            .send()
            .await?;

        validate_upstream_status(get_response.status())?;

        let status =
            StatusCode::from_u16(get_response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

        let mut response_headers = HeaderMap::new();
        let mut has_accept_ranges = false;

        for (name, value) in get_response.headers().iter() {
            if !is_response_header_allowed(name.as_str()) {
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

        if !has_accept_ranges {
            response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        }

        let stream = get_response
            .bytes_stream()
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error));

        let body = Body::from_stream(stream);

        let mut response = Response::builder().status(status).body(body)?;
        *response.headers_mut() = response_headers;

        Ok(response)
    }
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
