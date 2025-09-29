use std::io;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{
    self,
    header::{HeaderName, HeaderValue, HOST},
    HeaderMap, Request, Response, Uri,
};
use futures::TryStreamExt;
use reqwest::{
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue,
    },
    redirect::Policy,
    Body as ReqwestBody, Client, Method as ReqwestMethod, Proxy as ReqwestProxy,
};
use thiserror::Error;
use url::Url;

use crate::state::{AppState, RouteTarget};

/// Errors that can occur while proxying a request.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("downstream request is missing a host header")]
    MissingHost,

    #[error("no upstream route registered for host `{host}`")]
    RouteNotFound { host: String },

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
}

/// Top-level entry point used by handlers to forward requests to the upstream target.
pub async fn forward(
    state: AppState,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let host = extract_host(request.uri(), request.headers()).ok_or(ProxyError::MissingHost)?;
    let route = lookup_route(&state, &host).await?;
    let upstream_url = build_upstream_url(&route, request.uri())?;
    let upstream_scheme = upstream_url.scheme().to_string();

    let client = build_client(&route)?;
    let remote_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let headers =
        prepare_upstream_headers(request.headers(), remote_addr, &host, &upstream_scheme)?;

    let method = ReqwestMethod::from_bytes(request.method().as_str().as_bytes()).map_err(|_| {
        ProxyError::UnsupportedMethod {
            method: request.method().to_string(),
        }
    })?;

    let mut builder = client.request(method, upstream_url);
    builder = builder.headers(headers);

    let body_stream = request
        .into_body()
        .into_data_stream()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .into_stream();
    builder = builder.body(ReqwestBody::wrap_stream(body_stream));

    let upstream_response = builder
        .send()
        .await
        .map_err(|source| ProxyError::UpstreamRequest { source })?;

    let upstream_status = upstream_response.status();
    let status = http::StatusCode::from_u16(upstream_status.as_u16()).map_err(|source| {
        ProxyError::InvalidStatusCode {
            code: upstream_status.as_u16(),
            source,
        }
    })?;
    let mut response_builder = Response::builder().status(status);
    if let Some(headers) = response_builder.headers_mut() {
        for (name, value) in upstream_response.headers().iter() {
            let header_name = HeaderName::from_bytes(name.as_str().as_bytes())
                .map_err(|source| ProxyError::InvalidInboundHeaderName { source })?;
            let header_value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|source| ProxyError::InvalidInboundHeaderValue { source })?;
            headers.append(header_name, header_value);
        }
    }

    let response_stream = upstream_response
        .bytes_stream()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .into_stream();
    let response_body = Body::from_stream(response_stream);

    response_builder
        .body(response_body)
        .map_err(|source| ProxyError::ResponseBuild { source })
}

fn extract_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    if let Some(host) = uri.host() {
        return Some(host.to_string());
    }

    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

async fn lookup_route(state: &AppState, host: &str) -> Result<RouteTarget, ProxyError> {
    let routing_table = state.routing_table();
    let table = routing_table.read().await;
    table
        .get(host)
        .cloned()
        .ok_or_else(|| ProxyError::RouteNotFound {
            host: host.to_string(),
        })
}

fn build_client(route: &RouteTarget) -> Result<Client, ProxyError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(route.tls_insecure_skip_verify);

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

fn prepare_upstream_headers(
    downstream: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    host: &str,
    scheme: &str,
) -> Result<ReqwestHeaderMap, ProxyError> {
    let mut headers = ReqwestHeaderMap::new();
    let forwarded_host_req = ReqwestHeaderName::from_static("x-forwarded-host");
    let forwarded_proto_req = ReqwestHeaderName::from_static("x-forwarded-proto");
    let forwarded_for_req = ReqwestHeaderName::from_static("x-forwarded-for");
    let forwarded_for_lookup = HeaderName::from_static("x-forwarded-for");

    for (name, value) in downstream.iter() {
        if name == HOST {
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

    if let Some(addr) = remote_addr {
        let mut value = String::new();
        if let Some(existing) = downstream.get(&forwarded_for_lookup) {
            let existing = existing.to_str()?;
            if !existing.is_empty() {
                value.push_str(existing);
                value.push_str(", ");
            }
        }
        value.push_str(&addr.ip().to_string());
        let forwarded_value = ReqwestHeaderValue::from_str(&value)
            .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
        headers.insert(forwarded_for_req, forwarded_value);
    } else if let Some(existing) = downstream.get(&forwarded_for_lookup) {
        let forwarded_value = ReqwestHeaderValue::from_bytes(existing.as_bytes())
            .map_err(|source| ProxyError::InvalidOutboundHeaderValue { source })?;
        headers.insert(forwarded_for_req, forwarded_value);
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;
    use axum::http::HeaderMap;
    use reqwest::header::HeaderName as ReqHeaderName;

    #[test]
    fn build_upstream_url_joins_paths() {
        let target = RouteTarget {
            upstream: "https://example.com/vod".to_string(),
            tls_insecure_skip_verify: false,
            socks5: None,
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
        let headers = prepare_upstream_headers(
            &downstream,
            Some("198.51.100.10:1234".parse().unwrap()),
            "cdn.example.com",
            "https",
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
}
