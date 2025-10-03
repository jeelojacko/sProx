use std::time::Duration;

use cookie::Cookie;
use reqwest::{
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue, LOCATION, REFERER,
    },
    Client, Method as ReqwestMethod, Response, StatusCode,
};
use url::Url;

use crate::proxy::headers;
use crate::retry::{self, RetryError};
use crate::state::{RetryPolicy, HARD_REDIRECT_FOLLOW_MAX};

#[derive(Debug, Clone)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    host_only: bool,
}

#[derive(Debug, Default, Clone)]
struct SimpleCookieStore {
    cookies: Vec<StoredCookie>,
}

impl SimpleCookieStore {
    fn ingest(&mut self, response: &Response, url: &Url) {
        let default_domain = url
            .host_str()
            .map(|host| host.to_ascii_lowercase())
            .unwrap_or_default();
        let default_path = default_path(url.path());

        for value in response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
        {
            if let Ok(raw) = value.to_str() {
                if let Ok(parsed) = Cookie::parse(raw.to_string()) {
                    self.store_cookie(parsed, &default_domain, &default_path);
                }
            }
        }
    }

    fn store_cookie(&mut self, cookie: Cookie<'static>, default_domain: &str, default_path: &str) {
        let host_only = cookie.domain().is_none();
        let domain = cookie
            .domain()
            .and_then(normalize_domain)
            .unwrap_or_else(|| default_domain.to_string());
        let path = cookie
            .path()
            .map(normalize_path)
            .unwrap_or_else(|| default_path.to_string());
        let secure = cookie.secure().unwrap_or(false);
        let name = cookie.name().to_string();
        let value = cookie.value().to_string();

        if value.is_empty() {
            self.cookies.retain(|existing| {
                !(existing.name == name
                    && existing.domain == domain
                    && existing.path == path
                    && existing.host_only == host_only)
            });
            return;
        }

        self.cookies.retain(|existing| {
            !(existing.name == name
                && existing.domain == domain
                && existing.path == path
                && existing.host_only == host_only)
        });

        self.cookies.push(StoredCookie {
            name,
            value,
            domain,
            path,
            secure,
            host_only,
        });
    }

    fn apply(&self, headers: &mut ReqwestHeaderMap, url: &Url) {
        if self.cookies.is_empty() {
            return;
        }

        let host = url
            .host_str()
            .map(|host| host.to_ascii_lowercase())
            .unwrap_or_default();
        let path = url.path();
        let is_secure = url.scheme().eq_ignore_ascii_case("https");

        let mut parts = Vec::new();

        if let Some(existing) = headers
            .remove(reqwest::header::COOKIE)
            .and_then(|value| value.to_str().ok().map(|value| value.to_string()))
        {
            if !existing.trim().is_empty() {
                parts.push(existing);
            }
        }

        let jar_values: Vec<String> = self
            .cookies
            .iter()
            .filter(|cookie| cookie.matches(&host, path, is_secure))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();

        if !jar_values.is_empty() {
            parts.push(jar_values.join("; "));
        }

        if parts.is_empty() {
            return;
        }

        if let Ok(value) = ReqwestHeaderValue::from_str(&parts.join("; ")) {
            headers.insert(reqwest::header::COOKIE, value);
        }
    }
}

impl StoredCookie {
    fn matches(&self, host: &str, path: &str, is_secure: bool) -> bool {
        if self.secure && !is_secure {
            return false;
        }

        if self.host_only {
            if !host.eq_ignore_ascii_case(&self.domain) {
                return false;
            }
        } else if !domain_matches(&self.domain, host) {
            return false;
        }

        if !path.starts_with(&self.path) {
            return false;
        }

        if path.len() > self.path.len() && !self.path.ends_with('/') {
            if let Some(next) = path.as_bytes().get(self.path.len()) {
                if *next != b'/' {
                    return false;
                }
            }
        }

        true
    }
}

fn normalize_domain(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() || !path.starts_with('/') {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn default_path(path: &str) -> String {
    if path.is_empty() || !path.starts_with('/') {
        return "/".to_string();
    }

    if let Some(index) = path.rfind('/') {
        if index == 0 {
            return "/".to_string();
        }

        return path[..index].to_string();
    }

    "/".to_string()
}

fn domain_matches(cookie_domain: &str, host: &str) -> bool {
    if host.eq_ignore_ascii_case(cookie_domain) {
        return true;
    }

    host.ends_with(&format!(".{cookie_domain}"))
}

#[derive(Clone, Debug)]
pub struct FollowRedirectRequest {
    pub client: Client,
    pub method: ReqwestMethod,
    pub url: Url,
    pub headers: ReqwestHeaderMap,
    pub retry_policy: RetryPolicy,
    pub request_timeout: Duration,
    pub follow_max: usize,
}

impl FollowRedirectRequest {
    pub fn with_headers(&self, headers: ReqwestHeaderMap) -> Self {
        let mut cloned = self.clone();
        cloned.headers = headers;
        cloned
    }
}

#[derive(Debug)]
pub struct FollowRedirectResult {
    pub response: Response,
    pub final_url: Url,
    pub attempts: u32,
    pub redirects: usize,
    pub chain: Vec<Url>,
}

#[derive(Debug)]
pub enum FollowRedirectError {
    Retry {
        error: RetryError,
        attempts: u32,
    },
    LimitExceeded {
        limit: usize,
    },
    MissingLocation,
    InvalidLocation {
        location: String,
        source: url::ParseError,
    },
    InvalidLocationEncoding,
    RefererBuild {
        source: reqwest::header::InvalidHeaderValue,
    },
}

pub async fn follow_redirects(
    request: FollowRedirectRequest,
) -> Result<FollowRedirectResult, FollowRedirectError> {
    let mut current_url = request.url.clone();
    let mut headers = request.headers.clone();
    let mut redirects = 0usize;
    let mut total_attempts = 0u32;
    let mut chain = Vec::new();
    let limit = request.follow_max.clamp(1, HARD_REDIRECT_FOLLOW_MAX);
    let mut cookie_store = SimpleCookieStore::default();

    loop {
        chain.push(current_url.clone());

        cookie_store.apply(&mut headers, &current_url);

        let mut builder = request
            .client
            .request(request.method.clone(), current_url.clone());
        builder = builder.headers(headers.clone());
        builder = builder.timeout(request.request_timeout);

        let req = builder
            .build()
            .map_err(|error| FollowRedirectError::Retry {
                error: RetryError::from(error),
                attempts: total_attempts,
            })?;

        let attempt =
            retry::execute_with_retry(request.client.clone(), req, request.retry_policy.clone())
                .await;

        total_attempts += attempt.attempts();

        let response = match attempt.into_result() {
            Ok(response) => response,
            Err(error) => {
                return Err(FollowRedirectError::Retry {
                    error,
                    attempts: total_attempts,
                });
            }
        };

        cookie_store.ingest(&response, &current_url);

        let status = response.status();

        if !status.is_redirection() {
            return Ok(FollowRedirectResult {
                response,
                final_url: current_url,
                attempts: total_attempts,
                redirects,
                chain,
            });
        }

        if !matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            return Ok(FollowRedirectResult {
                response,
                final_url: current_url,
                attempts: total_attempts,
                redirects,
                chain,
            });
        }

        let location = response
            .headers()
            .get(LOCATION)
            .ok_or(FollowRedirectError::MissingLocation)?;
        let location = location
            .to_str()
            .map_err(|_| FollowRedirectError::InvalidLocationEncoding)?;
        let next_url =
            current_url
                .join(location)
                .map_err(|source| FollowRedirectError::InvalidLocation {
                    location: location.to_string(),
                    source,
                })?;

        if host_changed(&current_url, &next_url) {
            strip_cross_host_headers(&mut headers);
        }

        redirects += 1;
        if redirects > limit {
            return Err(FollowRedirectError::LimitExceeded { limit });
        }

        current_url = next_url;
    }
}

pub async fn get_with_adaptive_referer(
    request: FollowRedirectRequest,
) -> Result<FollowRedirectResult, FollowRedirectError> {
    if request.headers.contains_key(REFERER) {
        return follow_redirects(request).await;
    }

    let mut total_attempts = 0u32;
    let base_headers = request.headers.clone();
    let mut outcome = follow_redirects(request.clone()).await?;
    total_attempts += outcome.attempts;

    if !requires_referer_retry(outcome.response.status()) {
        outcome.attempts = total_attempts;
        return Ok(outcome);
    }

    let candidates = headers::candidate_referers(&outcome.chain);
    let mut last_outcome = outcome;

    for candidate in candidates.into_iter().take(3) {
        let mut attempt_headers = base_headers.clone();
        let referer = ReqwestHeaderValue::from_str(&candidate)
            .map_err(|source| FollowRedirectError::RefererBuild { source })?;
        attempt_headers.insert(REFERER, referer);

        let attempt_request = request.with_headers(attempt_headers);
        match follow_redirects(attempt_request).await {
            Ok(mut next_outcome) => {
                total_attempts += next_outcome.attempts;
                if requires_referer_retry(next_outcome.response.status()) {
                    last_outcome = next_outcome;
                    continue;
                }

                next_outcome.attempts = total_attempts;
                #[cfg(feature = "telemetry")]
                record_referer_success(&next_outcome.final_url);
                #[cfg(feature = "telemetry")]
                metrics::counter!("referer_retries_total", "result" => "success").increment(1);
                return Ok(next_outcome);
            }
            Err(FollowRedirectError::Retry { error, attempts }) => {
                return Err(FollowRedirectError::Retry {
                    error,
                    attempts: total_attempts + attempts,
                });
            }
            Err(other) => return Err(other),
        }
    }

    #[cfg(feature = "telemetry")]
    metrics::counter!("referer_retries_total", "result" => "fail").increment(1);

    last_outcome.attempts = total_attempts;
    Ok(last_outcome)
}

fn host_changed(current: &Url, next: &Url) -> bool {
    let host_differs = match (current.host_str(), next.host_str()) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
        _ => true,
    };

    if host_differs {
        return true;
    }

    current.port_or_known_default() != next.port_or_known_default()
}

fn strip_cross_host_headers(headers: &mut ReqwestHeaderMap) {
    const CROSS_HOST_HEADERS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    ];

    for name in CROSS_HOST_HEADERS {
        if let Ok(header_name) = ReqwestHeaderName::from_lowercase(name.as_bytes()) {
            headers.remove(header_name);
        }
    }
}

fn requires_referer_retry(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::PRECONDITION_FAILED
            | StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    )
}

#[cfg(feature = "telemetry")]
fn record_referer_success(final_url: &Url) {
    if let Some(host) = final_url.host_str() {
        let labels = [("host", host.to_string())];
        metrics::gauge!("referer_retry_last_used", &labels).set(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::{oneshot, Mutex};

    async fn spawn_redirect_chain() -> (
        SocketAddr,
        oneshot::Sender<()>,
        Arc<Mutex<Vec<Option<String>>>>,
    ) {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::Response as AxumResponse;

        #[derive(Clone)]
        struct TestState {
            cookies: Arc<Mutex<Vec<Option<String>>>>,
        }

        async fn start_handler() -> AxumResponse {
            axum::http::Response::builder()
                .status(StatusCode::FOUND)
                .header(axum::http::header::LOCATION, "/hop" as &str)
                .body(axum::body::Body::empty())
                .unwrap()
        }

        async fn hop_handler(State(_state): State<TestState>) -> AxumResponse {
            axum::http::Response::builder()
                .status(StatusCode::FOUND)
                .header(axum::http::header::LOCATION, "/final" as &str)
                .header("set-cookie", "session=abc; Path=/")
                .body(axum::body::Body::empty())
                .unwrap()
        }

        async fn final_handler(State(state): State<TestState>, headers: HeaderMap) -> AxumResponse {
            let cookie = headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            state.cookies.lock().await.push(cookie);
            axum::http::Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from("ok"))
                .unwrap()
        }

        let cookies = Arc::new(Mutex::new(Vec::new()));
        let state = TestState {
            cookies: cookies.clone(),
        };

        let router = Router::new()
            .route("/start", get(start_handler))
            .route("/hop", get(hop_handler))
            .route("/final", get(final_handler))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        (addr, tx, cookies)
    }

    #[tokio::test]
    async fn follow_redirects_preserves_cookie_jar() {
        let (addr, shutdown, cookies) = spawn_redirect_chain().await;

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let url = Url::parse(&format!("http://{}/start", addr)).unwrap();
        let request = FollowRedirectRequest {
            client: client.clone(),
            method: ReqwestMethod::GET,
            url,
            headers: ReqwestHeaderMap::new(),
            retry_policy: RetryPolicy::default(),
            request_timeout: Duration::from_secs(5),
            follow_max: 5,
        };

        let result = follow_redirects(request)
            .await
            .expect("redirects should follow");
        assert_eq!(result.response.status(), reqwest::StatusCode::OK);
        let stored = cookies.lock().await;
        assert!(stored
            .iter()
            .flatten()
            .any(|value| value.contains("session=abc")));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn adaptive_referer_recovers_from_forbidden() {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::Response as AxumResponse;

        #[derive(Clone)]
        struct TestState {
            attempts: Arc<Mutex<u32>>,
        }

        async fn start_handler() -> AxumResponse {
            axum::http::Response::builder()
                .status(StatusCode::FOUND)
                .header(axum::http::header::LOCATION, "/protected" as &str)
                .body(axum::body::Body::empty())
                .unwrap()
        }

        async fn protected_handler(
            State(state): State<TestState>,
            headers: HeaderMap,
        ) -> AxumResponse {
            let mut attempts = state.attempts.lock().await;
            *attempts += 1;
            if headers.get(axum::http::header::REFERER).is_some() {
                axum::http::Response::builder()
                    .status(StatusCode::OK)
                    .body(axum::body::Body::from("ok"))
                    .unwrap()
            } else {
                axum::http::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }
        }

        let state = TestState {
            attempts: Arc::new(Mutex::new(0)),
        };

        let router = Router::new()
            .route("/start", get(start_handler))
            .route("/protected", get(protected_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let url = Url::parse(&format!("http://{}/start", addr)).unwrap();
        let request = FollowRedirectRequest {
            client: client.clone(),
            method: ReqwestMethod::GET,
            url,
            headers: ReqwestHeaderMap::new(),
            retry_policy: RetryPolicy::default(),
            request_timeout: Duration::from_secs(5),
            follow_max: 5,
        };

        let result = get_with_adaptive_referer(request)
            .await
            .expect("referer retry should succeed");

        assert_eq!(result.response.status(), reqwest::StatusCode::OK);
        assert!(*state.attempts.lock().await >= 2);

        let _ = tx.send(());
    }
}
