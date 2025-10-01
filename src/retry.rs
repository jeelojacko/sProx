use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use rand::Rng;
use reqwest::{Client, Request, Response};
use tower::retry::{budget::Budget, Policy};
use tower::{retry::Retry, Service};

use crate::state::RetryPolicy;

/// Error returned when a retryable operation exhausts its attempts.
#[derive(Debug)]
pub enum RetryError {
    /// The underlying request failed even after all retry attempts were exhausted.
    Request(reqwest::Error),
    /// The retry budget rejected the attempt, signalling that the circuit is open.
    BudgetExhausted { source: reqwest::Error },
}

impl RetryError {
    pub fn into_source(self) -> reqwest::Error {
        match self {
            RetryError::Request(source) => source,
            RetryError::BudgetExhausted { source } => source,
        }
    }

    pub fn is_budget_exhausted(&self) -> bool {
        matches!(self, RetryError::BudgetExhausted { .. })
    }
}

impl From<reqwest::Error> for RetryError {
    fn from(source: reqwest::Error) -> Self {
        RetryError::Request(source)
    }
}

/// Executes the provided request using the supplied retry policy.
pub(crate) async fn execute_with_retry(
    client: Client,
    request: Request,
    policy: RetryPolicy,
) -> RetryAttempt {
    let shared_policy = Arc::new(SharedPolicy::new(policy));
    shared_policy.budget.deposit();

    let retry_policy = ExponentialBackoffPolicy::new(shared_policy.clone());
    let mut retry_service = Retry::new(retry_policy, ReqwestService::new(client));

    let result = match retry_service.call(request).await {
        Ok(response) => Ok(response),
        Err(error) => {
            if shared_policy.circuit_open.load(Ordering::SeqCst) {
                Err(RetryError::BudgetExhausted { source: error })
            } else {
                Err(RetryError::Request(error))
            }
        }
    };

    RetryAttempt {
        attempts: shared_policy.attempts(),
        result,
    }
}

pub(crate) struct RetryAttempt {
    attempts: u32,
    result: Result<Response, RetryError>,
}

impl RetryAttempt {
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn retries(&self) -> u32 {
        self.attempts.saturating_sub(1)
    }

    pub fn into_result(self) -> Result<Response, RetryError> {
        self.result
    }
}

#[derive(Clone)]
struct ExponentialBackoffPolicy {
    shared: Arc<SharedPolicy>,
    attempt: u32,
}

impl ExponentialBackoffPolicy {
    fn new(shared: Arc<SharedPolicy>) -> Self {
        Self { shared, attempt: 1 }
    }
}

impl Policy<Request, Response, reqwest::Error> for ExponentialBackoffPolicy {
    type Future = Pin<Box<dyn Future<Output = Self> + Send>>;

    fn retry(
        &self,
        request: &Request,
        result: Result<&Response, &reqwest::Error>,
    ) -> Option<Self::Future> {
        match result {
            Ok(_) => None,
            Err(error) => {
                if !self.shared.should_retry(request, error) {
                    return None;
                }

                if self.attempt >= self.shared.max_attempts() {
                    return None;
                }

                if self.shared.budget.withdraw().is_err() {
                    self.shared.circuit_open.store(true, Ordering::SeqCst);
                    return None;
                }

                let delay = self.shared.backoff_delay(self.attempt);
                let shared = self.shared.clone();
                let next_attempt = self.attempt + 1;
                self.shared.record_attempt(next_attempt);

                Some(Box::pin(async move {
                    tokio::time::sleep(delay).await;
                    Self {
                        shared,
                        attempt: next_attempt,
                    }
                }))
            }
        }
    }

    fn clone_request(&self, request: &Request) -> Option<Request> {
        request.try_clone()
    }
}

struct SharedPolicy {
    policy: RetryPolicy,
    budget: Arc<Budget>,
    circuit_open: Arc<AtomicBool>,
    attempts: Arc<AtomicU32>,
}

impl SharedPolicy {
    fn new(policy: RetryPolicy) -> Self {
        let budget = policy.budget_handle();
        Self {
            policy,
            budget,
            circuit_open: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicU32::new(1)),
        }
    }

    fn should_retry(&self, request: &Request, error: &reqwest::Error) -> bool {
        if !self.policy.is_method_retryable(request.method()) {
            return false;
        }

        if error.is_timeout() || error.is_connect() {
            return true;
        }

        if error.is_request() {
            return true;
        }

        // Treat transport layer errors that bubble up as retryable by default.
        error.is_body() || error.is_decode()
    }

    fn max_attempts(&self) -> u32 {
        self.policy.max_attempts().get()
    }

    fn backoff_delay(&self, attempt: u32) -> Duration {
        let base = self.policy.backoff_delay(attempt);
        let jitter = self.policy.backoff_jitter();
        if jitter <= f64::EPSILON {
            return base;
        }

        let mut rng = rand::thread_rng();
        let jitter_range = (1.0 - jitter).max(0.0)..=(1.0 + jitter);
        let factor: f64 = rng.gen_range(jitter_range);
        base.mul_f64(factor)
    }

    fn attempts(&self) -> u32 {
        self.attempts.load(Ordering::SeqCst)
    }

    fn record_attempt(&self, attempt: u32) {
        self.attempts.store(attempt, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct ReqwestService {
    client: Client,
}

impl ReqwestService {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

impl Service<Request> for ReqwestService {
    type Response = Response;
    type Error = reqwest::Error;
    type Future = BoxFuture<'static, Result<Response, reqwest::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let client = self.client.clone();
        Box::pin(async move { client.execute(request).await })
    }
}
