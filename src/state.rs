use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Identifier used to look up cached client metadata.
pub type ClientId = String;

/// Identifier used to look up routing entries.
pub type RouteId = String;

/// Identifier used to look up secret values.
pub type SecretName = String;

/// Representation of a downstream client registered with the proxy.
#[derive(Debug, Clone, Default)]
pub struct ClientMetadata {
    /// Arbitrary metadata describing a client; stored as key-value pairs so
    /// integrators can extend the schema without requiring code changes.
    pub attributes: HashMap<String, String>,
}

/// Representation of an upstream target used when proxying requests.
#[derive(Debug, Clone, Default)]
pub struct RouteTarget {
    /// Endpoint of the upstream target. The placeholder is a bare string until
    /// connection pooling and TLS configuration are implemented.
    pub upstream: String,
}

/// Representation of an opaque secret loaded from the configuration backend.
#[derive(Debug, Clone, Default)]
pub struct SecretValue {
    /// Raw secret value. Concrete projects may want to wrap this in a
    /// redaction-friendly type but for now a string keeps the placeholder
    /// ergonomic.
    pub value: String,
}

/// In-memory cache used to store client registrations.
pub type ClientsCache = HashMap<ClientId, ClientMetadata>;

/// In-memory routing table mapping proxy routes to upstream targets.
pub type RoutingTable = HashMap<RouteId, RouteTarget>;

/// In-memory secret store shared across the application.
pub type SecretsStore = HashMap<SecretName, SecretValue>;

/// Shared handle to the client cache protected by an asynchronous lock.
pub type SharedClientsCache = Arc<RwLock<ClientsCache>>;

/// Shared handle to the routing table protected by an asynchronous lock.
pub type SharedRoutingTable = Arc<RwLock<RoutingTable>>;

/// Shared handle to the secret store protected by an asynchronous lock.
pub type SharedSecretsStore = Arc<RwLock<SecretsStore>>;

/// Top-level application state shared across the Axum router and background
/// workers.
#[derive(Clone, Debug)]
pub struct AppState {
    clients_cache: SharedClientsCache,
    routing_table: SharedRoutingTable,
    secrets: SharedSecretsStore,
}

impl AppState {
    /// Constructs a new [`AppState`] using empty caches for each component.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a new [`AppState`] using the provided shared components. This
    /// makes it easy to plug in pre-populated caches during bootstrap while
    /// allowing handlers to share the same view of the data.
    pub fn with_components(
        clients_cache: SharedClientsCache,
        routing_table: SharedRoutingTable,
        secrets: SharedSecretsStore,
    ) -> Self {
        Self {
            clients_cache,
            routing_table,
            secrets,
        }
    }

    /// Returns a clone of the shared clients cache handle.
    pub fn clients_cache(&self) -> SharedClientsCache {
        Arc::clone(&self.clients_cache)
    }

    /// Returns a clone of the shared routing table handle.
    pub fn routing_table(&self) -> SharedRoutingTable {
        Arc::clone(&self.routing_table)
    }

    /// Returns a clone of the shared secrets store handle.
    pub fn secrets(&self) -> SharedSecretsStore {
        Arc::clone(&self.secrets)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            clients_cache: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_state_exposes_shared_handles() {
        let state = AppState::new();

        state.clients_cache().write().await.insert(
            "client-a".into(),
            ClientMetadata {
                attributes: HashMap::from([(String::from("plan"), String::from("premium"))]),
            },
        );

        let clients_handle = state.clients_cache();
        let cached = clients_handle.read().await;
        assert!(cached.contains_key("client-a"));

        state.routing_table().write().await.insert(
            "route-a".into(),
            RouteTarget {
                upstream: "https://example.com".into(),
            },
        );

        let routing_handle = state.routing_table();
        let routes = routing_handle.read().await;
        assert_eq!(routes["route-a"].upstream, "https://example.com");

        state.secrets().write().await.insert(
            "api_key".into(),
            SecretValue {
                value: "super-secret".into(),
            },
        );

        let secrets_handle = state.secrets();
        let secrets = secrets_handle.read().await;
        assert_eq!(secrets["api_key"].value, "super-secret");
    }
}
