use globset::{Glob, GlobMatcher};
use std::fmt;
use thiserror::Error;

/// Supported application-layer protocols used when routing requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteProtocol {
    Http,
    Https,
}

impl RouteProtocol {
    /// Builds a [`RouteProtocol`] from a URI scheme.
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

impl fmt::Display for RouteProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteProtocol::Http => write!(f, "http"),
            RouteProtocol::Https => write!(f, "https"),
        }
    }
}

/// Inclusive port range matcher used by the routing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Constructs a new [`PortRange`].
    pub fn new(start: u16, end: u16) -> Result<Self, RoutingError> {
        if start > end {
            return Err(RoutingError::InvalidPortRange { start, end });
        }

        Ok(Self { start, end })
    }

    /// Checks whether the provided port falls within the range.
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

/// Declarative route definition supplied by higher-level configuration loaders.
#[derive(Debug, Clone)]
pub struct RouteDefinition {
    /// Stable identifier for the route.
    pub id: String,
    /// Hostname glob patterns matched against the incoming request's host.
    pub host_patterns: Vec<String>,
    /// Allowed protocols for the route. When empty, any protocol is accepted.
    pub protocols: Vec<RouteProtocol>,
    /// Allowed destination ports. When empty, any port is accepted.
    pub ports: Vec<PortRange>,
}

impl RouteDefinition {
    /// Convenience constructor used by tests to build a route matching any host/port/protocol.
    pub fn any(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            host_patterns: Vec::new(),
            protocols: Vec::new(),
            ports: Vec::new(),
        }
    }
}

/// Request metadata used by the routing engine when selecting a route.
#[derive(Debug, Clone, Copy)]
pub struct RouteRequest<'a> {
    /// Optional host header or SNI name.
    pub host: Option<&'a str>,
    /// Protocol negotiated with the downstream client.
    pub protocol: RouteProtocol,
    /// Local port that received the downstream connection.
    pub port: u16,
}

/// Errors that can be emitted while constructing or evaluating the routing engine.
#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("invalid host glob `{pattern}`: {source}")]
    InvalidHostGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },

    #[error("port range start ({start}) must not be greater than end ({end})")]
    InvalidPortRange { start: u16, end: u16 },
}

/// Top-level routing engine that selects the first matching route for a request.
#[derive(Debug)]
pub struct RoutingEngine {
    routes: Vec<CompiledRoute>,
}

impl RoutingEngine {
    /// Compiles the provided route definitions into runtime matchers.
    pub fn new(routes: Vec<RouteDefinition>) -> Result<Self, RoutingError> {
        let mut compiled = Vec::with_capacity(routes.len());
        for definition in routes {
            compiled.push(CompiledRoute::new(definition)?);
        }

        Ok(Self { routes: compiled })
    }

    /// Returns the first route matching the provided request metadata.
    pub fn match_request(&self, request: &RouteRequest<'_>) -> Option<&RouteDefinition> {
        self.routes
            .iter()
            .find(|route| route.matches(request))
            .map(|route| &route.definition)
    }
}

#[derive(Debug)]
struct CompiledRoute {
    definition: RouteDefinition,
    host_matchers: Vec<GlobMatcher>,
}

impl CompiledRoute {
    fn new(definition: RouteDefinition) -> Result<Self, RoutingError> {
        let mut host_matchers = Vec::with_capacity(definition.host_patterns.len());
        for pattern in &definition.host_patterns {
            let glob = Glob::new(pattern)
                .map_err(|source| RoutingError::InvalidHostGlob {
                    pattern: pattern.clone(),
                    source,
                })?
                .compile_matcher();
            host_matchers.push(glob);
        }

        Ok(Self {
            definition,
            host_matchers,
        })
    }

    fn matches(&self, request: &RouteRequest<'_>) -> bool {
        self.protocol_matches(request)
            && self.port_matches(request.port)
            && self.host_matches(request.host)
    }

    fn protocol_matches(&self, request: &RouteRequest<'_>) -> bool {
        if self.definition.protocols.is_empty() {
            return true;
        }

        self.definition
            .protocols
            .iter()
            .any(|protocol| *protocol == request.protocol)
    }

    fn port_matches(&self, port: u16) -> bool {
        if self.definition.ports.is_empty() {
            return true;
        }

        self.definition
            .ports
            .iter()
            .any(|range| range.contains(port))
    }

    fn host_matches(&self, host: Option<&str>) -> bool {
        if self.host_matchers.is_empty() {
            return true;
        }

        let Some(host) = host else {
            return false;
        };

        let normalized = host.trim_end_matches('.').to_ascii_lowercase();

        self.host_matchers
            .iter()
            .any(|matcher| matcher.is_match(&normalized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_request(host: Option<&str>, protocol: RouteProtocol, port: u16) -> RouteRequest<'_> {
        RouteRequest {
            host,
            protocol,
            port,
        }
    }

    #[test]
    fn selects_first_matching_route() {
        let routes = vec![
            RouteDefinition {
                id: "first".into(),
                host_patterns: vec!["*.example.com".into()],
                protocols: vec![RouteProtocol::Https],
                ports: vec![PortRange::new(443, 443).unwrap()],
            },
            RouteDefinition::any("fallback"),
        ];

        let engine = RoutingEngine::new(routes).expect("routing engine should compile");
        let request = build_request(Some("video.example.com"), RouteProtocol::Https, 443);

        let route = engine
            .match_request(&request)
            .expect("a route should be selected");

        assert_eq!(route.id, "first");
    }

    #[test]
    fn falls_back_when_host_is_missing() {
        let routes = vec![
            RouteDefinition {
                id: "hosted".into(),
                host_patterns: vec!["*.example.com".into()],
                protocols: vec![RouteProtocol::Http],
                ports: vec![PortRange::new(80, 80).unwrap()],
            },
            RouteDefinition::any("default"),
        ];

        let engine = RoutingEngine::new(routes).expect("routing engine should compile");
        let request = build_request(None, RouteProtocol::Http, 80);

        let route = engine
            .match_request(&request)
            .expect("a fallback route should be selected");

        assert_eq!(route.id, "default");
    }

    #[test]
    fn rejects_invalid_glob_patterns() {
        let routes = vec![RouteDefinition {
            id: "bad".into(),
            host_patterns: vec!["[".into()],
            protocols: vec![],
            ports: vec![],
        }];

        let err = RoutingEngine::new(routes).expect_err("glob compilation should fail");
        matches!(err, RoutingError::InvalidHostGlob { .. });
    }

    #[test]
    fn rejects_invalid_port_ranges() {
        assert!(matches!(
            PortRange::new(100, 10),
            Err(RoutingError::InvalidPortRange {
                start: 100,
                end: 10
            })
        ));
    }

    #[test]
    fn matches_multiple_protocols_and_ports() {
        let routes = vec![RouteDefinition {
            id: "multi".into(),
            host_patterns: vec!["*.example.net".into()],
            protocols: vec![RouteProtocol::Http, RouteProtocol::Https],
            ports: vec![
                PortRange::new(80, 80).unwrap(),
                PortRange::new(8080, 8088).unwrap(),
            ],
        }];

        let engine = RoutingEngine::new(routes).expect("routing engine should compile");

        assert!(engine
            .match_request(&build_request(
                Some("edge.example.net"),
                RouteProtocol::Http,
                8080,
            ))
            .is_some());

        assert!(engine
            .match_request(&build_request(
                Some("edge.example.net"),
                RouteProtocol::Https,
                80,
            ))
            .is_some());

        assert!(engine
            .match_request(&build_request(
                Some("edge.example.net"),
                RouteProtocol::Https,
                8085,
            ))
            .is_some());
    }

    #[test]
    fn normalizes_trailing_dot_in_hostnames() {
        let routes = vec![RouteDefinition {
            id: "edge".into(),
            host_patterns: vec!["origin.example.org".into()],
            protocols: vec![RouteProtocol::Https],
            ports: vec![PortRange::new(443, 443).unwrap()],
        }];

        let engine = RoutingEngine::new(routes).expect("routing engine should compile");

        assert!(engine
            .match_request(&build_request(
                Some("origin.example.org."),
                RouteProtocol::Https,
                443,
            ))
            .is_some());
    }
}
