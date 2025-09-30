use super::*;

use std::time::Duration;

use reqwest::StatusCode;
use tokio::{net::TcpListener, sync::oneshot};
use url::Url;

use sProx::config::{Config, ListenerConfig, RouteConfig, Socks5Config, TlsConfig, UpstreamConfig};

#[tokio::test]
async fn health_endpoint_returns_success() {
    let config = Config {
        routes: vec![RouteConfig {
            id: "health-check".into(),
            listen: ListenerConfig {
                host: "127.0.0.1".into(),
                port: 0,
            },
            host_patterns: Vec::new(),
            protocols: Vec::new(),
            upstream: UpstreamConfig {
                origin: Url::parse("http://127.0.0.1:65535").expect("url should parse"),
                connect_timeout: Some(Duration::from_secs(1)),
                read_timeout: Some(Duration::from_secs(1)),
                request_timeout: Some(Duration::from_secs(1)),
                tls: TlsConfig {
                    enabled: false,
                    sni_hostname: None,
                    insecure_skip_verify: false,
                },
                socks5: Socks5Config {
                    enabled: false,
                    address: None,
                    username: None,
                    password: None,
                },
            },
            hls: None,
        }],
    };

    let state = build_app_state(&config).expect("app state should build");
    let router = app::build_router(state);

    let listener_cfg = primary_listener(&config).expect("listener should be available");
    let addr = resolve_listener_addr(listener_cfg).expect("listener address should resolve");

    let listener = TcpListener::bind(addr)
        .await
        .expect("listener should bind successfully");
    let local_addr = listener
        .local_addr()
        .expect("listener should expose local address");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = axum::serve(listener, router).with_graceful_shutdown(async {
        let _ = shutdown_rx.await;
    });
    let server_handle = tokio::spawn(async move { server.await });

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{local_addr}/health"))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let _ = shutdown_tx.send(());

    server_handle
        .await
        .expect("server task should join")
        .expect("server should shut down cleanly");
}
