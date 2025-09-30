use std::{
    collections::HashMap,
    env,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use anyhow::{Context, Result};

use sProx::{
    app,
    config::{Config, ListenerConfig},
    state::{AppState, HlsOptions, RouteTarget, Socks5Proxy},
};
use tokio::{net::TcpListener, sync::RwLock};

#[tokio::main]
async fn main() -> Result<()> {
    load_env_file()?;

    sProx::init()?;

    let config_path = env::var("SPROX_CONFIG").unwrap_or_else(|_| "config/routes.yaml".into());
    let config = Config::load_from_path(&config_path)
        .with_context(|| format!("failed to load configuration from `{config_path}`"))?;

    let listener = primary_listener(&config)
        .context("configuration must define at least one route to determine listener address")?;
    let addr = resolve_listener_addr(listener)
        .context("failed to resolve listener address from configuration")?;

    let state = build_app_state(&config);
    let router = app::build_router(state);

    tracing::info!(path = %config_path, %addr, "starting sProx server");

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| "failed to bind listener socket")?;
    let local_addr = listener
        .local_addr()
        .with_context(|| "failed to determine listener address")?;
    tracing::info!(%local_addr, "sProx listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("sProx shutdown complete");

    Ok(())
}

fn build_app_state(config: &Config) -> AppState {
    let mut routing_table = HashMap::new();

    for route in &config.routes {
        let socks5 = if route.upstream.socks5.enabled {
            route
                .upstream
                .socks5
                .address
                .as_ref()
                .map(|address| Socks5Proxy {
                    address: address.clone(),
                    username: route.upstream.socks5.username.clone(),
                    password: route.upstream.socks5.password.clone(),
                })
        } else {
            None
        };

        let hls = route.hls.as_ref().map(|hls| HlsOptions {
            enabled: hls.enabled,
            rewrite_playlist_urls: hls.rewrite_playlist_urls,
            base_url: hls.base_url.clone(),
            allow_insecure_segments: hls.allow_insecure_segments,
        });

        let target = RouteTarget {
            upstream: route.upstream.origin.to_string(),
            connect_timeout: route.upstream.connect_timeout,
            read_timeout: route.upstream.read_timeout,
            request_timeout: route.upstream.request_timeout,
            tls_insecure_skip_verify: route.upstream.tls.insecure_skip_verify,
            socks5,
            hls,
        };

        routing_table.insert(route.id.clone(), target);
    }

    AppState::with_components(
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(routing_table)),
        Arc::new(RwLock::new(HashMap::new())),
    )
}

fn primary_listener(config: &Config) -> Option<&ListenerConfig> {
    config.routes.first().map(|route| &route.listen)
}

fn resolve_listener_addr(listener: &ListenerConfig) -> Result<SocketAddr> {
    if let Ok(ip) = listener.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, listener.port));
    }

    let mut addrs = (listener.host.as_str(), listener.port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve listener host `{}`", listener.host))?;
    addrs
        .next()
        .context("listener host resolved to no addresses")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to listen for ctrl+c");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!(%error, "failed to listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("shutdown signal received");
}

fn load_env_file() -> anyhow::Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(err)) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod integration_tests;
