use std::{
    env,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sProx::{
    app,
    config::{Config, ListenerConfig},
    state::{reload_app_state_from_path, AppState, SharedAppState},
};
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(
    name = "sprox",
    about = "Streaming proxy service",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate configuration files without starting the server.
    Validate {
        /// Directory containing the proxy configuration files.
        #[arg(
            short = 'c',
            long = "config",
            value_name = "DIR",
            default_value = "config"
        )]
        config_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    load_env_file()?;
    sProx::init()?;

    match cli.command {
        Some(Command::Validate { config_dir }) => {
            validate_config_dir(&config_dir)?;
            Ok(())
        }
        None => run_server().await,
    }
}

async fn run_server() -> Result<()> {
    let config_path = env::var("SPROX_CONFIG").unwrap_or_else(|_| "config/routes.yaml".into());
    let config_path = PathBuf::from(config_path);
    let config = Config::load_from_path(&config_path).with_context(|| {
        format!(
            "failed to load configuration from `{}`",
            config_path.display()
        )
    })?;

    let listener = primary_listener(&config)
        .context("configuration must define at least one route to determine listener address")?;
    let addr = resolve_listener_addr(listener)
        .context("failed to resolve listener address from configuration")?;

    let app_state = AppState::from_config(&config)
        .context("failed to build application state from configuration")?;
    let shared_state = SharedAppState::new(app_state);
    let router = app::build_router(shared_state.clone());

    tracing::info!(path = %config_path.display(), %addr, "starting sProx server");

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| "failed to bind listener socket")?;
    let local_addr = listener
        .local_addr()
        .with_context(|| "failed to determine listener address")?;
    tracing::info!(%local_addr, "sProx listening");

    #[cfg(unix)]
    tokio::spawn(watch_for_config_reloads(
        config_path.clone(),
        shared_state.clone(),
    ));

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("sProx shutdown complete");

    Ok(())
}

fn validate_config_dir(dir: &Path) -> Result<()> {
    let config_path = dir.join("routes.yaml");
    let config = Config::load_from_path(&config_path).with_context(|| {
        format!(
            "failed to load configuration from `{}`",
            config_path.display()
        )
    })?;

    AppState::from_config(&config).with_context(|| {
        format!(
            "configuration `{}` failed validation",
            config_path.display()
        )
    })?;

    println!("configuration at `{}` is valid", config_path.display());

    Ok(())
}

#[cfg(unix)]
async fn watch_for_config_reloads(config_path: PathBuf, state: SharedAppState) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut signals = match signal(SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!(%error, "failed to initialise SIGHUP watcher");
            return;
        }
    };

    while signals.recv().await.is_some() {
        tracing::info!(path = %config_path.display(), "received SIGHUP; reloading configuration");
        match reload_app_state_from_path(&config_path, &state) {
            Ok(_) => tracing::info!(path = %config_path.display(), "configuration reload complete"),
            Err(error) => tracing::error!(
                path = %config_path.display(),
                error = ?error,
                "failed to reload configuration; retaining previous state"
            ),
        }
    }
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
