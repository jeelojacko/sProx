use std::{
    env,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use axum_server::tls_rustls::RustlsConfig;
use axum_server::{self, Handle};
use sProx::{
    app,
    config::{Config, ListenerConfig, ListenerTlsAcmeConfig, ListenerTlsConfig},
    state::{reload_app_state_from_path, AppState, SharedAppState},
};
use tokio::{fs, net::TcpListener, sync::watch, time::sleep};

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
    /// Perform an HTTP health check against a running sProx instance.
    Healthcheck {
        /// URL of the health endpoint to query.
        #[arg(
            long = "url",
            value_name = "URL",
            default_value = "http://127.0.0.1:8080/health"
        )]
        url: String,
        /// Maximum duration to wait for the health endpoint response.
        #[arg(long = "timeout", value_name = "SECONDS", default_value_t = 5)]
        timeout_seconds: u64,
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
        Some(Command::Healthcheck {
            url,
            timeout_seconds,
        }) => run_healthcheck(&url, timeout_seconds).await,
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
    let tls_settings = listener.tls.clone();

    let app_state = AppState::from_config(&config)
        .context("failed to build application state from configuration")?;
    let shared_state = SharedAppState::new(app_state);
    let router = app::build_router(shared_state.clone());
    let mut make_service = Some(router.into_make_service_with_connect_info::<SocketAddr>());

    tracing::info!(
        path = %config_path.display(),
        %addr,
        tls = tls_settings.is_some(),
        "starting sProx server"
    );

    #[cfg(unix)]
    tokio::spawn(watch_for_config_reloads(
        config_path.clone(),
        shared_state.clone(),
    ));

    if let Some(tls) = tls_settings {
        if let Some(acme) = tls.acme.as_ref() {
            prepare_acme_environment(acme).await?;
        }

        let rustls_config = build_rustls_config(&tls).await?;
        let handle = Handle::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        if tls.watch_for_changes {
            spawn_tls_reload_task(tls.clone(), rustls_config.clone(), shutdown_rx.clone());
        }

        let shutdown_handle = handle.clone();
        let shutdown_task = tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(None);
        });

        let log_handle = handle.clone();
        tokio::spawn(async move {
            if let Some(addr) = log_handle.listening().await {
                tracing::info!(%addr, "sProx listening");
            }
        });

        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(
                make_service
                    .take()
                    .expect("make service should be available for TLS"),
            )
            .await
            .context("server error")?;

        let _ = shutdown_tx.send(true);
        shutdown_task.abort();
    } else {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| "failed to bind listener socket")?;
        let local_addr = listener
            .local_addr()
            .with_context(|| "failed to determine listener address")?;
        tracing::info!(%local_addr, "sProx listening");

        axum::serve(
            listener,
            make_service
                .take()
                .expect("make service should be available for HTTP"),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    }

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

async fn build_rustls_config(config: &ListenerTlsConfig) -> Result<RustlsConfig> {
    RustlsConfig::from_pem_file(&config.certificate_path, &config.private_key_path)
        .await
        .with_context(|| {
            format!(
                "failed to load TLS materials from `{}` and `{}`",
                config.certificate_path.display(),
                config.private_key_path.display()
            )
        })
}

fn spawn_tls_reload_task(
    tls: ListenerTlsConfig,
    rustls_config: RustlsConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if let Err(error) = watch_certificate_changes(tls, rustls_config, &mut shutdown).await {
            tracing::error!(error = ?error, "TLS certificate watcher terminated unexpectedly");
        }
    });
}

async fn watch_certificate_changes(
    tls: ListenerTlsConfig,
    rustls_config: RustlsConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut last_seen = read_certificate_timestamps(&tls).await?;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = sleep(Duration::from_secs(5)) => {
                match read_certificate_timestamps(&tls).await {
                    Ok(timestamps) => {
                        if timestamps != last_seen {
                            match rustls_config
                                .reload_from_pem_file(&tls.certificate_path, &tls.private_key_path)
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        certificate = %tls.certificate_path.display(),
                                        key = %tls.private_key_path.display(),
                                        "TLS certificates reloaded"
                                    );
                                    last_seen = timestamps;
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        certificate = %tls.certificate_path.display(),
                                        key = %tls.private_key_path.display(),
                                        "failed to reload TLS certificates"
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            error = ?error,
                            certificate = %tls.certificate_path.display(),
                            key = %tls.private_key_path.display(),
                            "failed to inspect TLS certificate metadata"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

async fn read_certificate_timestamps(
    config: &ListenerTlsConfig,
) -> Result<(SystemTime, SystemTime)> {
    let cert_meta = fs::metadata(&config.certificate_path)
        .await
        .with_context(|| {
            format!(
                "failed to read certificate metadata at `{}`",
                config.certificate_path.display()
            )
        })?;
    let key_meta = fs::metadata(&config.private_key_path)
        .await
        .with_context(|| {
            format!(
                "failed to read private key metadata at `{}`",
                config.private_key_path.display()
            )
        })?;

    let cert_modified = cert_meta.modified().with_context(|| {
        format!(
            "failed to determine modification time for `{}`",
            config.certificate_path.display()
        )
    })?;
    let key_modified = key_meta.modified().with_context(|| {
        format!(
            "failed to determine modification time for `{}`",
            config.private_key_path.display()
        )
    })?;

    Ok((cert_modified, key_modified))
}

async fn prepare_acme_environment(config: &ListenerTlsAcmeConfig) -> Result<()> {
    fs::create_dir_all(&config.cache_path)
        .await
        .with_context(|| {
            format!(
                "failed to create ACME cache directory `{}`",
                config.cache_path.display()
            )
        })?;

    tracing::info!(
        cache = %config.cache_path.display(),
        contacts = ?config.contact_emails,
        directory = %config
            .directory_url
            .as_deref()
            .unwrap_or("https://acme-v02.api.letsencrypt.org/directory"),
        "ACME automation hooks enabled"
    );

    Ok(())
}

fn load_env_file() -> anyhow::Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(err)) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn run_healthcheck(url: &str, timeout_seconds: u64) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build healthcheck HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to reach health endpoint at `{url}`"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!(
            "health endpoint `{url}` returned status {}",
            response.status()
        ))
    }
}

#[cfg(test)]
mod integration_tests;
