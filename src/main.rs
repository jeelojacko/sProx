use anyhow::Context;
use std::io::ErrorKind;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    load_env_file()?;
    init_tracing()?;

    sprox::init_placeholder();

    tracing::info!("sProx bootstrap complete");

    Ok(())
}

fn load_env_file() -> anyhow::Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(err)) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn init_tracing() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to construct tracing filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .context("failed to initialize tracing subscriber")
}
