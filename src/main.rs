use std::io::ErrorKind;

fn main() -> anyhow::Result<()> {
    load_env_file()?;

    sProx::init()?;

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
