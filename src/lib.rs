#![allow(non_snake_case)]

//! sProx library crate.
//!
//! The project currently exposes placeholder modules that will be
//! fleshed out in future tasks. The goal of this crate is to ensure the
//! workspace compiles while feature-gated dependencies are wired up.

pub mod app;
pub mod bandwidth;
#[cfg(feature = "config-loader")]
pub mod config;
pub mod ip;
pub mod proxy;
pub mod routing;
pub mod security;
pub mod state;
pub mod stream;
pub use stream::direct;
#[cfg(feature = "telemetry")]
mod telemetry;
pub mod util;

/// Initializes crate-level resources, including telemetry stacks when the
/// corresponding features are enabled.
pub fn init() -> anyhow::Result<()> {
    #[cfg(feature = "telemetry")]
    telemetry::init()?;

    Ok(())
}

#[cfg(feature = "telemetry")]
pub fn scrape_metrics() -> Option<String> {
    telemetry::prometheus_metrics()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_does_not_error() {
        init().expect("initialization should succeed");
    }
}
