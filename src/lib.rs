#![allow(non_snake_case)]

//! sProx library crate.
//!
//! The project currently exposes placeholder modules that will be
//! fleshed out in future tasks. The goal of this crate is to ensure the
//! workspace compiles while feature-gated dependencies are wired up.

pub mod app;
#[cfg(feature = "config-loader")]
pub mod config;
pub mod routing;
pub mod security;
pub mod state;

/// Initializes crate-level resources. The implementation will be
/// provided in later steps once configuration loading and telemetry are
/// available.
pub fn init_placeholder() {
    // Intentionally left empty until future tasks add initialization
    // logic.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_placeholder_does_not_panic() {
        init_placeholder();
    }
}
