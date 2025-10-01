use std::fs;

use sProx::{
    config::Config,
    state::{reload_app_state_from_path, AppState, SharedAppState},
};
use tempfile::TempDir;
use tokio::runtime::Runtime;

const INITIAL_CONFIG: &str = r#"
routes:
  - id: "alpha"
    listen:
      host: "127.0.0.1"
      port: 8080
    host_patterns: []
    protocols: ["http"]
    upstream:
      origin: "http://initial.example.com"
"#;

const UPDATED_CONFIG: &str = r#"
routes:
  - id: "alpha"
    listen:
      host: "127.0.0.1"
      port: 8080
    host_patterns: []
    protocols: ["http"]
    upstream:
      origin: "https://updated.example.com"
"#;

const INVALID_CONFIG: &str = r#"
routes:
  - id: "alpha"
    listen:
      host: "127.0.0.1"
      port: 8080
    host_patterns: []
    protocols: ["http"]
    upstream:
      tls:
        enabled: true
"#;

#[test]
fn reload_replaces_state_on_success() {
    let runtime = Runtime::new().expect("runtime should start");
    let temp = TempDir::new().expect("temp dir should create");
    let config_path = temp.path().join("routes.yaml");
    fs::write(&config_path, INITIAL_CONFIG).expect("config should write");

    let config = Config::load_from_path(&config_path).expect("config should load");
    let shared = SharedAppState::new(AppState::from_config(&config).expect("state should build"));

    runtime.block_on(async {
        assert_eq!(
            current_upstream(&shared).await,
            "http://initial.example.com"
        );
    });

    fs::write(&config_path, UPDATED_CONFIG).expect("config should update");
    reload_app_state_from_path(&config_path, &shared).expect("reload should succeed");

    runtime.block_on(async {
        assert_eq!(
            current_upstream(&shared).await,
            "https://updated.example.com"
        );
    });
}

#[test]
fn reload_preserves_state_when_validation_fails() {
    let runtime = Runtime::new().expect("runtime should start");
    let temp = TempDir::new().expect("temp dir should create");
    let config_path = temp.path().join("routes.yaml");
    fs::write(&config_path, INITIAL_CONFIG).expect("config should write");

    let config = Config::load_from_path(&config_path).expect("config should load");
    let shared = SharedAppState::new(AppState::from_config(&config).expect("state should build"));

    runtime.block_on(async {
        assert_eq!(
            current_upstream(&shared).await,
            "http://initial.example.com"
        );
    });

    fs::write(&config_path, INVALID_CONFIG).expect("config should update");
    let result = reload_app_state_from_path(&config_path, &shared);
    assert!(result.is_err(), "reload should fail for invalid config");

    runtime.block_on(async {
        assert_eq!(
            current_upstream(&shared).await,
            "http://initial.example.com"
        );
    });
}

async fn current_upstream(state: &SharedAppState) -> String {
    let snapshot = state.snapshot();
    let table = snapshot.routing_table();
    let guard = table.read().await;
    guard
        .values()
        .next()
        .expect("route should exist")
        .upstream
        .trim_end_matches('/')
        .to_string()
}
