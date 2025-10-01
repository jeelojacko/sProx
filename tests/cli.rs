use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn validate_command_accepts_valid_configuration() {
    let temp = TempDir::new().expect("temp dir should create");
    let config_path = temp.path().join("routes.yaml");
    fs::copy("config/routes.yaml", config_path).expect("config file should copy");

    Command::cargo_bin("sProx")
        .expect("binary should compile")
        .args([
            "validate",
            "-c",
            temp.path().to_str().expect("path should stringify"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("configuration at"));
}
