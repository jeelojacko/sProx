use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::process::Stdio;
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use reqwest::StatusCode;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::sleep;

#[tokio::test]
async fn tls_server_starts_with_self_signed_cert() {
    let temp = TempDir::new().expect("temp dir should create");
    let config_path = temp.path().join("routes.yaml");
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");

    fs::copy("tests/fixtures/tls/cert.pem", &cert_path).expect("certificate should copy");
    fs::copy("tests/fixtures/tls/key.pem", &key_path).expect("key should copy");

    let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port should bind");
    let port = listener
        .local_addr()
        .expect("address should resolve")
        .port();
    drop(listener);

    let config = format!(
        r#"routes:
  - id: "tls"
    listen:
      host: "127.0.0.1"
      port: {port}
      tls:
        enabled: true
        certificate_path: "{cert}"
        private_key_path: "{key}"
        watch_for_changes: false
    host_patterns: []
    protocols: ["http"]
    upstream:
      origin: "http://127.0.0.1:1"
"#,
        port = port,
        cert = cert_path.display(),
        key = key_path.display(),
    );

    fs::write(&config_path, config).expect("config should write");

    let binary = AssertCommand::cargo_bin("sProx")
        .expect("binary should be built")
        .get_program()
        .to_owned();

    let mut child = Command::new(&binary)
        .env("SPROX_CONFIG", &config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("server should spawn");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client should build");

    let url = format!("https://127.0.0.1:{port}/health");
    let mut attempts = 0;
    let response = loop {
        match client.get(&url).send().await {
            Ok(response) => break response,
            Err(error) => {
                attempts += 1;
                if attempts >= 20 {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    panic!("failed to reach TLS health endpoint: {error}");
                }

                sleep(Duration::from_millis(100)).await;
            }
        }
    };

    assert_eq!(response.status(), StatusCode::OK);

    let _ = child.kill().await;
    let _ = child.wait().await;
}
