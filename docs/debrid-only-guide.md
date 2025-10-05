# Debrid-only streaming quickstart

This guide walks through the smallest possible sProx deployment that exposes **only**
the `/proxy/stream` endpoint for Real-Debrid, AllDebrid, or EasyDebrid style playback
clients. It is written for operators with minimal infrastructure background and covers
three practical topics:

1. Preparing the environment variables required for debrid access
2. Running the proxy directly on your machine (Rust toolchain)
3. Running the proxy with Docker Compose using the same configuration bundle

The instructions below assume a Linux or macOS workstation. Windows users can run the
same commands from within Windows Subsystem for Linux (WSL).

---

## 1. Collect the required values

1. **Clone the repository** (or download the archive) and change into the project
   directory:
   ```bash
   git clone https://github.com/<org>/sProx.git
   cd sProx
   ```
2. **Generate secrets** that protect the proxy's authenticated endpoints. Copy the
   example file and edit the values in a text editor:
   ```bash
   cp .env.example .env
   ```

   Replace the placeholder values with your own. At minimum you need:

   ```dotenv
   # .env (debrid-only)
   API_PASSWORD="choose-a-strong-passphrase"
   SIGNING_SECRET="base64-string-from-openssl"
   AES_KEY="hex-string-from-openssl"
   SPROX_DIRECT_API_PASSWORD="proxy-shared-secret"
   ```

   *Optional debrid provider tokens*: only define `REALDEBRID_API_TOKEN`,
   `ALLDEBRID_API_TOKEN`, or `EASYDEBRID_API_TOKEN` when you plan to call the
   provider's API directly. The `/proxy/stream` endpoint simply forwards the URL it
   receives, so if your addon embeds the token inside the link you can leave these
   variables unset.
   * `SPROX_DIRECT_API_PASSWORD` is the password end-user apps must include when calling
     `/proxy/stream` (send it as the `Authorization: Bearer` header).

   Generate random strings with `openssl rand -base64 32` (for `SIGNING_SECRET`) and
   `openssl rand -hex 32` (for `AES_KEY`), then paste the results into the file.

3. **Create a minimal configuration** dedicated to direct streaming. Save the following
   as `config/debrid-only.yaml`:

   ```yaml
   routes:
     - id: "direct-listener"
       listen:
         host: "0.0.0.0"
         port: 8080
       host_patterns:
         - "localhost"
         - "127.0.0.1"
       upstream:
         origin: "https://example.com/placeholder"
         connect_timeout_ms: 1000
         read_timeout_ms: 3000
         request_timeout_ms: 5000
         tls:
           enabled: true
           sni_hostname: "example.com"
           insecure_skip_verify: false
         socks5:
           enabled: false
           address: null
           username: null
           password: null
         redirect:
           follow_max: 3
       hls:
         enabled: false

   direct_stream:
     request_timeout_ms: 45000
     response_buffer_bytes: 131072
     allowlist:
       - domain: "real-debrid.com"
         schemes: ["https"]
         paths:
           - "/d/**"
       - domain: "alldebrid.com"
         schemes: ["https"]
         paths:
           - "/v/**"
       - domain: "easydebrid.com"
         schemes: ["https"]
         paths:
           - "/d/**"

   secrets:
     default_ttl_secs: 300
   ```

   This configuration exposes a single listener on port 8080 (required by sProx's boot
   process) but the upstream route is a placeholder that should never be exercised for
   debrid-only usage. All meaningful traffic flows through `/proxy/stream`, which is
   restricted by the allowlist. The `.env` value `SPROX_DIRECT_API_PASSWORD` injects the
   shared secret at runtime, so no plaintext password lives inside the configuration file.
   Expand the allowlist with additional domains (e.g. regional mirrors or `www.`
   subdomains) if your account requires them.

---

## 2. Run locally with the Rust toolchain

Running the binary directly is useful for testing configuration edits before you build
images or push changes to a server.

1. **Install Rust** (only required once):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add x86_64-unknown-linux-gnu   # optional on macOS
   ```
2. **Build the optimized binary** without DRM-specific features:
   ```bash
   cargo build --release --no-default-features --features "http-proxy config-loader telemetry"
   ```
3. **Launch the proxy** using the dedicated configuration file:
   ```bash
   ./target/release/sprox --config config/debrid-only.yaml
   ```
4. **Test the direct stream endpoint** from another terminal:
   ```bash
   curl -H "Authorization: Bearer $SPROX_DIRECT_API_PASSWORD" \
        "http://127.0.0.1:8080/proxy/stream?url=https%3A%2F%2Freal-debrid.com%2Fd%2F<id>"
   ```

   Replace `<id>` with the identifier extracted from your Real-Debrid link. The proxy
   returns the upstream response exactly as the client would receive it. If the command
   succeeds you can point your player or automation tooling at the same URL.

### Useful maintenance commands

```bash
# Validate the configuration file and environment variables
cargo run --release -- validate -c config/debrid-only.yaml

# Follow structured logs while the service is running
RUST_LOG=info ./target/release/sprox --config config/debrid-only.yaml
```

---

## 3. Run with Docker Compose

The container workflow is nearly identical but bundles the runtime into a single command.
Ensure Docker Desktop (macOS/Windows) or Docker Engine (Linux) is installed before
continuing.

1. **Create a Docker Compose file** named `docker-compose.debrid.yaml` in the project
   root:

   ```yaml
   services:
     sprox:
       image: ghcr.io/<org>/sprox:latest
       container_name: sprox-debrid
       restart: unless-stopped
       ports:
         - "8080:8080"
       environment:
         SPROX_CONFIG: /config/debrid-only.yaml
       env_file:
         - .env
       volumes:
         - ./config/debrid-only.yaml:/config/debrid-only.yaml:ro
       command: ["--config", "/config/debrid-only.yaml"]
   ```

2. **Start the stack**:
   ```bash
   docker compose -f docker-compose.debrid.yaml up -d
   ```
3. **Check health** and follow logs:
   ```bash
   docker compose -f docker-compose.debrid.yaml ps
   docker compose -f docker-compose.debrid.yaml logs -f
   ```
4. **Invoke the endpoint** exactly as in the local workflow—port `8080` on your host is
   forwarded to the container.

To remove the service entirely, run:
```bash
docker compose -f docker-compose.debrid.yaml down
```

---

## Frequently asked questions

- **Can I expose HTTPS?** Yes. Terminate TLS in front of the container (nginx, Caddy, or
  a CDN) or mount certificates into the container and add a route listener that serves
  HTTPS on port 8443.
- **How do I add IP restrictions?** Place the proxy behind a firewall or reverse proxy
  that supports IP allowlists. sProx focuses on request validation and relies on your
  network perimeter for coarse-grained access control.
- **Where should the logs go?** Docker users can forward logs with a logging driver. Bare
  metal deployments can use `systemd` service files and journal forwarding.

This quickstart keeps the moving pieces to an absolute minimum—only the direct stream
endpoint and secrets vault are active. You can layer on additional listeners, DRM
features, or observability later by merging this configuration with the defaults in
`config/routes.yaml`.
