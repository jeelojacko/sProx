# Operational notes

This guide summarises best practices for deploying, monitoring, and securing sProx in
staging and production environments. Adjust the recommendations to fit your existing
observability, compliance, and release management tooling.

## Security posture

- **Principle of least privilege** – Run the proxy under a dedicated system account with
  restricted file system and network permissions. Allow outbound access only to
  configured upstreams and required key servers.
- **Secrets management** – Store TLS private keys, DRM credentials, and API tokens in a
  secret manager (e.g., AWS Secrets Manager, HashiCorp Vault). Inject them at runtime via
  environment variables rather than committing them to configuration files.
- **Direct stream controls** – Keep the `/proxy/stream` allowlist as narrow as possible.
  Require `api_password` for production deployments and rotate the secret frequently. The
  service automatically rejects destinations that resolve to private or documentation IP
  ranges, but explicit network ACLs provide additional protection.
- **Input validation** – Harden manifest parsers against malformed inputs. Reject paths
  containing directory traversal sequences and normalise headers to avoid request
  smuggling issues.
- **Logging hygiene** – Never log tokens, DRM keys, or personally identifiable
  information. Redact sensitive headers at the middleware layer.

## TLS management

- Terminate inbound TLS with modern cipher suites (TLS 1.2+) and enable HTTP/2 ALPN.
- Use `config/listeners/*.yaml` to set per-route certificates when different hostnames are
  served from the same cluster.
- Monitor certificate expiry and automate renewal. Integrate with ACME or corporate PKI
  using background jobs that place renewed keys in a hot-reloadable location.
- Enable `watch_for_changes` on listeners so renewed certificates are reloaded without
  restarts. When ACME cache directories are configured sProx prepares them automatically for
  external clients.
- Enforce strict transport security (HSTS) in client responses and consider enabling TLS
  session resumption to reduce handshake overhead.

## DRM and key services

- Communicate with DRM backends over mutually authenticated TLS when available. This
  protects against impersonation and replay attacks.
- Cache DRM keys in memory for the minimum viable duration (e.g., per-request) and wipe
  buffers after use.
- Implement rate limits and anomaly detection on key requests to prevent abuse.
- Keep packager integrations (FFmpeg/Shaka) patched to the latest security releases.

## Observability

- Emit structured logs (JSON) with request IDs, upstream latency, and manifest processing
  metrics. Forward them to a central aggregation system (ELK, Loki, etc.).
- Publish Prometheus metrics for request volume, response codes, TLS handshakes, manifest
  rewrite timings, direct stream throughput, and DRM key lookup latency via the `/metrics`
  endpoint.
- Trace end-to-end requests with OpenTelemetry (OTLP exporter). Include spans for
  manifest parsing and upstream fetches to identify bottlenecks.

## Deployment and operations

- Use infrastructure-as-code (Terraform, Pulumi, CloudFormation) to provision listener
  frontends, compute, and load balancers.
- Implement blue/green or canary deployments. Validate new releases with synthetic HLS
  playback tests before shifting traffic.
- Configure autoscaling policies based on CPU, network throughput, and manifest
  processing latency. For bursty events, consider pre-scaling nodes.
- Maintain a runbook for incident response, including steps to rotate credentials, roll
  back configurations, and drain traffic.
- Run `sprox validate -c <dir>` during CI/CD to catch configuration errors before rollout.
- Use `kill -HUP` to reload configuration in place; failures fall back to the previous
  snapshot. When TLS `watch_for_changes` is enabled certificate rotations require no manual
  intervention.
- Document required environment overrides (`SPROX_CONFIG`, `SPROX_PROXY_URL`,
  `SPROX_DIRECT_*`) so operators know which secrets must be present in each environment.

## Disaster recovery

- Store configuration and deployment artefacts in version control. Regularly back up
  critical configuration to off-site storage.
- Replicate the service across multiple availability zones or regions to reduce blast
  radius during outages.
- Document recovery time objectives (RTO) and recovery point objectives (RPO) for each
  deployment environment. Test failover procedures at least once per quarter.

## Local-to-production parity

- Mirror production listener and upstream definitions in staging to detect manifest or DRM
  regressions early.
- Use feature flags for experimental manifest rewrites so they can be toggled without a
  redeploy.
- Keep configuration schemas synchronised across environments to avoid runtime surprises.
- Exercise the rate limiter, CORS policies, and direct stream allowlist in staging. Tests
  should confirm that disallowed headers and destinations return `400`/`403` responses.
