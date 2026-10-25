# Samma SIEM

> [!WARNING]
> **The custom YAML rule engine in this repo is deprecated.** That is the Go
> engine in `main.go`, `rule.go`, `server.go` (with `config.go`, `nats.go`) and the
> deployments under [`examples/`](examples/). It gets no new features, and it
> will be removed once a release ships on the new stack.
>
> The Kubernetes SIEM is now:
>
> - **[`chart/samma-siem`](chart/samma-siem/README.md)** in this repo. It installs
>   NATS JetStream, the streams and consumers, and an optional MinIO.
> - **[samma-io/detection-engine](https://github.com/samma-io/detection-engine)**,
>   the Sigma engine used by both the AWS and the k8s SIEM. It runs one service
>   per lane: `k8s` and `scanner`. Its rules live under
>   [`rules/k8s`](https://github.com/samma-io/detection-engine/tree/main/rules/k8s)
>   and [`rules/scanner`](https://github.com/samma-io/detection-engine/tree/main/rules/scanner),
>   each with a `.tests.yml`. All 27 k8s rules from
>   [samma-io/siem-rules](https://github.com/samma-io/siem-rules) were ported
>   there, and so were its nmap and nikto rules (as `scanner` rules).
>
> Write new detections as Sigma rules in detection-engine, not as YAML rules here.
> The rest of this README describes the legacy engine. Keep it only for
> maintaining existing deployments until they are cut over.

## Legacy engine (deprecated)

A lightweight, rule-based Security Information and Event Management (SIEM) engine written in Go. It ingests security events via HTTP and NATS, evaluates them against YAML-defined detection rules, and publishes alerts to NATS subjects.

## Features

- **Dual ingestion** -- HTTP POST (`/ingest`) and NATS subscriptions
- **YAML detection rules** with composable `and`/`or` logic, `equals` and `regex` matchers, and nested field access (dot notation)
- **Compliance mapping** -- PCI DSS, GDPR, HIPAA, NIST 800-53, MITRE ATT&CK, TSC, GPG13
- **NATS alert publishing** -- each rule defines its own output subject
- **Multi-stage Docker build** with a minimal Alpine runtime image
- **Health endpoint** at `/healthz`

## Architecture

```
Events ──► HTTP /ingest ──┐
                          ├──► Rule Engine ──► NATS (alerts)
Events ──► NATS subscribe ┘
```

Events are JSON objects. The rule engine walks all compiled rules and, on a match, publishes a structured alert (rule metadata + original event) to the rule's configured NATS subject.

## Quick Start (legacy)

For local development of the legacy engine only. Do not use this to stand up
a new SIEM; install `chart/samma-siem` with detection-engine instead.

```bash
docker compose up -d
```

This starts the SIEM engine alongside a NATS server. Rules are loaded from a mounted volume at `/app/rules`.

### Send a test event

```bash
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer devtoken" \
  -d '{"type": "nmap", "target": "10.0.0.1", "port": 22}'
```

`/ingest` requires a bearer token configured via `SIEM_INGEST_TOKENS`; requests without a valid token are rejected with `401 unauthorized`. The `/healthz` endpoint requires no token, so liveness probes keep working. Every published alert carries a `source` field identifying the authenticated sender (e.g. `"source": "dev"`) or the NATS subject the event arrived on.

## Configuration (legacy)

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SIEM_HTTP_PORT` | `8080` | HTTP server listen port |
| `SIEM_NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `SIEM_NATS_USER` | _(empty)_ | NATS username (optional; empty disables NATS auth) |
| `SIEM_NATS_PASSWORD` | _(empty)_ | NATS password (optional) |
| `SIEM_NATS_SUBSCRIBE` | _(empty)_ | Comma-separated NATS subjects to subscribe to |
| `SIEM_RULES_DIR` | `./rules` | Directory containing YAML rule files |
| `SIEM_INGEST_TOKENS` | _(empty)_ | Comma-separated `name=token` pairs for `/ingest` bearer auth (e.g. `scanner-fleet=aaa,ci=bbb`). **Required** — the process refuses to start without at least one token |

## Writing Rules (legacy format)

New rules go in [samma-io/detection-engine](https://github.com/samma-io/detection-engine) as Sigma rules. The legacy YAML format is documented below only for reading and maintaining existing rules.

Rules are YAML files placed in the rules directory. Example:

```yaml
name: nmap-ssh-scan
description: Detects nmap scans targeting SSH
severity: medium
nats_subject: samma.alerts.network

compliance:
  mitre:
    - "T1046"
  pci_dss:
    - "11.2"

match:
  and:
    - field: type
      equals: nmap
    - field: port
      equals: "22"
```

### Match conditions

| Type | Description |
|---|---|
| `field` + `equals` | Exact string match on a field (supports dot notation for nested fields) |
| `field` + `regex` | Regex match on a field |
| `and` | All sub-conditions must match |
| `or` | At least one sub-condition must match |

Conditions can be nested arbitrarily (e.g. `and` containing an `or`).

## Running Tests (legacy)

```bash
# Unit tests
go test ./...

# Integration tests (requires rules + test data)
SIEM_RULES_DIR=./rules SIEM_TEST_DIR=./test go test -v ./...

# Via Docker Compose
docker compose run test
```

## Building (legacy)

```bash
# Build binary
go build -o siem .

# Build Docker image
docker build -t sammascanner/siem:latest .
```

## Helm chart (current k8s SIEM)

`chart/samma-siem` is the chart of the Kubernetes SIEM (the NATS transport of
`samma-io/aws-siem`). It installs NATS JetStream, the streams and consumers, and
an optional MinIO; see [`chart/samma-siem/README.md`](chart/samma-siem/README.md).
Detection runs in [samma-io/detection-engine](https://github.com/samma-io/detection-engine),
not in the legacy engine above.

## License

Copyright Samma IO. All rights reserved.
