# Samma SIEM Engine

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

## Quick Start

```bash
docker compose up -d
```

This starts the SIEM engine alongside a NATS server. Rules are loaded from a mounted volume at `/app/rules`.

### Send a test event

```bash
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{"type": "nmap", "target": "10.0.0.1", "port": 22}'
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SIEM_HTTP_PORT` | `8080` | HTTP server listen port |
| `SIEM_NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `SIEM_NATS_SUBSCRIBE` | _(empty)_ | Comma-separated NATS subjects to subscribe to |
| `SIEM_RULES_DIR` | `./rules` | Directory containing YAML rule files |

## Writing Rules

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

## Running Tests

```bash
# Unit tests
go test ./...

# Integration tests (requires rules + test data)
SIEM_RULES_DIR=./rules SIEM_TEST_DIR=./test go test -v ./...

# Via Docker Compose
docker compose run test
```

## Building

```bash
# Build binary
go build -o siem .

# Build Docker image
docker build -t sammascanner/siem:latest .
```

## License

Copyright Samma IO. All rights reserved.
