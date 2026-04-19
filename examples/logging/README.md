# Logging Stack + SIEM on Kubernetes (Talos Linux)

A complete, production-ready logging pipeline that collects all container logs from a Kubernetes cluster, stores them in Loki for search, and feeds them through the Samma SIEM for real-time threat detection and compliance alerting.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Every K8s Node                                                  │
│  ┌──────────────┐                                                │
│  │  Fluent Bit  │  DaemonSet — tails /var/log/containers/*.log   │
│  │  (DaemonSet) │  enriches with pod/namespace/container labels  │
│  └──────┬───────┘                                                │
└─────────┼───────────────────────────────────────────────────────┘
          │ Fluent Forward :24224
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  namespace: logging                                              │
│                                                                  │
│  ┌──────────────────┐    samma.logs.k8s    ┌──────────────────┐ │
│  │ Vector Collector │ ──────────────────► │      NATS        │ │
│  │  (Deployment)    │                      │  (StatefulSet)   │ │
│  └──────────────────┘                      │  JetStream LOGS  │ │
│                                            └────────┬─────────┘ │
│  ┌──────────────────┐                               │           │
│  │ Vector Aggregator│ ◄─────────────────────────────┘           │
│  │  (Deployment)    │  queue: vector-aggregator                  │
│  └────────┬─────────┘                                           │
│           │ HTTP :3100                                           │
│           ▼                                                      │
│  ┌──────────────────┐                                           │
│  │      Loki        │  log storage — queryable via LogQL         │
│  │  (SingleBinary)  │                                           │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
          │
          │ samma.logs.> (cross-namespace — NATS is reachable)
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  namespace: samma                                                │
│                                                                  │
│  ┌──────────────────┐    samma.alerts.*   ┌──────────────────┐  │
│  │   Samma SIEM     │ ──────────────────► │      NATS        │  │
│  │  (rule engine)   │                      │  (same broker)   │  │
│  └──────────────────┘                      └────────┬─────────┘  │
│                                                     │            │
│  ┌──────────────────┐                               │            │
│  │   Alert Sink     │ ◄─────────────────────────────┘            │
│  │    (Vector)      │  queue: alert-sink                         │
│  └────────┬─────────┘                                           │
│           │ HTTP :3100 → Loki (logging namespace)               │
│           ▼                                                      │
│      Grafana — LogQL dashboards for logs and alerts             │
└─────────────────────────────────────────────────────────────────┘
```

### NATS Subjects

| Subject | Producer | Consumer | Purpose |
|---------|----------|----------|---------|
| `samma.logs.k8s` | Vector Collector | Vector Aggregator, SIEM | All container logs |
| `samma.alerts.*` | SIEM | Alert Sink | Rule match alerts |

### Files in this Directory

| File | Purpose |
|------|---------|
| `ns.yaml` | `logging` and `samma` namespaces with privileged PSA labels |
| `nats.yaml` | Single-node NATS StatefulSet with JetStream (5Gi PVC) |
| `nats-stream-setup.yaml` | One-time Job — creates the `LOGS` JetStream stream |
| `loki-values.yaml` | Helm values for Loki SingleBinary (50Gi PVC) |
| `fluentbit.yaml` | Fluent Bit DaemonSet + ClusterRole + ConfigMap |
| `vector.yaml` | Vector Collector (Fluent Bit → NATS) + Vector Aggregator (NATS → Loki) |
| `siem.yaml` | Samma SIEM Deployment + Alert Sink (alerts → Loki) |

---

## Prerequisites

- Kubernetes cluster running **Talos Linux** (or any standard distribution)
- `kubectl` configured for your cluster
- Helm 3
- SIEM container image available: `sammascanner/siem:v0.1`
- Detection rules directory (from the `siem-rules` repo)

Add Helm repos:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

---

## Talos Linux Notes

Fluent Bit runs as a DaemonSet and mounts host paths (`/var/log/containers`, `/var/log/pods`, `/run`). Talos enforces Pod Security Admission — **both namespaces must have the `privileged` enforcement label** before any workload is scheduled. `ns.yaml` already sets this.

No Talos machine configuration changes are needed. Container logs are written to `/var/log/containers/` on every node in the standard CRI format, exactly as on any other Kubernetes distribution.

---

## Deploy

Apply resources in this exact order. Each step waits for the previous to be ready.

### Step 1 — Namespaces

```bash
kubectl apply -f ns.yaml
```

### Step 2 — NATS with JetStream

```bash
kubectl apply -f nats.yaml
kubectl rollout status statefulset/nats -n logging --timeout=120s
```

### Step 3 — Create the LOGS stream

```bash
kubectl apply -f nats-stream-setup.yaml
kubectl wait -n logging --for=condition=complete job/nats-stream-setup --timeout=60s
```

### Step 4 — Loki

```bash
helm upgrade --install loki grafana/loki \
  --version 6.7.4 \
  --namespace logging \
  -f loki-values.yaml

kubectl rollout status statefulset/loki -n logging --timeout=180s
```

### Step 5 — Vector Collector and Aggregator

```bash
kubectl apply -f vector.yaml
kubectl rollout status deployment/vector-collector -n logging --timeout=60s
kubectl rollout status deployment/vector-aggregator -n logging --timeout=60s
```

### Step 6 — Fluent Bit

Start Fluent Bit last — once the full downstream pipeline (NATS → Loki) is ready.

```bash
kubectl apply -f fluentbit.yaml
kubectl rollout status daemonset/fluent-bit -n logging --timeout=60s
```

### Step 7 — Load Detection Rules

Clone the `siem-rules` repo alongside this repo and create the rules ConfigMap:

```bash
kubectl create configmap siem-rules -n samma \
  --from-file=../../../../siem-rules/rules/
```

To update rules later without restarting the SIEM:

```bash
kubectl create configmap siem-rules -n samma \
  --from-file=../../../../siem-rules/rules/ \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 8 — SIEM and Alert Sink

```bash
kubectl apply -f siem.yaml
kubectl rollout status deployment/siem -n samma --timeout=60s
kubectl rollout status deployment/alert-sink -n samma --timeout=60s
```

---

## Verify

### All pods running

```bash
kubectl get pods -n logging
kubectl get pods -n samma
```

Expected output — all pods in `Running` or `Completed` state:

```
NAMESPACE   NAME                               READY   STATUS
logging     fluent-bit-<hash>                  1/1     Running   (one per node)
logging     nats-0                             1/1     Running
logging     nats-stream-setup-<hash>           0/1     Completed
logging     loki-0                             1/1     Running
logging     vector-collector-<hash>            1/1     Running
logging     vector-aggregator-<hash>           1/1     Running
samma       siem-<hash>                        1/1     Running
samma       alert-sink-<hash>                  1/1     Running
```

### Check log flow through each component

```bash
# Fluent Bit — should show log lines being read from /var/log/containers
kubectl logs -n logging -l app=fluent-bit --tail=20

# Vector Collector — should show events forwarded to NATS
kubectl logs -n logging -l app=vector-collector --tail=20

# Vector Aggregator — should show events written to Loki
kubectl logs -n logging -l app=vector-aggregator --tail=20

# SIEM — should show rules loaded and events being evaluated
kubectl logs -n samma -l app=siem --tail=20
```

### Verify the NATS stream has messages

```bash
kubectl run nats-test --rm -it --restart=Never \
  --image=natsio/nats-box:0.14.5 \
  -- nats stream info LOGS \
     --server nats://nats.logging.svc.cluster.local:4222
```

Look for `Num Messages` to be greater than 0.

### Check Loki has logs

```bash
kubectl port-forward -n logging svc/loki-headless 3100:3100 &

# Loki ready
curl -s localhost:3100/ready

# Labels present — means logs arrived
curl -s 'localhost:3100/loki/api/v1/labels' | jq .values

# Query recent logs
curl -sG 'localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={namespace=~".+"}' \
  --data-urlencode 'limit=5' | jq '.data.result[].stream'
```

### SIEM health check

```bash
kubectl port-forward -n samma svc/siem 8080:8080 &
curl http://localhost:8080/healthz
# → {"status":"ok"}
```

### End-to-end alert test

Publish a synthetic event that matches a SIEM rule:

```bash
kubectl run nats-test --rm -it --restart=Never \
  --image=natsio/nats-box:0.14.5 \
  -- nats pub samma.logs.k8s \
     '{"source_type":"kubernetes","namespace":"default","pod":"test","container":"test","verb":"exec","objectRef":{"resource":"pods","subresource":"exec"}}' \
     --server nats://nats.logging.svc.cluster.local:4222
```

Then check the SIEM logs for a rule match and check Loki for the alert:

```bash
kubectl logs -n samma -l app=siem --tail=10

# Query SIEM alerts in Loki
curl -sG 'localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="siem-alerts"}' \
  --data-urlencode 'limit=5' | jq '.data.result[].values[][1]'
```

---

## Grafana Setup

Deploy Grafana (any method — Helm, manifest, existing instance) and add two datasources:

### Datasource: Logs

| Field | Value |
|-------|-------|
| Type | Loki |
| Name | Logs |
| URL | `http://loki.logging.svc.cluster.local:3100` |
| Auth | None |

### Datasource: Alerts

| Field | Value |
|-------|-------|
| Type | Loki |
| Name | SIEM Alerts |
| URL | `http://loki.logging.svc.cluster.local:3100` |
| Auth | None |

### Sample LogQL Queries

**All logs from a namespace:**
```logql
{namespace="kube-system"}
```

**Logs from a specific pod:**
```logql
{pod=~"coredns.*"}
```

**Error lines across the cluster:**
```logql
{namespace=~".+"} |= "error"
```

**All SIEM alerts:**
```logql
{job="siem-alerts"}
```

**Critical alerts only:**
```logql
{job="siem-alerts", severity="critical"}
```

**Alerts for a specific rule:**
```logql
{job="siem-alerts"} | json | rule_name="pod-exec-detected"
```

---

## Syslog from External Devices

The Vector Collector exposes a NodePort for syslog — routers, firewalls, and servers can ship logs directly into the pipeline without any agent.

- **UDP:** `<any-node-ip>:30514`
- **TCP:** `<any-node-ip>:30515`

Configure your device to forward syslog to any cluster node IP. Logs appear in Loki with `{source="syslog"}`.

---

## Cleanup

```bash
kubectl delete -f siem.yaml
kubectl delete -f fluentbit.yaml
kubectl delete -f vector.yaml
helm uninstall loki -n logging
kubectl delete -f nats-stream-setup.yaml
kubectl delete -f nats.yaml
kubectl delete -f ns.yaml
```

---

## What Comes Next

- **Custom rules** — add YAML rule files to the `siem-rules` repo and reload the ConfigMap (Step 7). No SIEM restart needed if the rules directory is watched.
- **Audit logs** — deploy the Talos audit log collector (`../../audit-log-collector.yaml`) to feed K8s API server audit events into the same NATS subject.
- **Alerts to Elasticsearch** — swap the Alert Sink in `siem.yaml` to write to Elasticsearch instead of Loki for richer aggregation and the existing Grafana compliance dashboards (see `../simple/alert-sink.yaml`).
- **Multi-node NATS** — for production, replace `nats.yaml` with a 3-node cluster (see `../../code/nats.yaml` in the v2-k8s repo for a reference Helm-based deployment).
