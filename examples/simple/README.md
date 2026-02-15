# Simple Kubernetes Deployment

This example deploys the Samma SIEM into a Kubernetes cluster with the following pipeline:

```
K8s Logs --> Fluent Bit --> Vector --> NATS --> SIEM --> NATS (alerts) --> Vector (sink) --> Elasticsearch --> Grafana
```

## Architecture

| Component       | Role                                                              |
|-----------------|-------------------------------------------------------------------|
| Fluent Bit      | DaemonSet that tails container logs and forwards them to Vector   |
| Vector          | Aggregator that formats logs and publishes them to NATS           |
| NATS            | Message broker connecting all components                          |
| SIEM            | Reads logs from NATS, evaluates rules, publishes alerts to NATS   |
| Alert Sink      | Vector instance that subscribes to NATS alerts and writes to Elasticsearch |
| Elasticsearch   | Stores alerts for search and analysis                             |
| Grafana         | Dashboard UI for visualizing and exploring alerts                 |

## Prerequisites

- A running Kubernetes cluster (minikube, kind, or cloud-managed)
- `kubectl` configured against your cluster
- `helm` v3 installed
- The SIEM container image built and available (`sammascanner/siem:v0.1`)
- Detection rules ready (from the `siem-rules` repo)

## Step 1 - Create namespace

```bash
kubectl apply -f namespace.yaml
```

## Step 2 - Deploy NATS

Install NATS using the official Helm chart as described in the
[NATS Kubernetes documentation](https://docs.nats.io/running-a-nats-service/nats-kubernetes).

```bash
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm repo update
helm install nats nats/nats -n samma -f nats-values.yaml
```

This deploys a single NATS server with JetStream enabled and a `nats-box` pod for testing.

### Verify NATS

```bash
kubectl exec -n samma deployment/nats-box -- nats pub test "hello samma"
```

You should see: `Published 12 bytes to "test"`

## Step 3 - Deploy Vector (log aggregator)

Vector receives logs from Fluent Bit, formats them, and publishes to NATS.

```bash
helm repo add vector https://helm.vector.dev
helm repo update
helm install vector vector/vector -n samma -f vector-values.yaml
```

## Step 4 - Deploy Fluent Bit

Fluent Bit runs as a DaemonSet, reading container logs from each node and forwarding
them to Vector.

```bash
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
helm install fluent-bit fluent/fluent-bit -n samma -f fluent-bit-values.yaml
```

## Step 5 - Load detection rules

Create a ConfigMap from your rules directory. This assumes the `siem-rules` repo is
cloned next to the `siem` repo.

```bash
kubectl create configmap siem-rules -n samma --from-file=../../../siem-rules/rules/
```

To update rules later:

```bash
kubectl create configmap siem-rules -n samma --from-file=../../../siem-rules/rules/ \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Step 6 - Deploy the SIEM

```bash
kubectl apply -f siem.yaml
```

The SIEM subscribes to `samma.logs.>` on NATS. When a log event matches a rule, it
publishes an alert to the rule's configured NATS subject (e.g. `samma.alerts.k8s.user_login`).

### Verify the SIEM

```bash
kubectl get pods -n samma -l app=siem
kubectl logs -n samma -l app=siem
```

Check the health endpoint:

```bash
kubectl port-forward -n samma svc/siem 8080:8080 &
curl http://localhost:8080/healthz
```

## Step 7 - Deploy Elasticsearch

```bash
kubectl apply -f elasticsearch.yaml
```

Wait for the pod to become ready:

```bash
kubectl wait -n samma --for=condition=ready pod -l app=elasticsearch --timeout=120s
```

## Step 8 - Deploy the alert sink

The alert sink is a Vector instance that subscribes to `samma.alerts.>` on NATS and
writes every alert into Elasticsearch, indexed by severity.

```bash
kubectl apply -f alert-sink.yaml
```

## Step 9 - Deploy Grafana

Grafana is pre-configured with an Elasticsearch datasource pointing at the `samma-alerts-*`
indices. Default credentials are `admin` / `samma`.

```bash
kubectl apply -f grafana.yaml
```

Wait for it to start:

```bash
kubectl wait -n samma --for=condition=ready pod -l app=grafana --timeout=90s
```

Access the Grafana UI:

```bash
kubectl port-forward -n samma svc/grafana 3000:3000
```

Then open http://localhost:3000 and go to **Explore** to query alerts from Elasticsearch.

## Verify the full pipeline

1. **Check all pods are running:**

```bash
kubectl get pods -n samma
```

2. **Publish a test event through NATS:**

```bash
kubectl exec -n samma deployment/nats-box -- nats pub samma.logs.k8s.test \
  '{"kind":"Event","objectRef":{"resource":"users"},"verb":"authenticate"}'
```

3. **Check the SIEM logs for a match:**

```bash
kubectl logs -n samma -l app=siem --tail=20
```

4. **Query Elasticsearch for the alert:**

```bash
kubectl port-forward -n samma svc/elasticsearch 9200:9200 &
curl -s 'http://localhost:9200/samma-alerts-*/_search?pretty'
```

5. **View alerts in Grafana:**

```bash
kubectl port-forward -n samma svc/grafana 3000:3000
```

Open http://localhost:3000 (admin / samma), go to **Explore**, select the
**Elasticsearch - Alerts** datasource, and run a query.

## Data flow summary

```
                                   samma.logs.k8s.*
  Fluent Bit ──> Vector ──────────────────────────────> NATS
  (DaemonSet)   (aggregator)                             │
                                                         │ subscribe: samma.logs.>
                                                         v
                                                        SIEM
                                                    (rule engine)
                                                         │
                                                         │ publish: samma.alerts.*
                                                         v
                                                        NATS
                                                         │
                                                         │ subscribe: samma.alerts.>
                                                         v
                                                   Alert Sink (Vector)
                                                         │
                                                         v
                                                   Elasticsearch
                                                  (samma-alerts-*)
                                                         │
                                                         v
                                                      Grafana
                                                    (dashboards)
```

## Cleanup

```bash
helm uninstall fluent-bit -n samma
helm uninstall vector -n samma
helm uninstall nats -n samma
kubectl delete -f grafana.yaml
kubectl delete -f alert-sink.yaml
kubectl delete -f siem.yaml
kubectl delete -f elasticsearch.yaml
kubectl delete -f namespace.yaml
```
