#!/usr/bin/env bash
# Renders chart/samma-siem and checks the stream and consumer definitions
# and the workloads are there. Run from the repo root after `helm dependency build chart/samma-siem`.
set -euo pipefail
chart=${1:-chart/samma-siem}
helm=${HELM:-helm}
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { "$helm" template ci "$chart" --namespace samma "$@"; }

# doc NAME KIND: the rendered document of that kind and metadata.name.
doc() {
  awk -v name="$1" -v kind="$2" '
    /^---/ { if (k && n) print buf; buf=""; k=0; n=0; next }
    { buf = buf $0 "\n" }
    $0 == "kind: " kind { k=1 }
    $0 == "  name: " name { n=1 }
    END { if (k && n) print buf }' <<<"$out"
}
# deployments: the names of the Deployments this chart renders.
deployments() {
  awk '/^---/ { k=0 } /^kind: Deployment$/ { k=1 } k && /^  name: / { print $2; k=0 }' <<<"$out" | sort
}
# check_workload NAME WANT...: the Deployment exists, is hardened, and has
# every WANT line in it. RUN_AS is the uid it must run as (default 65532).
check_workload() {
  local name=$1 d; shift
  d=$(doc "$name" Deployment)
  [ -n "$d" ] || fail "no Deployment $name"
  for want in \
    'automountServiceAccountToken: false' 'runAsNonRoot: true' "runAsUser: ${RUN_AS:-65532}" \
    'readOnlyRootFilesystem: true' 'allowPrivilegeEscalation: false' 'drop: [ALL]' \
    'type: RuntimeDefault' 'kubernetes.io/arch: amd64' 'limits:' 'requests:' \
    "$@"
  do
    grep -qF -- "$want" <<<"$d" || fail "Deployment $name lacks $want"
  done
  grep -qE 'image: .*:latest$' <<<"$d" && fail "Deployment $name runs a latest image"
  return 0
}
# services: the names of the Services this chart (not its subcharts) renders.
services() {
  awk '/^---/ { k=0 } /^kind: Service$/ { k=1 } k && /^  name: / { print $2; k=0 }' <<<"$out" | grep '^ci-samma-siem-' | sort
}
# consumers: the consumer configs in the streams ConfigMap.
consumers() {
  grep -oE '^  consumer\.[A-Z_]+\.[a-z0-9-]+\.json:' <<<"$out" | sed 's/^  consumer\.//; s/\.json:$//' | sort
}

out=$(render)

# The four streams of the contract, with their subjects.
for want in \
  'stream.SIEM_RAW.json:' '"subjects": ["samma.raw.workspace"]' \
  'stream.SIEM_LOGS.json:' '"subjects": ["samma.logs.workspace"]' \
  'stream.SIEM_ALERTS.json:' '"subjects": ["samma.alerts.>"]' \
  'stream.INGESTER_SLICES.json:' '"subjects": ["samma.ingester.slices.>"]' \
  '"retention": "workqueue"'
do
  grep -qF -- "$want" <<<"$out" || fail "render lacks $want"
done

# The durable consumers, one per lane and per ingester source.
for want in \
  'consumer.SIEM_RAW.vector-workspace.json:' \
  'consumer.SIEM_LOGS.detection-engine-workspace.json:' \
  'consumer.SIEM_ALERTS.alert-destination.json:' \
  'consumer.INGESTER_SLICES.ingester-google-workspace.json:' \
  '"max_deliver": 5' '"ack_policy": "explicit"'
do
  grep -qF -- "$want" <<<"$out" || fail "render lacks $want"
done

# Never a wildcard on the lane streams.
grep -qE '"samma\.(raw|logs)\.>"' <<<"$out" && fail "a lane stream captures a wildcard"

# No Ingress, nothing but ClusterIP.
grep -qE '^kind: Ingress' <<<"$out" && fail "render contains an Ingress"
grep -qE 'type: (NodePort|LoadBalancer)' <<<"$out" && fail "render exposes a Service outside the cluster"

# Hook Jobs exist.
grep -qF 'name: ci-samma-siem-streams' <<<"$out" || fail "no streams Job"
grep -qF 'name: ci-samma-siem-bucket' <<<"$out" || fail "no bucket Job"

# The workloads with the default values: one lane, one ingester source.
nats='value: "nats://ci-nats.samma.svc:4222"'
want_deps=$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-workspace \
  ci-samma-siem-ingester-google-workspace ci-samma-siem-siem-storage ci-samma-siem-vector | sort)
[ "$(deployments)" = "$want_deps" ] || fail "default Deployments: $(deployments | tr '\n' ' ')"
[ "$(services)" = "ci-samma-siem-detection-engine-workspace" ] || fail "default Services: $(services | tr '\n' ' ')"
want_cons=$(printf '%s\n' SIEM_ALERTS.alert-destination SIEM_ALERTS.storage-s3-alerts \
  SIEM_LOGS.detection-engine-workspace SIEM_LOGS.storage-logs SIEM_LOGS.storage-s3-logs \
  SIEM_RAW.vector-workspace INGESTER_SLICES.ingester-google-workspace | sort)
[ "$(consumers)" = "$want_cons" ] || fail "default consumers: $(consumers | tr '\n' ' ')"
grep -qE 'name: ci-samma-siem-(quickwit|grafana)$' <<<"$out" && fail "quickwit or grafana rendered by default"
check_workload ci-samma-siem-detection-engine-workspace \
  'image: ghcr.io/samma-io/detection-engine:d5d7439' \
  '- name: ENGINE_TRANSPORT' 'value: "workspace"' "$nats" \
  'value: "detection-engine-workspace"' 'value: "samma.logs.workspace"' \
  '- name: ENGINE_VISIBILITY_TIMEOUT' 'value: "300s"' 'path: /readyz'
check_workload ci-samma-siem-vector \
  'image: ghcr.io/samma-io/vector:f2f2dea' 'args: [--config, "/etc/vector/vector-k8s.yaml"]' \
  '- name: NATS_URL' "$nats" 'path: /health'
check_workload ci-samma-siem-ingester-google-workspace \
  'image: ghcr.io/samma-io/ingester:89ed408' 'args: [daemon]' 'replicas: 0' 'type: Recreate' \
  '- name: INGESTER_TRANSPORT' 'value: "google-workspace"' "$nats" \
  '- name: INGESTER_POSTGRES_DSN_FILE' 'secretName: siem-postgres' \
  'value: /var/run/secrets/ingester/key.json' 'secretName: ingester-google'
check_workload ci-samma-siem-alert-destination \
  'image: ghcr.io/samma-io/alert-destination:779befa' \
  '- name: ALERTDEST_TRANSPORT' "$nats" '- name: ALERTDEST_POSTGRES_DSN_FILE' \
  'value: /etc/alert-destination/routes.yaml' 'name: ci-samma-siem-alert-routes' \
  'secretName: siem-postgres'
for v in ENGINE INGESTER ALERTDEST; do
  grep -qF -- "- name: ${v}_TRANSPORT
              value: nats" <<<"$out" || fail "${v}_TRANSPORT is not nats"
done
routes=$(doc ci-samma-siem-alert-routes ConfigMap)
grep -qF 'require_slack: false' <<<"$routes" || fail "routes do not say require_slack: false"
grep -qF '{to: postgres, target: siem_alerts}' <<<"$routes" || fail "routes do not deliver to siem_alerts"
grep -qE '^    (slack|github):' <<<"$routes" && fail "default routes name slack or github"
grep -qF 'kind: Service
metadata:
  name: ci-samma-siem-detection-engine-workspace' <<<"$out" || fail "no engine Service"
check_workload ci-samma-siem-siem-storage \
  'image: ghcr.io/samma-io/siem-storage:sha-6c3f143' \
  '- name: STORAGE_BACKENDS' 'value: "postgres,s3"' "$nats" \
  'value: storage-logs' 'value: SIEM_LOGS' 'name: siem-postgres' 'key: dsn' \
  'value: "http://ci-minio.samma.svc:9000"' 'value: "samma-siem-archive"' 'value: "5m"' \
  'name: ci-minio' 'key: rootUser' 'key: rootPassword' 'path: /healthz'
grep -qF -- '- name: STORAGE_NATS_SUBSCRIBE' <<<"$out" && fail "siem-storage creates its own consumer"
# The storage consumers: every lane's log subject, and the S3 AckWait above
# the 5m flush interval (6m) with the service's max_ack_pending.
cons() { grep -A12 -F "consumer.$1.json:" <<<"$out"; }
grep -qF '"filter_subjects": ["samma.logs.workspace"]' <<<"$(cons SIEM_LOGS.storage-logs)" || fail "storage-logs filter"
grep -qF '"ack_wait": 60000000000' <<<"$(cons SIEM_LOGS.storage-logs)" || fail "storage-logs AckWait"
grep -qF '"ack_wait": 360000000000' <<<"$(cons SIEM_LOGS.storage-s3-logs)" || fail "storage-s3-logs AckWait"
grep -qF '"max_ack_pending": 10000' <<<"$(cons SIEM_LOGS.storage-s3-logs)" || fail "storage-s3-logs max_ack_pending"
grep -qF '"filter_subject": "samma.alerts.>"' <<<"$(cons SIEM_ALERTS.storage-s3-alerts)" || fail "storage-s3-alerts filter"
grep -qF '"ack_wait": 120000000000' <<<"$(cons SIEM_ALERTS.storage-s3-alerts)" || fail "storage-s3-alerts AckWait"

# One storage backend at a time: only its consumers.
out=$(render --set-json 'storage.backends=["postgres"]')
[ "$(consumers | grep storage)" = "SIEM_LOGS.storage-logs" ] || fail "postgres only: $(consumers | grep storage | tr '\n' ' ')"
grep -qF 'STORAGE_S3_' <<<"$out" && fail "postgres only still configures S3"
out=$(render --set-json 'storage.backends=["s3"]')
[ "$(consumers | grep storage | tr '\n' ' ')" = "SIEM_ALERTS.storage-s3-alerts SIEM_LOGS.storage-s3-logs " ] || fail "s3 only: $(consumers | grep storage | tr '\n' ' ')"
grep -qF 'STORAGE_POSTGRES_DSN' <<<"$out" && fail "s3 only still reads the DSN"
out=$(render --set storage.enabled=false)
consumers | grep -q storage && fail "storage consumers without storage"
deployments | grep -q siem-storage && fail "siem-storage rendered while disabled"

# Everything on: storage, Quickwit and Grafana with every lane.
out=$(render -f "$chart/ci/all-enabled-values.yaml")
want_deps=$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-k8s \
  ci-samma-siem-detection-engine-scanner ci-samma-siem-detection-engine-workspace ci-samma-siem-grafana \
  ci-samma-siem-ingester-google-workspace ci-samma-siem-quickwit ci-samma-siem-siem-storage ci-samma-siem-vector | sort)
[ "$(deployments)" = "$want_deps" ] || fail "all-enabled Deployments: $(deployments | tr '\n' ' ')"
want_svcs=$(printf '%s\n' ci-samma-siem-detection-engine-k8s ci-samma-siem-detection-engine-scanner \
  ci-samma-siem-detection-engine-workspace ci-samma-siem-grafana ci-samma-siem-quickwit | sort)
[ "$(services)" = "$want_svcs" ] || fail "all-enabled Services: $(services | tr '\n' ' ')"
want_cons=$(printf '%s\n' SIEM_ALERTS.alert-destination SIEM_ALERTS.storage-s3-alerts \
  SIEM_LOGS.detection-engine-workspace SIEM_LOGS.detection-engine-k8s SIEM_LOGS.detection-engine-scanner \
  SIEM_LOGS.storage-logs SIEM_LOGS.storage-s3-logs SIEM_RAW.vector-workspace \
  INGESTER_SLICES.ingester-google-workspace | sort)
[ "$(consumers)" = "$want_cons" ] || fail "all-enabled consumers: $(consumers | tr '\n' ' ')"
lanes='["samma.logs.workspace","samma.logs.k8s","samma.logs.scanner"]'
grep -qF "\"filter_subjects\": $lanes" <<<"$(cons SIEM_LOGS.storage-logs)" || fail "storage-logs lacks a lane"
grep -qF "\"filter_subjects\": $lanes" <<<"$(cons SIEM_LOGS.storage-s3-logs)" || fail "storage-s3-logs lacks a lane"
check_workload ci-samma-siem-siem-storage 'value: "postgres,s3"' "$nats"
check_workload ci-samma-siem-quickwit \
  'image: ghcr.io/samma-io/quickwit:ci-placeholder' 'type: Recreate' \
  '- name: QW_MODE' 'value: k8s' 'name: siem-quickwit-metastore' 'key: uri' \
  'value: "s3://samma-siem-archive/quickwit/indexes"' 'value: "http://ci-minio.samma.svc:9000"' \
  '- name: QW_S3_FORCE_PATH_STYLE_ACCESS' 'name: ci-minio' \
  'mountPath: /quickwit/qwdata' 'mountPath: /tmp' 'path: /health/readyz'
RUN_AS=472 check_workload ci-samma-siem-grafana \
  'image: ghcr.io/samma-io/grafana:ci-placeholder' \
  'value: /etc/grafana/provisioning-k8s' 'value: "http://ci-samma-siem-quickwit.samma.svc:7280/api/v1"' \
  '- name: GF_SECURITY_ADMIN_PASSWORD' '- name: SIEM_POSTGRES_HOST' '- name: SIEM_POSTGRES_DB' \
  '- name: SIEM_POSTGRES_USER' '- name: SIEM_POSTGRES_PASSWORD' '- name: SIEM_POSTGRES_SSLMODE' \
  'name: siem-grafana' 'mountPath: /var/lib/grafana-data' 'path: /api/health'
grep -qF 'siem-postgres' <<<"$(doc ci-samma-siem-grafana Deployment)" && fail "Grafana gets the writer's Postgres Secret"
for svc in ci-samma-siem-quickwit ci-samma-siem-grafana; do
  grep -qF 'type: ClusterIP' <<<"$(doc $svc Service)" || fail "Service $svc is not ClusterIP"
done
grep -qF 'values: [grafana, vector]' <<<"$(doc ci-samma-siem-quickwit NetworkPolicy)" || fail "no Quickwit NetworkPolicy"
grep -qE '^kind: Ingress' <<<"$out" && fail "all-enabled render contains an Ingress"
grep -qE 'type: (NodePort|LoadBalancer)' <<<"$out" && fail "all-enabled render exposes a Service outside the cluster"

# Every lane: workspace plus the NATS-only k8s and scanner lanes.
out=$(render -f "$chart/ci/all-lanes-values.yaml")
want_deps=$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-k8s \
  ci-samma-siem-detection-engine-scanner ci-samma-siem-detection-engine-workspace \
  ci-samma-siem-ingester-google-workspace ci-samma-siem-siem-storage ci-samma-siem-vector | sort)
[ "$(deployments)" = "$want_deps" ] || fail "all-lanes Deployments: $(deployments | tr '\n' ' ')"
for lane in workspace k8s scanner; do
  check_workload "ci-samma-siem-detection-engine-$lane" \
    "value: \"$lane\"" "value: \"detection-engine-$lane\"" "value: \"samma.logs.$lane\"" "$nats"
  grep -qF "consumer.SIEM_LOGS.detection-engine-$lane.json:" <<<"$out" || fail "no detection-engine-$lane consumer"
done
grep -qF 'siem.samma.io/raw-lanes: "workspace"' <<<"$out" || fail "vector is not on the workspace raw lane only"
check_workload ci-samma-siem-vector "$nats"

# A second lane without raw records: logs subject and engine consumer only.
out=$(render --set 'lanes[0]=workspace' --set 'lanes[1].name=k8s' --set 'lanes[1].raw=false')
grep -qF '"subjects": ["samma.logs.workspace","samma.logs.k8s"]' <<<"$out" || fail "k8s lane missing from SIEM_LOGS"
grep -qF 'consumer.SIEM_LOGS.detection-engine-k8s.json:' <<<"$out" || fail "no detection-engine-k8s consumer"
grep -qF 'samma.raw.k8s' <<<"$out" && fail "raw: false lane is in SIEM_RAW"

# External NATS and S3, no subcharts.
out=$(render --set nats.enabled=false --set externalNats.url=nats://nats.samma.svc:4222 \
  --set minio.enabled=false --set s3.endpoint=https://s3.example.invalid --set s3.existingSecret=s3)
grep -qF 'value: "nats://nats.samma.svc:4222"' <<<"$out" || fail "externalNats.url not used"
grep -qE '^kind: StatefulSet' <<<"$out" && fail "nats subchart rendered while disabled"
grep -qE '^  name: ci-(nats|minio)' <<<"$out" && fail "subchart rendered while disabled"
for v in ENGINE_NATS_URL INGESTER_NATS_URL ALERTDEST_NATS_URL STORAGE_NATS_URL NATS_URL; do
  grep -qF -- "- name: $v
              value: \"nats://nats.samma.svc:4222\"" <<<"$out" || fail "$v does not use externalNats.url"
done
grep -qF 'ci-nats.samma.svc' <<<"$out" && fail "a workload still points at the in-release NATS"
grep -qF 'value: "https://s3.example.invalid"' <<<"$(doc ci-samma-siem-siem-storage Deployment)" || fail "siem-storage does not use s3.endpoint"
grep -qF 'name: s3' <<<"$(doc ci-samma-siem-siem-storage Deployment)" || fail "siem-storage does not use s3.existingSecret"

# No lane with raw records: no Vector.
out=$(render --set 'lanes[0].name=k8s' --set 'lanes[0].raw=false' --set ingester.enabled=false)
[ "$(deployments)" = "$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-k8s ci-samma-siem-siem-storage | sort)" ] \
  || fail "raw: false only: $(deployments | tr '\n' ' ')"

# Bad input is refused.
render --set 'lanes[0]=>' >/dev/null 2>&1 && fail "a wildcard lane rendered"
render --set nats.enabled=false >/dev/null 2>&1 && fail "rendered without any NATS URL"
render --set streams.logs.maxAge=7days >/dev/null 2>&1 && fail "a bad duration rendered"
render --set detectionEngine.tag=latest >/dev/null 2>&1 && fail "a latest image rendered"
render --set vector.tag= >/dev/null 2>&1 && fail "an image without tag or digest rendered"
render --set postgres.existingSecret= >/dev/null 2>&1 && fail "rendered without the Postgres Secret"
render --set ingester.perSource.google-workspace.replicas=1 >/dev/null 2>&1 && fail "a live Workspace ingester rendered without its subject"
render --set ingester.perSource.google-workspace.replicas=2 >/dev/null 2>&1 && fail "two ingester replicas rendered"
render --set-json 'ingester.sources=["google-workspace","slack"]' >/dev/null 2>&1 && fail "an ingester source rendered without its raw lane"
render --set alertDestination.slack.enabled=true >/dev/null 2>&1 && fail "require_slack rendered with the postgres-only routes"
render --set alertDestination.messageTimeout=120s >/dev/null 2>&1 && fail "a message timeout at the AckWait rendered"
render --set-json 'detectionEngine.env={"ENGINE_TRANSPORT":"sqs"}' >/dev/null 2>&1 && fail "the transport was overridden through env"

# Storage, Quickwit and Grafana refusals.
all=(-f "$chart/ci/all-enabled-values.yaml")
render --set storage.tag= >/dev/null 2>&1 && fail "siem-storage rendered without a tag"
render --set-json 'storage.backends=["elasticsearch"]' >/dev/null 2>&1 && fail "an unsupported storage backend rendered"
render --set-json 'storage.backends=[]' >/dev/null 2>&1 && fail "siem-storage rendered without a backend"
render --set consumers.ackWait.storageS3Logs=5m >/dev/null 2>&1 && fail "an S3 AckWait at the flush interval rendered"
render --set-json 'storage.env={"STORAGE_BACKENDS":"elasticsearch"}' >/dev/null 2>&1 && fail "the storage backends were overridden through env"
render --set quickwit.enabled=true --set quickwit.metastore.existingSecret=m >/dev/null 2>&1 && fail "quickwit rendered without a tag"
render --set quickwit.enabled=true --set quickwit.tag=latest --set quickwit.metastore.existingSecret=m >/dev/null 2>&1 && fail "quickwit rendered with latest"
render --set quickwit.enabled=true --set quickwit.tag=abc1234 >/dev/null 2>&1 && fail "quickwit rendered without its metastore Secret"
render "${all[@]}" --set quickwit.replicas=2 >/dev/null 2>&1 && fail "two quickwit replicas rendered"
render "${all[@]}" --set quickwit.indexRootUri=file:///x >/dev/null 2>&1 && fail "a non-S3 quickwit index root rendered"
render --set grafana.enabled=true --set grafana.existingSecret=g >/dev/null 2>&1 && fail "grafana rendered without a tag"
render --set grafana.enabled=true --set grafana.tag=abc1234 >/dev/null 2>&1 && fail "grafana rendered without its read-only Secret"
render "${all[@]}" --set grafana.existingSecret=siem-postgres >/dev/null 2>&1 && fail "grafana rendered with the writer's Postgres Secret"
render "${all[@]}" --set grafana.existingSecret=pg --set postgres.existingSecret=pg >/dev/null 2>&1 && fail "grafana rendered with postgres.existingSecret"
render "${all[@]}" --set-json 'grafana.env={"QUICKWIT_URL":"http://x"}' >/dev/null 2>&1 && fail "QUICKWIT_URL was overridden through env"
render "${all[@]}" >/dev/null || fail "the all-enabled values do not render"

echo "chart render checks passed"
