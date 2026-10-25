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
# every WANT line in it.
check_workload() {
  local name=$1 d; shift
  d=$(doc "$name" Deployment)
  [ -n "$d" ] || fail "no Deployment $name"
  for want in \
    'automountServiceAccountToken: false' 'runAsNonRoot: true' 'runAsUser: 65532' \
    'readOnlyRootFilesystem: true' 'allowPrivilegeEscalation: false' 'drop: [ALL]' \
    'type: RuntimeDefault' 'kubernetes.io/arch: amd64' 'limits:' 'requests:' \
    "$@"
  do
    grep -qF -- "$want" <<<"$d" || fail "Deployment $name lacks $want"
  done
  grep -qE 'image: .*:latest$' <<<"$d" && fail "Deployment $name runs a latest image"
  return 0
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
  ci-samma-siem-ingester-google-workspace ci-samma-siem-vector | sort)
[ "$(deployments)" = "$want_deps" ] || fail "default Deployments: $(deployments | tr '\n' ' ')"
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

# Every lane: workspace plus the NATS-only k8s and scanner lanes.
out=$(render -f "$chart/ci/all-lanes-values.yaml")
want_deps=$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-k8s \
  ci-samma-siem-detection-engine-scanner ci-samma-siem-detection-engine-workspace \
  ci-samma-siem-ingester-google-workspace ci-samma-siem-vector | sort)
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
for v in ENGINE_NATS_URL INGESTER_NATS_URL ALERTDEST_NATS_URL NATS_URL; do
  grep -qF -- "- name: $v
              value: \"nats://nats.samma.svc:4222\"" <<<"$out" || fail "$v does not use externalNats.url"
done
grep -qF 'ci-nats.samma.svc' <<<"$out" && fail "a workload still points at the in-release NATS"

# No lane with raw records: no Vector.
out=$(render --set 'lanes[0].name=k8s' --set 'lanes[0].raw=false' --set ingester.enabled=false)
[ "$(deployments)" = "$(printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-detection-engine-k8s | sort)" ] \
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

echo "chart render checks passed"
