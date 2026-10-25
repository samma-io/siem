#!/usr/bin/env bash
# Renders chart/samma-siem and checks the stream and consumer definitions
# are there. Run from the repo root after `helm dependency build chart/samma-siem`.
set -euo pipefail
chart=${1:-chart/samma-siem}
helm=${HELM:-helm}
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { "$helm" template ci "$chart" --namespace samma "$@"; }

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

# A second lane without raw records: logs subject and engine consumer only.
out=$(render --set 'lanes[0]=workspace' --set 'lanes[1].name=k8s' --set 'lanes[1].raw=false')
grep -qF '"subjects": ["samma.logs.workspace","samma.logs.k8s"]' <<<"$out" || fail "k8s lane missing from SIEM_LOGS"
grep -qF 'consumer.SIEM_LOGS.detection-engine-k8s.json:' <<<"$out" || fail "no detection-engine-k8s consumer"
grep -qF 'samma.raw.k8s' <<<"$out" && fail "raw: false lane is in SIEM_RAW"

# External NATS and S3, no subcharts.
out=$(render --set nats.enabled=false --set externalNats.url=nats://nats.samma.svc:4222 \
  --set minio.enabled=false --set s3.endpoint=https://s3.example.invalid --set s3.existingSecret=s3)
grep -qF 'value: "nats://nats.samma.svc:4222"' <<<"$out" || fail "externalNats.url not used"
grep -qE '^kind: (StatefulSet|Deployment)' <<<"$out" && fail "subchart rendered while disabled"

# Bad input is refused.
render --set 'lanes[0]=>' >/dev/null 2>&1 && fail "a wildcard lane rendered"
render --set nats.enabled=false >/dev/null 2>&1 && fail "rendered without any NATS URL"
render --set streams.logs.maxAge=7days >/dev/null 2>&1 && fail "a bad duration rendered"

echo "chart render checks passed"
