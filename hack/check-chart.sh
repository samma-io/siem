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

# SIEM_RAW's duplicate window covers a Workspace reconcile pass's reach (6h
# lookback + 1h interval + margin = 8h, samma-io/ingester#8); SIEM_LOGS has
# no lane cap without the k8s lane.
stream() { grep -A20 -F "stream.$1.json:" <<<"$out"; }
grep -qF '"duplicate_window": 28800000000000,' <<<"$(stream SIEM_RAW)" || fail "SIEM_RAW duplicate window is not 8h"
grep -qF '"max_bytes": 419430400,' <<<"$(stream SIEM_LOGS)" || fail "SIEM_LOGS max_bytes is not 400MiB"
grep -qF '"duplicate_window": 7200000000000,' <<<"$(stream INGESTER_SLICES)" || fail "INGESTER_SLICES duplicate window changed"

# Never a wildcard on the lane streams.
grep -qE '"samma\.(raw|logs)\.>"' <<<"$out" && fail "a lane stream captures a wildcard"

# No Ingress, nothing but ClusterIP.
grep -qE '^kind: Ingress' <<<"$out" && fail "render contains an Ingress"
grep -qE 'type: (NodePort|LoadBalancer)' <<<"$out" && fail "render exposes a Service outside the cluster"

# Hook Jobs exist.
grep -qF 'name: ci-samma-siem-streams' <<<"$out" || fail "no streams Job"
grep -qF 'name: ci-samma-siem-bucket' <<<"$out" || fail "no bucket Job"

# Under ArgoCD the Jobs are Sync hooks in wave 1, after NATS and MinIO (wave
# 0) and before the Deployments (wave 2); the Helm hooks stay for helm install.
for job in ci-samma-siem-streams ci-samma-siem-bucket; do
  d=$(doc "$job" Job)
  for want in 'helm.sh/hook: post-install,post-upgrade' 'helm.sh/hook-delete-policy: before-hook-creation' \
    'argocd.argoproj.io/hook: Sync' 'argocd.argoproj.io/hook-delete-policy: BeforeHookCreation' \
    'argocd.argoproj.io/sync-wave: "1"'
  do
    grep -qF -- "$want" <<<"$d" || fail "Job $job lacks $want"
  done
done
# check_waves: every Deployment of this chart is in wave 2, nothing else in the
# render (subcharts, ConfigMaps, Secrets, Services) is in a wave of its own.
check_waves() {
  local name
  for name in $(deployments | grep '^ci-samma-siem-'); do
    grep -qF 'argocd.argoproj.io/sync-wave: "2"' <<<"$(doc "$name" Deployment)" || fail "Deployment $name is not in sync wave 2"
  done
  grep -qF 'argocd.argoproj.io/sync-wave' <<<"$(doc ci-minio Deployment)" && fail "the MinIO Deployment has a sync wave"
  [ "$(grep -c 'argocd.argoproj.io/sync-wave' <<<"$out")" = "$(( $(deployments | grep -c '^ci-samma-siem-') + $(grep -c 'argocd.argoproj.io/hook: Sync' <<<"$out") ))" ] \
    || fail "a resource other than the Jobs and Deployments has a sync wave"
  return 0
}
check_waves

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
grep -qF 'INGESTER_SECRETS' <<<"$(doc ci-samma-siem-ingester-google-workspace Deployment)" && fail "the Workspace ingester has INGESTER_SECRETS"
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
# Without quickwit.enabled Vector runs its base config only, and without
# alertDestination.existingSecret alert-destination has no token files.
vec=$(doc ci-samma-siem-vector Deployment)
grep -qF 'QUICKWIT_URL' <<<"$vec" && fail "vector has QUICKWIT_URL without quickwit.enabled"
grep -qF 'vector-k8s-quickwit' <<<"$vec" && fail "vector has a Quickwit overlay without quickwit.enabled"
ad=$(doc ci-samma-siem-alert-destination Deployment)
grep -qF '_TOKEN_FILE' <<<"$ad" && fail "alert-destination has token files without existingSecret"
grep -qF '/var/run/secrets/alert-destination' <<<"$ad" && fail "alert-destination mounts tokens without existingSecret"

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

# Everything on: storage, Quickwit and Grafana with every lane, Vector into
# Quickwit, Slack and GitHub routes.
all_values=(-f "$chart/ci/all-enabled-values.yaml")
out=$(render "${all_values[@]}")
saas='workspace slack onepassword cloudflare'
want_deps=$( (printf '%s\n' ci-minio ci-samma-siem-alert-destination ci-samma-siem-grafana ci-samma-siem-quickwit \
  ci-samma-siem-siem-storage ci-samma-siem-vector ci-samma-siem-detection-engine-k8s ci-samma-siem-detection-engine-scanner \
  ci-samma-siem-ingester-google-workspace ci-samma-siem-ingester-slack ci-samma-siem-ingester-onepassword ci-samma-siem-ingester-cloudflare
  for l in $saas; do echo "ci-samma-siem-detection-engine-$l"; done) | sort)
[ "$(deployments)" = "$want_deps" ] || fail "all-enabled Deployments: $(deployments | tr '\n' ' ')"
check_waves
want_svcs=$( (printf '%s\n' ci-samma-siem-detection-engine-k8s ci-samma-siem-detection-engine-scanner \
  ci-samma-siem-grafana ci-samma-siem-quickwit
  for l in $saas; do echo "ci-samma-siem-detection-engine-$l"; done) | sort)
[ "$(services)" = "$want_svcs" ] || fail "all-enabled Services: $(services | tr '\n' ' ')"
want_cons=$( (printf '%s\n' SIEM_ALERTS.alert-destination SIEM_ALERTS.storage-s3-alerts \
  SIEM_LOGS.detection-engine-k8s SIEM_LOGS.detection-engine-scanner \
  SIEM_LOGS.storage-logs SIEM_LOGS.storage-s3-logs SIEM_ALERTS.vector-alerts-quickwit \
  SIEM_LOGS.vector-quickwit-k8s SIEM_LOGS.vector-quickwit-scanner \
  INGESTER_SLICES.ingester-google-workspace INGESTER_SLICES.ingester-slack \
  INGESTER_SLICES.ingester-onepassword INGESTER_SLICES.ingester-cloudflare
  for l in $saas; do echo "SIEM_RAW.vector-$l"; echo "SIEM_LOGS.detection-engine-$l"; done) | sort)
[ "$(consumers)" = "$want_cons" ] || fail "all-enabled consumers: $(consumers | tr '\n' ' ')"
lanes='["samma.logs.workspace","samma.logs.slack","samma.logs.onepassword","samma.logs.cloudflare","samma.logs.k8s","samma.logs.scanner"]'
grep -qF '"subjects": ["samma.raw.workspace","samma.raw.slack","samma.raw.onepassword","samma.raw.cloudflare"]' <<<"$(stream SIEM_RAW)" || fail "all-enabled SIEM_RAW subjects"
# SIEM_LOGS: 400MiB plus the k8s lane's 2GiB.
grep -qF '"max_bytes": 2566914048,' <<<"$(stream SIEM_LOGS)" || fail "SIEM_LOGS max_bytes lacks the k8s lane cap"
grep -qF 'siem.samma.io/raw-lanes: "workspace,slack,onepassword,cloudflare"' <<<"$out" || fail "vector raw-lanes annotation"
# The token sources read their Secret's key token with INGESTER_SECRETS=file.
for src in slack onepassword cloudflare; do
  up=$(tr a-z A-Z <<<"$src")
  check_workload "ci-samma-siem-ingester-$src" 'image: ghcr.io/samma-io/ingester:b4c844c' \
    "value: \"$src\"" '- name: INGESTER_SECRETS
              value: file' "- name: INGESTER_${up}_TOKEN_FILE
              value: /var/run/secrets/ingester/token" \
    'mountPath: /var/run/secrets/ingester' "secretName: ingester-$src"
  d=$(doc "ci-samma-siem-ingester-$src" Deployment)
  grep -qF 'GOOGLE_APPLICATION_CREDENTIALS' <<<"$d" && fail "ingester-$src has GOOGLE_APPLICATION_CREDENTIALS"
  grep -qF '_TOKEN_PARAM' <<<"$d" && fail "ingester-$src has a *_TOKEN_PARAM"
  [ "$(grep -c '_TOKEN_FILE' <<<"$d")" = 1 ] || fail "ingester-$src has more than its own token file"
done
grep -qF 'replicas: 1' <<<"$(doc ci-samma-siem-ingester-slack Deployment)" || fail "ingester-slack is not live"
grep -qF 'replicas: 0' <<<"$(doc ci-samma-siem-ingester-onepassword Deployment)" || fail "ingester-onepassword is not at 0"
check_workload ci-samma-siem-ingester-cloudflare 'replicas: 1' \
  '- name: INGESTER_CLOUDFLARE_ACCOUNT_ID' '- name: INGESTER_CLOUDFLARE_ZONE_IDS'
grep -qF 'INGESTER_SECRETS' <<<"$(doc ci-samma-siem-ingester-google-workspace Deployment)" && fail "the Workspace ingester has INGESTER_SECRETS"
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
# Vector into Quickwit: every overlay after the base config (logs-saas,
# alerts, then the k8s and scanner lanes), QUICKWIT_URL the REST base without
# /api/v1, and the consumers of the alerts and lane overlays.
check_workload ci-samma-siem-vector "$nats" \
  'args: [--config, "/etc/vector/vector-k8s.yaml", --config, "/etc/vector/vector-k8s-quickwit.yaml", --config, "/etc/vector/vector-k8s-quickwit-alerts.yaml", --config, "/etc/vector/vector-k8s-quickwit-k8s.yaml", --config, "/etc/vector/vector-k8s-quickwit-scanner.yaml"]' \
  '- name: QUICKWIT_URL
              value: "http://ci-samma-siem-quickwit.samma.svc:7280"'
grep -qF '"filter_subject": "samma.alerts.>"' <<<"$(cons SIEM_ALERTS.vector-alerts-quickwit)" || fail "vector-alerts-quickwit filter"
grep -qF '"durable_name": "vector-alerts-quickwit"' <<<"$(cons SIEM_ALERTS.vector-alerts-quickwit)" || fail "vector-alerts-quickwit name"
grep -qF '"ack_wait": 120000000000' <<<"$(cons SIEM_ALERTS.vector-alerts-quickwit)" || fail "vector-alerts-quickwit AckWait"
for lane in k8s scanner; do
  c=$(cons "SIEM_LOGS.vector-quickwit-$lane")
  grep -qF "\"durable_name\": \"vector-quickwit-$lane\"" <<<"$c" || fail "vector-quickwit-$lane name"
  grep -qF "\"filter_subject\": \"samma.logs.$lane\"" <<<"$c" || fail "vector-quickwit-$lane filter"
  grep -qF '"ack_wait": 60000000000' <<<"$c" || fail "vector-quickwit-$lane AckWait"
done
# Slack and GitHub routed: both token files, from the whole Secret.
check_workload ci-samma-siem-alert-destination \
  '- name: ALERTDEST_SLACK_TOKEN_FILE
              value: /var/run/secrets/alert-destination/slack-token' \
  '- name: ALERTDEST_GITHUB_TOKEN_FILE
              value: /var/run/secrets/alert-destination/github-token' \
  'mountPath: /var/run/secrets/alert-destination' 'secretName: siem-alert-destination'
grep -qE '^ *subPath:' <<<"$(doc ci-samma-siem-alert-destination Deployment)" && fail "the token Secret is mounted by subPath"
grep -qF '{to: slack, target: C0EXAMPLE1}' <<<"$(doc ci-samma-siem-alert-routes ConfigMap)" || fail "the all-enabled routes do not reach slack"

# Quickwit without vector.quickwitAlerts: the logs overlay only, no consumer.
out=$(render "${all_values[@]}" --set vector.quickwitAlerts=false)
check_workload ci-samma-siem-vector \
  'args: [--config, "/etc/vector/vector-k8s.yaml", --config, "/etc/vector/vector-k8s-quickwit.yaml", --config, "/etc/vector/vector-k8s-quickwit-k8s.yaml", --config, "/etc/vector/vector-k8s-quickwit-scanner.yaml"]' \
  'value: "http://ci-samma-siem-quickwit.samma.svc:7280"'
consumers | grep -q vector-alerts-quickwit && fail "vector-alerts-quickwit without vector.quickwitAlerts"
# One lane overlay: workspace and k8s only, the k8s overlay and consumer.
out=$(render "${all_values[@]}" --set-json 'lanes=["workspace",{"name":"k8s","raw":false}]' \
  --set-json 'ingester.sources=["google-workspace"]')
check_workload ci-samma-siem-vector \
  'args: [--config, "/etc/vector/vector-k8s.yaml", --config, "/etc/vector/vector-k8s-quickwit.yaml", --config, "/etc/vector/vector-k8s-quickwit-alerts.yaml", --config, "/etc/vector/vector-k8s-quickwit-k8s.yaml"]'
[ "$(consumers | grep vector-quickwit)" = "SIEM_LOGS.vector-quickwit-k8s" ] || fail "workspace+k8s: $(consumers | grep vector-quickwit | tr '\n' ' ')"
# The k8s and scanner overlays layer on the base config, which reads
# vector-workspace: without the workspace raw lane they are refused, and with
# vector.enabled: false there is no Vector and none of its consumers.
nows=(--set-json 'lanes=[{"name":"k8s","raw":false},{"name":"scanner","raw":false}]' --set ingester.enabled=false)
render "${all_values[@]}" "${nows[@]}" >/dev/null 2>&1 && fail "the k8s and scanner overlays rendered without the workspace lane"
render "${all_values[@]}" "${nows[@]}" --set streams.enabled=false >/dev/null 2>&1 && fail "the k8s and scanner overlays rendered without the workspace lane (no streams)"
render "${all_values[@]}" --set-json 'lanes=[{"name":"workspace","raw":false},{"name":"k8s","raw":false}]' --set ingester.enabled=false >/dev/null 2>&1 \
  && fail "the k8s overlay rendered with a workspace lane without raw records"
err=$(render "${all_values[@]}" "${nows[@]}" 2>&1 >/dev/null || true)
grep -qF 'add lane workspace (with raw records) to lanes, or set vector.enabled: false' <<<"$err" || fail "the workspace-lane refusal does not say what to do: $err"
out=$(render "${all_values[@]}" "${nows[@]}" --set vector.enabled=false)
deployments | grep -q vector && fail "vector rendered while disabled"
consumers | grep -q vector- && fail "a Vector consumer without a Vector: $(consumers | grep vector- | tr '\n' ' ')"

# existingSecret with the default postgres-only table: both files are set
# (alert-destination ignores the unrouted ones), nothing is refused.
out=$(render --set alertDestination.existingSecret=tokens)
check_workload ci-samma-siem-alert-destination \
  '- name: ALERTDEST_SLACK_TOKEN_FILE' '- name: ALERTDEST_GITHUB_TOKEN_FILE' 'secretName: tokens' 
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
consumers | grep -q vector-quickwit && fail "vector-quickwit consumers without quickwit.enabled"
grep -qF 'vector-k8s-quickwit' <<<"$(doc ci-samma-siem-vector Deployment)" && fail "a Quickwit overlay without quickwit.enabled"
grep -qF '"max_bytes": 2566914048,' <<<"$(stream SIEM_LOGS)" || fail "all-lanes SIEM_LOGS max_bytes lacks the k8s lane cap"

# A second lane without raw records: logs subject and engine consumer only.
out=$(render --set 'lanes[0]=workspace' --set 'lanes[1].name=k8s' --set 'lanes[1].raw=false' \
  --set nats.config.jetstream.fileStore.pvc.size=4Gi)
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
out=$(render --set 'lanes[0].name=k8s' --set 'lanes[0].raw=false' --set ingester.enabled=false \
  --set nats.config.jetstream.fileStore.pvc.size=4Gi)
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

# Ingester token sources (siem#23): a live one needs its Secret, Cloudflare
# its account and zones, and the chart's names cannot be overridden.
ae=(-f "$chart/ci/all-enabled-values.yaml")
render "${ae[@]}" --set ingester.perSource.slack.existingSecret= >/dev/null 2>&1 && fail "a live Slack ingester rendered without its Secret"
render "${ae[@]}" --set ingester.perSource.onepassword.replicas=1 --set ingester.perSource.onepassword.existingSecret= >/dev/null 2>&1 && fail "a live 1Password ingester rendered without its Secret"
render "${ae[@]}" --set ingester.perSource.onepassword.replicas=1 >/dev/null || fail "a live 1Password ingester with its Secret does not render"
render "${ae[@]}" --set ingester.perSource.cloudflare.existingSecret= >/dev/null 2>&1 && fail "a live Cloudflare ingester rendered without its Secret"
for k in INGESTER_CLOUDFLARE_ACCOUNT_ID INGESTER_CLOUDFLARE_ZONE_IDS; do
  render "${ae[@]}" --set "ingester.perSource.cloudflare.env.$k=" >/dev/null 2>&1 && fail "a live Cloudflare ingester rendered without $k"
done
render "${ae[@]}" --set ingester.perSource.slack.replicas=2 >/dev/null 2>&1 && fail "two Slack ingester replicas rendered"
for v in INGESTER_SECRETS INGESTER_SLACK_TOKEN_FILE INGESTER_ONEPASSWORD_TOKEN_FILE INGESTER_CLOUDFLARE_TOKEN_FILE; do
  render "${ae[@]}" --set-json "ingester.perSource.slack.env={\"$v\":\"x\"}" >/dev/null 2>&1 && fail "$v was overridden through env"
done
render "${ae[@]}" --set-json 'lanes=["workspace","slack","onepassword",{"name":"k8s","raw":false}]' >/dev/null 2>&1 && fail "the Cloudflare ingester rendered without its raw lane"
render "${ae[@]}" --set-json 'lanes=["workspace",{"name":"slack","raw":false},"onepassword","cloudflare"]' >/dev/null 2>&1 && fail "the Slack ingester rendered with a lane without raw records"

# SIEM_RAW's duplicate window (ingester#8): at least 6h plus the Workspace
# reconcile interval, and never above maxAge.
render --set streams.raw.duplicateWindow=2h >/dev/null 2>&1 && fail "a 2h SIEM_RAW duplicate window rendered"
render --set streams.raw.duplicateWindow=7h >/dev/null || fail "a 7h duplicate window with a 1h reconcile interval does not render"
render --set ingester.reconcileInterval=3h >/dev/null 2>&1 && fail "an 8h window rendered with a 3h reconcile interval"
render --set ingester.perSource.google-workspace.reconcileInterval=3h >/dev/null 2>&1 && fail "an 8h window rendered with a 3h Workspace reconcile interval"
render --set ingester.enabled=false --set streams.raw.duplicateWindow=2h >/dev/null || fail "the window is checked without an ingester"
render --set streams.raw.duplicateWindow=25h >/dev/null 2>&1 && fail "a duplicate window above maxAge rendered"

# SIEM_LOGS's k8s lane cap (siem#24) against the JetStream PVC.
al=(-f "$chart/ci/all-lanes-values.yaml")
err=$(render "${al[@]}" --set nats.config.jetstream.fileStore.pvc.size=1Gi 2>&1 >/dev/null || true)
grep -qF 'add up to 2758 MiB, more than the JetStream file store' <<<"$err" || fail "the k8s lane cap rendered on a 1Gi PVC: $err"
render "${al[@]}" --set nats.config.jetstream.fileStore.pvc.size=3Gi >/dev/null || fail "the k8s lane cap does not render on a 3Gi PVC"
render "${al[@]}" --set nats.config.jetstream.fileStore.pvc.size=2700Mi >/dev/null 2>&1 && fail "the caps rendered above a 2700Mi PVC"
render "${al[@]}" --set nats.config.jetstream.fileStore.maxSize=1Gi >/dev/null 2>&1 && fail "the caps rendered above fileStore.maxSize"
render "${al[@]}" --set nats.config.jetstream.fileStore.pvc.size=1Gi --set nats.config.jetstream.fileStore.maxSize=3Gi >/dev/null \
  || fail "fileStore.maxSize does not win over the PVC size"
render "${al[@]}" --set streams.logs.laneMaxBytes.k8s=300MiB --set nats.config.jetstream.fileStore.pvc.size=1Gi >/dev/null \
  || fail "a 300MiB k8s cap does not fit a 1Gi PVC"
render --set streams.logs.maxBytes=1GiB >/dev/null 2>&1 && fail "the default caps rendered above the 1Gi PVC"
render "${al[@]}" --set nats.config.jetstream.fileStore.pvc.size=1Gi --set nats.enabled=false --set externalNats.url=nats://n:4222 >/dev/null \
  || fail "an external NATS was held to the bundled PVC"
render "${al[@]}" --set streams.logs.laneMaxBytes.k8s=2GB >/dev/null 2>&1 && fail "a bad lane cap rendered"

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

# Slack/GitHub tokens and Vector's Quickwit overlays: refusals.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/slack-routes.yaml" <<'YAML'
routes:
  - {level: "*", log_source: "*", deliveries: [{to: postgres, target: siem_alerts}, {to: slack, target: C0X}]}
default:
  deliveries: [{to: postgres, target: siem_alerts}, {to: slack, target: C0X}]
YAML
cat >"$tmp/github-default.yaml" <<'YAML'
require_slack: false
routes: []
default:
  deliveries: [{to: github, target: o/r}]
YAML
slack=(--set-file "alertDestination.routes=$tmp/slack-routes.yaml")
github=(--set-file "alertDestination.routes=$tmp/github-default.yaml")
# The tables themselves render with the Secret, so a refusal below is the
# missing Secret's and not a typo in the table.
render "${slack[@]}" --set alertDestination.existingSecret=t >/dev/null || fail "a slack route with existingSecret does not render"
render "${github[@]}" --set alertDestination.existingSecret=t >/dev/null || fail "a github default with existingSecret does not render"
render "${slack[@]}" --set alertDestination.slack.enabled=true --set alertDestination.existingSecret=t >/dev/null || fail "slack.enabled with routes and existingSecret does not render"
render "${all[@]}" --set alertDestination.existingSecret= >/dev/null 2>&1 && fail "slack and github routes rendered without existingSecret"
render "${slack[@]}" >/dev/null 2>&1 && fail "a slack route rendered without existingSecret"
render "${github[@]}" >/dev/null 2>&1 && fail "a github default rendered without existingSecret"
render "${slack[@]}" --set alertDestination.slack.enabled=true >/dev/null 2>&1 && fail "slack.enabled rendered without existingSecret"
printf 'routes: [\n' >"$tmp/bad-routes.yaml"
render --set-file "alertDestination.routes=$tmp/bad-routes.yaml" >/dev/null 2>&1 && fail "a routes table that is not YAML rendered"
for v in ALERTDEST_SLACK_TOKEN_FILE ALERTDEST_GITHUB_TOKEN_FILE; do
  render --set alertDestination.existingSecret=t --set-json "alertDestination.env={\"$v\":\"/x\"}" >/dev/null 2>&1 && fail "$v was overridden through env"
done
render --set vector.quickwitAlerts=true >/dev/null 2>&1 && fail "vector.quickwitAlerts rendered without quickwit.enabled"
render --set vector.quickwitAlerts=true --set streams.enabled=false >/dev/null 2>&1 && fail "vector.quickwitAlerts rendered without quickwit.enabled (no streams)"
render "${all[@]}" --set-json 'vector.env={"QUICKWIT_URL":"http://x"}' >/dev/null 2>&1 && fail "QUICKWIT_URL was overridden through vector.env"
render --set-json 'vector.env={"QUICKWIT_URL":"http://x"}' >/dev/null 2>&1 && fail "QUICKWIT_URL was set through vector.env without quickwit"

echo "chart render checks passed"
