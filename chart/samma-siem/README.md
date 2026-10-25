# samma-siem chart

The Helm chart of the Kubernetes SIEM: ingester, Vector, detection-engine,
alert-destination and siem-storage talking over NATS JetStream, with Quickwit
and Grafana for search and dashboards.

```
ingester-<source> ─► samma.raw.<lane> ─► vector ─► samma.logs.<lane> ─► detection-engine-<lane>
   (SIEM_RAW)                              (SIEM_LOGS)
─► samma.alerts.<lane> ─► alert-destination ─► Postgres siem_alerts
     (SIEM_ALERTS)

samma.logs.<lane> ─► siem-storage ─► Postgres siem_events, S3 archive
samma.alerts.>    ─► siem-storage ─► S3 archive
grafana ─► quickwit (search; metastore in Postgres, index on S3)
        ─► Postgres siem_alerts (read-only login)
```

It installs:

- NATS with JetStream on a file store (the official `nats` chart, `nats.enabled`)
- the streams `SIEM_RAW`, `SIEM_LOGS`, `SIEM_ALERTS` and `INGESTER_SLICES`, and
  their durable consumers, created by a hook Job
- the pipeline workloads and siem-storage (see "Workloads")
- Quickwit and Grafana, off by default (see "Storage, search and dashboards")
- MinIO and an archive bucket (the official `minio` chart, `minio.enabled`), or
  any S3-compatible store you point it at
- a reference to the existing TimescaleDB through a Secret (no Postgres is deployed)

The message contract is in
`samma-io/aws-siem`: `docs/contracts/detection-alert-v1.md` ("NATS transport")
and `docs/contracts/nats-transport.md`.

Nothing is exposed outside the cluster. Every Service is ClusterIP and the chart
renders no Ingress.

## Install

The dependencies are pinned in `Chart.yaml` and `Chart.lock`. Their archives
(`charts/*.tgz`) are not committed, so fetch them first:

```bash
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm repo add minio https://charts.min.io/
helm dependency build chart/samma-siem
# The Postgres Secret (postgres.existingSecret, default siem-postgres) must
# exist first; see "Postgres" below.
helm upgrade --install samma-siem chart/samma-siem -n samma-siem --create-namespace
kubectl -n samma-siem logs job/samma-siem-streams
```

To use a NATS you already run (the JetStream NATS in `samma`, for example):

```bash
helm upgrade --install samma-siem chart/samma-siem -n samma \
  --set nats.enabled=false --set externalNats.url=nats://nats.samma.svc:4222
```

The streams Job then edits the streams that `samma-io/deploy` `siem/00-streams-job.yaml`
created. With the default values the configs are identical except `SIEM_RAW`'s
duplicate window, which that Job sets to 2h and this chart to 8h (see "Streams and
consumers"); the Job edits it to 8h.

## Lanes

A lane is on NATS when its subjects are captured by the streams. **List only the
lanes that are deployed**, never a wildcard. The legacy pipeline publishes
`samma.logs.k8s` and `samma.logs.k8s.audit` on core NATS at about 11 MiB/min, and
a stream on `samma.logs.>` would fill its byte cap within the hour.

Each entry in `lanes` gives:

| What | Name |
|---|---|
| subject in `SIEM_RAW` | `samma.raw.<lane>` |
| subject in `SIEM_LOGS` | `samma.logs.<lane>` |
| consumer on `SIEM_RAW` (Vector) | `vector-<lane>` |
| consumer on `SIEM_LOGS` (detection-engine) | `detection-engine-<lane>` |

```yaml
lanes:
  - workspace
  - {name: k8s, raw: false}   # no raw records: SIEM_LOGS and the engine consumer only
```

`raw: false` is for lanes without vendor records from the ingester (`k8s` and
`scanner` in the contract). Lane names are lowercase, as in `lane-names.md`.

Independent of lanes:

| Stream | Subjects | Consumer |
|---|---|---|
| `SIEM_ALERTS` | `samma.alerts.>` | `alert-destination` |
| `INGESTER_SLICES` (work queue) | `samma.ingester.slices.>` | `ingester-<source>` on `samma.ingester.slices.<source>`, for each of `ingester.sources` |

Adding a lane is a values change and an upgrade. The Job adds the subject to the
stream and creates the consumers. Size the stream's byte cap for the new lane's
volume.

**The k8s lane's byte cap.** `streams.logs.laneMaxBytes.<lane>` is added to
`SIEM_LOGS`'s `max_bytes` for each lane in `lanes` that has one. The default is
`k8s: 2GiB`, about three hours of the ~11 MiB/min audit volume. JetStream caps a
stream, not a subject, so this is room in the one `SIEM_LOGS` stream: once it is
full the oldest records go, whatever their lane, and at full audit volume
`SIEM_LOGS` (Workspace included) keeps about three hours instead of `maxAge`.
siem-storage's Postgres and S3 copies are the long-term ones. **The JetStream PVC
must grow with the cap**: with `k8s` the caps add up to 710 MiB + 2GiB, so set
`nats.config.jetstream.fileStore.pvc.size` to `4Gi`. With `nats.enabled` the chart
refuses caps that add up to more than `fileStore.maxSize`, or else the PVC size.
On an installed release the NATS StatefulSet's claim template cannot change:
expand the PVC itself (`kubectl patch pvc`, a StorageClass with
`allowVolumeExpansion`), delete the StatefulSet with `--cascade=orphan`, then
upgrade.

**Raw lanes Vector does not read yet.** The `slack`, `onepassword` and
`cloudflare` sources need their lanes with raw records, which also gives each a
`vector-<lane>` consumer on `SIEM_RAW`. The baked Vector config (`vector-k8s.yaml`)
filters only `workspace`, so those lanes' records are not normalised: they stay
unfiltered in `SIEM_RAW` until its `maxAge`, and nothing reaches their
`samma.logs.<lane>` or detection-engine until a Vector image reads them.

## Streams and consumers

The ConfigMap `<release>-streams` holds one JSON config per stream
(`stream.<NAME>.json`) and per consumer (`consumer.<STREAM>.<name>.json`). The
post-install/post-upgrade Job `<release>-streams` runs
`nats stream add|edit --config` and `nats consumer add|edit --config` over them.
It creates what is missing and edits what exists to match, so running it again
changes nothing. It runs nats-box, pinned by digest, as a non-root user with a
read-only root filesystem, no capabilities and the RuntimeDefault seccomp profile.

**Under ArgoCD.** ArgoCD maps Helm's post-install/post-upgrade hooks to
PostSync, which would start the workloads before their consumers exist. The
streams and bucket Jobs therefore also carry `argocd.argoproj.io/hook: Sync`, and
the sync runs in waves: wave 0 is NATS, MinIO and every ConfigMap, Secret and
Service; wave 1 the two Jobs; wave 2 this chart's Deployments. ArgoCD waits for
each wave to be healthy, and for the Jobs to complete, before the next. The
subcharts stay in wave 0 because the minio chart cannot annotate its Secret,
ServiceAccount and ConfigMap. Helm ignores the ArgoCD annotations, so a plain
`helm install` behaves as before.

| Stream | Retention | `maxAge` | `maxBytes` | `duplicateWindow` |
|---|---|---|---|---|
| `SIEM_RAW` | limits, discard old | 24h | 100MiB | 8h |
| `SIEM_LOGS` | limits, discard old | 7d | 400MiB, plus `laneMaxBytes` (`k8s`: 2GiB) | 2m |
| `SIEM_ALERTS` | limits, discard old | 30d | 200MiB | 2m |
| `INGESTER_SLICES` | work queue | 24h | 10MiB | 2h |

All streams are file storage with one replica. These are the numbers running on
v2, except `SIEM_RAW`'s duplicate window. **The byte caps must fit the JetStream
PVC.** They add up to 710 MiB against the 1Gi default of
`nats.config.jetstream.fileStore.pvc.size` (2758 MiB with the `k8s` lane, see
"Lanes"). Raise the caps and the PVC together, never the caps alone; the chart
refuses a sum above it. A work-queue stream's retention cannot be changed after it
is created.

**`SIEM_RAW`'s duplicate window is 8h.** The ingester republishes every record a
reconcile pass re-reads with the same `Nats-Msg-Id`, and JetStream drops the copy
only inside the window. A Workspace pass re-reads `[previous pass's end - lookback,
now]`; the longest lookback is 6h (`token`, `groups`, `groups_enterprise`,
`calendar`, `user_accounts`; `drive` 3h), so a record is re-read up to 6h plus one
reconcile interval (1h) after its event. With the old 2h window those late
re-reads were stored again under a new stream sequence and alerted twice
(samma-io/ingester#8). 8h is 6h + 1h + 1h of margin. The chart refuses
`streams.raw.duplicateWindow` below 6h plus the Workspace `reconcileInterval`, and
any stream's window above its `maxAge`. JetStream keeps the id of every record in
the window in memory, so the cost grows with the window. The longer window also
means a reconcile pass never replaces a record Vector lost (samma-io/vector
README, "What the ingester's reconcile pass recovers").

The consumers are durable pull consumers, explicit ack, deliver all,
`maxDeliver` 5. When a message exhausts `maxDeliver`, it stays in the stream
until its age or byte limit, and JetStream emits a max-deliveries advisory. That
is the DLQ of this transport.

| Consumer | `consumers.ackWait.*` | Default | Rule |
|---|---|---|---|
| `vector-<lane>` | `vector` | 60s | Vector acks once the record is in `SIEM_LOGS` |
| `detection-engine-<lane>` | `detectionEngine` | 300s | equal to `ENGINE_VISIBILITY_TIMEOUT` |
| `alert-destination` | `alertDestination` | 120s | above `ALERTDEST_DAEMON_MESSAGE_TIMEOUT` (60s) |
| `ingester-<source>` | `ingester` | 20m | above the daemon's 15m message timeout |
| `storage-logs` | `storage` | 60s | a batch of `storage.batchSize` committed to `siem_events` well within it |
| `storage-s3-logs` | `storageS3Logs` | 6m | above `storage.s3.flushInterval` (5m): a message is acked only once its object is written. The chart refuses an AckWait at or below the interval |
| `storage-s3-alerts` | `storageS3Alerts` | 2m | one object per alert; the service's own value |
| `vector-alerts-quickwit` | `vectorAlertsQuickwit` | 120s | only with `vector.quickwitAlerts`; above the alerts sink's 5s batch plus 30s request retried for 30s |
| `vector-quickwit-k8s`, `vector-quickwit-scanner` | `vectorQuickwitLogs` | 60s | only with `quickwit.enabled` and the lane; Vector acks on hand-off, the sinks are best-effort |

The storage consumers exist only with `storage.enabled`, and only for the
configured `storage.backends`: `storage-logs` (on `SIEM_LOGS`) for `postgres`,
`storage-s3-logs` (on `SIEM_LOGS`) and `storage-s3-alerts` (on `SIEM_ALERTS`)
for `s3`. The two on `SIEM_LOGS` filter on every lane's `samma.logs.<lane>`
(`filter_subjects`). The S3 ones hold messages unacked for up to a flush
interval, so they have `max_ack_pending` 10000, as the service creates them;
every other consumer has 1000.

`vector-alerts-quickwit` (on `SIEM_ALERTS`, filter `samma.alerts.>`) exists only
with `quickwit.enabled`, `vector.quickwitAlerts` and a rendered Vector: Vector's
alerts overlay reads it and does not start without it. Likewise
`vector-quickwit-k8s` and `vector-quickwit-scanner` (on `SIEM_LOGS`, filters
`samma.logs.k8s`, `samma.logs.scanner`) exist only with `quickwit.enabled`,
`vector.enabled` and that lane in `lanes`.

## Workloads

Each workload is a Deployment with no Ingress and at most a ClusterIP Service.
Every pod runs as uid 65532 (`workloads.runAsUser`; Grafana as its image's
472, `grafana.runAsUser`), non-root, with a read-only
root filesystem, all capabilities dropped, the RuntimeDefault seccomp profile, no
service account token, requests and limits, and `kubernetes.io/arch: amd64` (the
images are linux/amd64 only). The env, args, probes and ports are those of the
deployment running on v2 (`samma-io/deploy` `siem/`).

| Deployment | One per | Reads | Writes | Notes |
|---|---|---|---|---|
| `<release>-ingester-<source>` | entry of `ingester.sources` | `INGESTER_SLICES` (`ingester-<source>`) | `samma.raw.<lane>`, `ingester_checkpoint` | `daemon`, `INGESTER_TRANSPORT=nats`, `Recreate`, at most one replica |
| `<release>-vector` | release, if a lane has raw records | `SIEM_RAW` (`vector-<lane>`); with `vector.quickwitAlerts` also `SIEM_ALERTS` (`vector-alerts-quickwit`); with `quickwit.enabled` and the k8s or scanner lane also `SIEM_LOGS` (`vector-quickwit-<lane>`) | `samma.logs.<lane>`; with `quickwit.enabled` also Quickwit | `--config /etc/vector/vector-k8s.yaml`, the config baked into the image, plus the Quickwit overlays (see "Quickwit") |
| `<release>-detection-engine-<lane>` | entry of `lanes` | `SIEM_LOGS` (`detection-engine-<lane>`) | `samma.alerts.<lane>` | `ENGINE_TRANSPORT=nats`, rules baked in at `/rules`, ClusterIP Service on `:9090` |
| `<release>-alert-destination` | release | `SIEM_ALERTS` (`alert-destination`) | `siem_alerts`, `alert_ledger`; Slack and GitHub when routed | `ALERTDEST_TRANSPORT=nats`, routes from ConfigMap `<release>-alert-routes`, tokens from `alertDestination.existingSecret` |
| `<release>-siem-storage` | release, `storage.enabled` | `SIEM_LOGS` (`storage-logs`, `storage-s3-logs`), `SIEM_ALERTS` (`storage-s3-alerts`) | `siem_events`, the S3 archive | `STORAGE_BACKENDS=postgres,s3`, binds to the Job's consumers |
| `<release>-quickwit` | release, `quickwit.enabled` | ingest API | index on S3, metastore in Postgres | `QW_MODE=k8s`, `Recreate`, one replica, ClusterIP Service on `:7280` |
| `<release>-grafana` | release, `grafana.enabled` | Quickwit, `siem_alerts` | nothing | k8s provisioning, runs as uid 472, ClusterIP Service on `:3000` |

All of them use the chart's NATS URL: the in-release Service with
`nats.enabled`, else `externalNats.url`. Until the streams Job has created their
consumers on a first install, the workloads exit at start and are restarted.

**Images** are `ghcr.io/samma-io/<repo>` at a commit tag, set per component
(`<component>.tag`, or `.digest`, which wins). `latest` is refused. The defaults
are the tags running on v2:

| Component | Tag | Note |
|---|---|---|
| `ingester` | `89ed408` | NATS transport (ingester#5); no token files (Slack, 1Password and Cloudflare need `b4c844c` or later) |
| `vector` | `f2f2dea` | `config/vector-k8s.yaml`, the Workspace lane; no Quickwit overlays (needs `34806c1` or later with `quickwit.enabled`, `5fbdb00` or later with it and the k8s or scanner lane) |
| `detectionEngine` | `d5d7439` | NATS transport; knows the SaaS lanes only |
| `alertDestination` | `779befa` | NATS transport, Postgres ledger and destination; no Slack or GitHub (needs `e9987eb` or later to route to them) |
| `storage` | `sha-6c3f143` | siem-storage `main` with the Postgres and S3 backends, built by its CI |
| `quickwit` | none, required | pushed by hand, see "Images built by hand" |
| `grafana` | none, required | pushed by hand, see "Images built by hand" |

**Lanes that need a newer image.** The `k8s` and `scanner` lanes and their rules
are in detection-engine `main` from `0c5b5ce` on, and `d5d7439` refuses
`ENGINE_LOG_SOURCE=k8s`. Set `detectionEngine.tag` to an image built from there
before adding them. The baked Vector config reads only `vector-workspace`, so a
raw lane other than `workspace` needs a Vector image whose config reads it.
With `quickwit.enabled`, Vector gets the Quickwit overlays, which are in
samma-io/vector `main` from `34806c1` on (the k8s and scanner ones from `5fbdb00`
on); `f2f2dea` does not have the files and would not start. Routing alerts to Slack or GitHub needs alert-destination
`main` from `e9987eb` on; `779befa` refuses such a table.

**Ingester sources.** A source publishes to `samma.raw.<lane>` (`workspace` for
`google-workspace`), so its lane must be in `lanes` with raw records; the chart
refuses to render otherwise. Every source ships at `replicas: 0`. To take the
Workspace ingester live:

1. Create the Secret named in `ingester.perSource.google-workspace.existingSecret`
   (default `ingester-google`, key `key.json`): a service-account key that may
   impersonate the delegated service account (`samma-io/ingester` README,
   "Credential setup"). It is mounted at `/var/run/secrets/ingester`.
2. Set `ingester.perSource.google-workspace.env.INGESTER_GWS_SUBJECT` and
   `INGESTER_GCP_TARGET_SERVICE_ACCOUNT`, and `replicas: 1`. The chart refuses
   `replicas: 1` without them, and more than one replica.

`slack`, `onepassword` and `cloudflare` read a token from a file
(`samma-io/ingester` README, "Token secrets"), which needs an ingester image from
`b4c844c` on. Add the source to `ingester.sources` and its lane (`slack`,
`onepassword`, `cloudflare`, with raw records) to `lanes`, then:

1. Create the Secret named in `ingester.perSource.<source>.existingSecret`
   (defaults `ingester-slack`, `ingester-onepassword`, `ingester-cloudflare`) with
   the token under the key `token`:
   `kubectl -n <namespace> create secret generic ingester-slack --from-file=token=./slack-token`.
   With `existingSecret` set the chart sets `INGESTER_SECRETS=file` and
   `INGESTER_<SOURCE>_TOKEN_FILE=/var/run/secrets/ingester/token`.
2. For Cloudflare, set `ingester.perSource.cloudflare.env.INGESTER_CLOUDFLARE_ACCOUNT_ID`
   and `INGESTER_CLOUDFLARE_ZONE_IDS` (1 to 10, comma-separated); for 1Password,
   `INGESTER_ONEPASSWORD_BASE_URL` if the account is not in the US region.
3. Set `replicas: 1`. The chart refuses it without `existingSecret`, and for
   Cloudflare without the account and zone ids.

`INGESTER_SECRETS` and the three `*_TOKEN_FILE` names are the chart's; setting
them in `env` is refused. `*_TOKEN_PARAM` is left alone: the ingester refuses it
under file mode at start. Until a Vector image reads those lanes their records
are not normalised (see "Lanes").

**Routes.** The default table sends everything to the `postgres` destination,
table `siem_alerts`, with `require_slack: false`. `alertDestination.routes`
replaces it with a whole table. Slack and GitHub need an alert-destination
image from `e9987eb` on (`779befa` builds only `postgres` and refuses a table
that names `slack` or `github`) and a Secret, `alertDestination.existingSecret`,
with the keys:

| Key | Holds | File (`ALERTDEST_*_TOKEN_FILE`) |
|---|---|---|
| `slack-token` | the Slack bot token | `/var/run/secrets/alert-destination/slack-token` |
| `github-token` | the GitHub fine-grained PAT | `/var/run/secrets/alert-destination/github-token` |

```sh
kubectl -n <namespace> create secret generic siem-alert-destination \
  --from-file=slack-token=./slack-token --from-file=github-token=./github-token
```

The Secret is mounted whole (not by `subPath`), so a rotated token reaches the
file and is re-read after an authentication failure without a restart. With
`existingSecret` set the chart sets both `ALERTDEST_SLACK_TOKEN_FILE` and
`ALERTDEST_GITHUB_TOKEN_FILE`, whatever the table routes to: alert-destination
builds a destination only when a route names it and ignores the other file, so
a key no route uses may be left out of the Secret, while a routed one that is
missing stops the pod at start. The chart refuses `alertDestination.slack.enabled`,
or a `routes` table with a `deliveries` entry `to: slack` or `to: github`,
without `existingSecret`. Tokens never go in values.

**Extra env.** `vector.env`, `detectionEngine.env`, `alertDestination.env` and
`storage.env`, `quickwit.env`, `grafana.env` and
`ingester.perSource.<source>.env` take `NAME: value` settings from the service's
README. A name the chart sets (the transport, NATS, Postgres, routes, token files, `INGESTER_SECRETS`, `QUICKWIT_URL`) is refused,
and an empty value is left out.

## Storage, search and dashboards

**siem-storage** is on by default with both backends. It needs nothing beyond
what the pipeline already has: the DSN from `postgres.existingSecret` (it
writes `siem_events`, created by its migrations at start, and never touches
`siem_alerts`, which is alert-destination's) and the S3 settings from `s3.*`
(the bundled MinIO by default, path-style, bucket `s3.bucket`). The service has
no file setting for the DSN, so it gets `STORAGE_POSTGRES_DSN` from the Secret
with `secretKeyRef`; it never logs it. `storage.backends: [postgres]` or `[s3]`
runs one backend; `elasticsearch` is refused, there is none in this SIEM.

**Quickwit** and **Grafana** are off by default: their images have no tag to
default to, and each needs a Secret that only you can create. Turn them on
together; Grafana's Quickwit datasources point at this release's Quickwit
Service.

### Quickwit

```yaml
quickwit:
  enabled: true
  tag: <short sha of samma-io/quickwit, 10d8377 or later>
  metastore:
    existingSecret: siem-quickwit-metastore   # key uri
```

- **Metastore.** A Secret with `QW_METASTORE_URI`,
  `postgres://<user>:<password>@<host>:5432/<db>`, under `quickwit.metastore.uriKey`
  (`uri`). Give Quickwit a database of its own; it runs its own migrations
  there. The chart creates neither the Secret nor the database.
- **Index data** goes to `quickwit.indexRootUri`, by default
  `s3://<s3.bucket>/quickwit/indexes`, with the S3 endpoint and keys of `s3.*`.
- The image's auto-bootstrap creates the four k8s indexes (`logs-saas`,
  `logs-k8s`, `logs-scanner`, `alerts`) once `/health/readyz` answers.
- One replica, `Recreate`: the node has no peers. `QW_DATA_DIR` (staged
  splits, ingest WAL) is an emptyDir (`quickwit.dataSizeLimit`), `/tmp` another;
  the root filesystem is read-only.
- **Quickwit has no authentication.** Its Service is ClusterIP, and a
  NetworkPolicy (`quickwit.networkPolicy.enabled`, on) admits port 7280 only
  from this release's Grafana and Vector pods. It needs a CNI that enforces
  NetworkPolicy.
- **Vector feeds it.** With `quickwit.enabled` Vector runs with
  `--config /etc/vector/vector-k8s-quickwit.yaml` after its base config and
  `QUICKWIT_URL=http://<release>-samma-siem-quickwit.<namespace>.svc:7280` (no
  `/api/v1`): the filtered Workspace records go to the `logs-saas` index,
  best-effort (retried, buffered, then dropped; NATS is never held up).
  `vector.quickwitAlerts: true` adds `vector-k8s-quickwit-alerts.yaml`: alerts
  from consumer `vector-alerts-quickwit` on `SIEM_ALERTS`, which the streams Job
  creates, into the `alerts` index; that path blocks while Quickwit is down and
  the alerts wait in the stream. Both need a Vector image from `34806c1` on
  (samma-io/vector README, "Quickwit (optional)"). `vector.quickwitAlerts`
  without `quickwit.enabled` is refused.
- **The k8s and scanner lanes.** For each of them in `lanes`, Vector also gets
  `vector-k8s-quickwit-<lane>.yaml` (into `logs-k8s`, `logs-scanner`,
  best-effort), reading consumer `vector-quickwit-<lane>` on `SIEM_LOGS`, which the
  streams Job creates (AckWait `consumers.ackWait.vectorQuickwitLogs`). They need
  a Vector image from `5fbdb00` on. These overlays layer on the base config and
  `vector-k8s-quickwit.yaml` (its Prometheus exporter) and cannot run alone, and
  the base config reads `vector-workspace` on `SIEM_RAW`, without which Vector does
  not start. A base config without the Workspace lane would be a new file in the
  Vector image, so the chart instead **requires the `workspace` lane, with raw
  records, whenever it would load the k8s or scanner overlay**, and refuses
  otherwise; set `vector.enabled: false` for a release without it. Records reach
  `samma.logs.k8s` and `samma.logs.scanner` only once something publishes there
  (the scanner relay and k8s audit collection are not in this chart).

### Grafana

```yaml
grafana:
  enabled: true
  tag: <short sha of samma-io/grafana with provisioning-k8s>
  existingSecret: siem-grafana
```

`GF_PATHS_PROVISIONING=/etc/grafana/provisioning-k8s`, `QUICKWIT_URL` is
`http://<release>-samma-siem-quickwit.<namespace>.svc:7280/api/v1`. Everything
else comes from `grafana.existingSecret`, a Secret of Grafana's own (key names
in `grafana.keys`):

| Key | Env | |
|---|---|---|
| `admin-password` | `GF_SECURITY_ADMIN_PASSWORD` | required |
| `admin-user` | `GF_SECURITY_ADMIN_USER` | optional, `admin` |
| `postgres-host` | `SIEM_POSTGRES_HOST` | required |
| `postgres-port` | `SIEM_POSTGRES_PORT` | optional, `5432` |
| `postgres-database` | `SIEM_POSTGRES_DB` | required, the database alert-destination writes `siem_alerts` into (`siem`) |
| `postgres-user` | `SIEM_POSTGRES_USER` | required, **a read-only login** |
| `postgres-password` | `SIEM_POSTGRES_PASSWORD` | required |
| `postgres-sslmode` | `SIEM_POSTGRES_SSLMODE` | optional, `require` |

The Postgres datasource runs whatever SQL a dashboard editor types, so
read-only is enforced by the database: create the `siem_alerts_reader` role and
its login as in the samma-io/grafana README, "The read-only database user"
(`CONNECT`, `USAGE` on the schema, `SELECT` on `siem_alerts`, and
`default_transaction_read_only`). **Never** point Grafana at
`postgres.existingSecret`: that is the `siem` role, which owns and writes the
tables. The chart refuses `grafana.existingSecret` equal to it.

```bash
kubectl -n samma-siem create secret generic siem-grafana \
  --from-literal=admin-password="$(openssl rand -base64 24)" \
  --from-literal=postgres-host=<timescaledb host> \
  --from-literal=postgres-database=siem \
  --from-literal=postgres-user=grafana_siem \
  --from-literal=postgres-password='<the role password>'
```

Nothing persists: the dashboards and datasources are provisioned from the
image, and the data directory (`GF_PATHS_DATA=/var/lib/grafana-data`, users
and sessions) is an emptyDir, so a restart forgets UI-made users. The plugins
are baked in, and preinstalled-plugin downloads are off. Grafana runs as uid
472, the owner of its files in the image.

### Reaching Grafana and Quickwit

Neither has an Ingress or a hostname; both are ClusterIP. Use
`kubectl port-forward` (release `samma-siem` in namespace `samma-siem`; the
names are `<release>-samma-siem-*` unless the release name contains
`samma-siem`):

```bash
kubectl -n samma-siem port-forward svc/samma-siem-grafana 3000:3000
# http://localhost:3000, user admin, the admin-password of grafana.existingSecret

kubectl -n samma-siem port-forward svc/samma-siem-quickwit 7280:7280
# http://localhost:7280/ui/search, and the REST API under /api/v1
```

`helm status` prints the exact commands. Exposing either beyond that is a
separate decision and not part of this chart.

### Images built by hand

`ghcr.io/samma-io/quickwit` and `ghcr.io/samma-io/grafana` are not built by CI.
They are pushed with `samma-io/aws-siem`'s `hack/build-images.sh`, which runs
each repo's `make image push` for linux/amd64 and tags with the repo's short
git sha:

```bash
# Sibling checkouts of aws-siem, quickwit and grafana, each on the commit to ship:
# quickwit main at 10d8377 or later (QW_MODE=k8s), grafana with provisioning-k8s
# (samma-io/grafana#3).
echo "$GHCR_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
aws-siem/hack/build-images.sh quickwit grafana
# tags: git -C quickwit rev-parse --short HEAD, git -C grafana rev-parse --short HEAD
```

Set `quickwit.tag` and `grafana.tag` to those shas (or `.digest`). The chart
fails the render when either is enabled without one, and refuses `latest`.
If the packages are private, list a pull Secret in `workloads.imagePullSecrets`.

## Values

| Key | Default | What |
|---|---|---|
| `lanes` | `[workspace]` | Deployed lanes, see "Lanes" |
| `ingester.sources` | `[google-workspace]` | Ingester sources with a slice consumer |
| `nats.enabled` | `true` | Install the `nats` chart (2.15.0) with JetStream |
| `nats.config.jetstream.fileStore.pvc.size` | `1Gi` | JetStream PVC; must hold the stream caps (`4Gi` with the `k8s` lane) |
| `nats.config.jetstream.fileStore.pvc.storageClassName` | empty | StorageClass of the PVC |
| `nats.natsBox.enabled` | `false` | The upstream chart's always-on nats-box Deployment |
| `nats.*` | | Passed to the [nats chart](https://github.com/nats-io/k8s/tree/main/helm/charts/nats) |
| `externalNats.url` | empty | NATS URL when `nats.enabled` is false (required then) |
| `streams.enabled` | `true` | Render the streams ConfigMap and Job |
| `streams.{raw,logs,alerts,ingesterSlices}.maxAge` | see table | Whole number with `s`, `m`, `h` or `d` |
| `streams.{raw,logs,alerts,ingesterSlices}.maxBytes` | see table | Whole number with `B`, `KiB`, `MiB`, `GiB` or `TiB` |
| `streams.{raw,logs,alerts,ingesterSlices}.duplicateWindow` | see table | Duration as above; `raw` at least 6h plus the Workspace `reconcileInterval` |
| `streams.logs.laneMaxBytes` | `{k8s: 2GiB}` | Added to `SIEM_LOGS`'s cap per lane in `lanes`; grow the PVC with it |
| `consumers.maxDeliver` | `5` | Deliveries before a message is given up |
| `consumers.ackWait.*` | see table | Per consumer kind |
| `natsBox.image`, `.tag`, `.digest` | `natsio/nats-box` `0.18.1` + digest | Image of the streams Job; a digest wins over the tag |
| `natsBox.runAsUser` | `65532` | uid of the streams Job |
| `s3.endpoint` | empty | S3 endpoint; empty with `minio.enabled` means the bundled MinIO |
| `s3.bucket` | `samma-siem-archive` | Archive bucket (`s3://<bucket>/<lane>/date=YYYY-MM-DD/...`) |
| `s3.region` | `us-east-1` | Region |
| `s3.existingSecret` | empty | Secret with the S3 keys; empty with `minio.enabled` means the MinIO root Secret |
| `s3.accessKeyIdKey`, `s3.secretAccessKeyKey` | `accessKeyId`, `secretAccessKey` | Key names in `s3.existingSecret` |
| `s3.forcePathStyle` | `true` | Path-style addressing (MinIO); siem-storage and Quickwit |
| `minioClient.image`, `.tag`, `.digest` | `cgr.dev/chainguard/minio-client` + digest | Image of the bucket Job |
| `minio.enabled` | `true` | Install the `minio` chart (5.4.0), standalone, one 10Gi PVC |
| `minio.existingSecret` | empty | Secret with `rootUser` and `rootPassword` |
| `minio.*` | | Passed to the [minio chart](https://github.com/minio/minio/tree/master/helm/minio) |
| `postgres.existingSecret` | `siem-postgres` | Secret holding a DSN for the existing TimescaleDB (database `siem`, never `scan_results`); required by the ingester and alert-destination |
| `postgres.dsnKey` | `dsn` | Key of the DSN in that Secret |
| `workloads.runAsUser` | `65532` | uid of every workload |
| `workloads.nodeSelector` | `kubernetes.io/arch: amd64` | Node selector of every workload |
| `workloads.tolerations`, `.affinity`, `.podAnnotations` | empty | Scheduling and pod annotations |
| `workloads.imagePullSecrets` | `[]` | Pull Secrets, by name, for private ghcr.io packages |
| `<component>.enabled` | `true` | `ingester`, `vector`, `detectionEngine`, `alertDestination`, `storage`; `false` for `quickwit`, `grafana` |
| `<component>.image`, `.tag`, `.digest`, `.pullPolicy` | see "Workloads" | A digest wins over the tag; `latest` is refused |
| `<component>.resources` | as on v2 | Requests and limits |
| `vector.replicas`, `detectionEngine.replicas`, `alertDestination.replicas` | `1` | Replicas |
| `vector.configPath` | `/etc/vector/vector-k8s.yaml` | Config file in the image |
| `vector.quickwitAlerts` | `false` | With `quickwit.enabled`: alerts into Quickwit, consumer `vector-alerts-quickwit` |
| `detectionEngine.workers` | `2` | `ENGINE_WORKERS` |
| `alertDestination.messageTimeout` | `60s` | `ALERTDEST_DAEMON_MESSAGE_TIMEOUT`; must be below `consumers.ackWait.alertDestination` |
| `alertDestination.routes` | empty | A whole routing table; empty is the postgres-only table |
| `alertDestination.slack.enabled` | `false` | `require_slack`; needs `routes`, `existingSecret` and an image from `e9987eb` on |
| `alertDestination.existingSecret` | empty | Secret with keys `slack-token`, `github-token`; required when Slack or GitHub is routed |
| `ingester.replicas`, `.scheduleInterval`, `.reconcileInterval` | `0`, `10m`, `1h` | Defaults for every source |
| `ingester.perSource.<source>.replicas` | `0` | 0 or 1 |
| `ingester.perSource.<source>.existingSecret`, `.secretOptional` | `ingester-<google, slack, onepassword, cloudflare>`, `true` | Credential Secret of the source (key `key.json` for Workspace, `token` for the others) |
| `ingester.perSource.<source>.env` | Workspace subject and service account, 1Password base URL, Cloudflare account and zone ids, empty | Extra `INGESTER_*` settings |
| `storage.backends` | `[postgres, s3]` | `STORAGE_BACKENDS`; also which storage consumers exist |
| `storage.batchSize`, `.batchWait` | `100`, `1s` | Postgres batches |
| `storage.eventsRetention` | `30 days` | TimescaleDB retention of `siem_events` |
| `storage.s3.flushInterval`, `.flushBytes` | `5m`, `16777216` | S3 object flush; the interval must stay below `consumers.ackWait.storageS3Logs` |
| `storage.replicas` | `1` | Replicas |
| `quickwit.metastore.existingSecret`, `.uriKey` | empty (required), `uri` | Secret with the `postgres://` metastore URI |
| `quickwit.indexRootUri` | empty: `s3://<s3.bucket>/quickwit/indexes` | `QW_DEFAULT_INDEX_ROOT_URI` |
| `quickwit.networkPolicy.enabled` | `true` | Admit 7280 only from this release's Grafana and Vector |
| `quickwit.dataSizeLimit` | `2Gi` | emptyDir size of `QW_DATA_DIR` |
| `grafana.existingSecret` | empty (required) | Admin password and read-only Postgres login; never `postgres.existingSecret` |
| `grafana.keys.*` | see "Grafana" | Key names in that Secret |
| `grafana.runAsUser` | `472` | uid of the Grafana pod |
| `grafana.replicas` | `1` | Replicas |
| `<component>.env` | `{}` | Extra env, see "Workloads" |

Notes:

- **MinIO image.** MinIO no longer publishes images on quay.io or Docker Hub, and
  the minio chart's defaults no longer pull. The chart therefore uses Chainguard's
  `minio` and `minio-client` images, pinned by digest. To mirror your own, set
  `minio.image` and `minioClient`.
- **MinIO users.** The upstream default creates a `console` / `console123`
  consoleAdmin user. This chart sets `minio.users`, `policies`, `svcaccts` and
  `buckets` to empty. The bucket is created by this chart's own Job.
- **Credentials and GitOps.** With empty `minio.rootUser` / `rootPassword`, the
  minio chart keeps the Secret already in the cluster, or generates one at install.
  `helm template` cannot read the cluster, so it generates new credentials on every
  render. A GitOps tool needs `minio.existingSecret`.
- **The bucket Job** has no shell. mc reads `MC_HOST_s3`, which the kubelet builds
  from the Secret, so the access key and secret must be URL-safe. MinIO's
  generated ones are alphanumeric. The Job runs only with `minio.enabled`. With
  another S3, create the bucket there.
- **Postgres.** The ingester keeps `ingester_checkpoint` there, and
  alert-destination `alert_ledger` and `siem_alerts`, and siem-storage
  `siem_events`; each creates its tables at start. The ingester and
  alert-destination mount the DSN from `postgres.existingSecret` as a file
  (`*_POSTGRES_DSN_FILE`); siem-storage, which has no file setting, reads it
  with `secretKeyRef`. It is never in values. The chart creates neither the
  Secret nor the database: create the role, database and Secret as in
  `samma-io/deploy` `siem/README.md` ("First install").

## Checking a change

```bash
helm dependency build   # after the two `helm repo add` above chart/samma-siem
helm lint --strict chart/samma-siem
helm lint --strict chart/samma-siem -f chart/samma-siem/ci/all-lanes-values.yaml
helm lint --strict chart/samma-siem -f chart/samma-siem/ci/all-enabled-values.yaml
helm template ci chart/samma-siem --namespace samma
hack/check-chart.sh            # streams, consumers, workloads and refusals: default, all lanes, all enabled
```

CI (`.github/workflows/chart.yml`) runs the same steps with Helm 3 and Helm 4.
