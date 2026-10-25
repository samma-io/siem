# samma-siem chart

The Helm chart of the Kubernetes SIEM: ingester, Vector, detection-engine and
alert-destination talking over NATS JetStream.

```
ingester-<source> ─► samma.raw.<lane> ─► vector ─► samma.logs.<lane> ─► detection-engine-<lane>
   (SIEM_RAW)                              (SIEM_LOGS)
─► samma.alerts.<lane> ─► alert-destination ─► Postgres siem_alerts
     (SIEM_ALERTS)
```

It installs:

- NATS with JetStream on a file store (the official `nats` chart, `nats.enabled`)
- the streams `SIEM_RAW`, `SIEM_LOGS`, `SIEM_ALERTS` and `INGESTER_SLICES`, and
  their durable consumers, created by a hook Job
- the four workloads (see "Workloads")
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
created. With the default values the configs are identical, so nothing changes.

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

## Streams and consumers

The ConfigMap `<release>-streams` holds one JSON config per stream
(`stream.<NAME>.json`) and per consumer (`consumer.<STREAM>.<name>.json`). The
post-install/post-upgrade Job `<release>-streams` runs
`nats stream add|edit --config` and `nats consumer add|edit --config` over them.
It creates what is missing and edits what exists to match, so running it again
changes nothing. It runs nats-box, pinned by digest, as a non-root user with a
read-only root filesystem, no capabilities and the RuntimeDefault seccomp profile.

| Stream | Retention | `maxAge` | `maxBytes` | `duplicateWindow` |
|---|---|---|---|---|
| `SIEM_RAW` | limits, discard old | 24h | 100MiB | 2h |
| `SIEM_LOGS` | limits, discard old | 7d | 400MiB | 2m |
| `SIEM_ALERTS` | limits, discard old | 30d | 200MiB | 2m |
| `INGESTER_SLICES` | work queue | 24h | 10MiB | 2h |

All streams are file storage with one replica. These are the numbers running on
v2. **The byte caps must fit the JetStream PVC.** They add up to 710 MiB against
the 1Gi default of `nats.config.jetstream.fileStore.pvc.size`. Raise the caps and
the PVC together, never the caps alone. A work-queue stream's retention cannot be
changed after it is created.

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

## Workloads

Each workload is a Deployment with no Ingress and at most a ClusterIP Service.
Every pod runs as uid 65532 (`workloads.runAsUser`), non-root, with a read-only
root filesystem, all capabilities dropped, the RuntimeDefault seccomp profile, no
service account token, requests and limits, and `kubernetes.io/arch: amd64` (the
images are linux/amd64 only). The env, args, probes and ports are those of the
deployment running on v2 (`samma-io/deploy` `siem/`).

| Deployment | One per | Reads | Writes | Notes |
|---|---|---|---|---|
| `<release>-ingester-<source>` | entry of `ingester.sources` | `INGESTER_SLICES` (`ingester-<source>`) | `samma.raw.<lane>`, `ingester_checkpoint` | `daemon`, `INGESTER_TRANSPORT=nats`, `Recreate`, at most one replica |
| `<release>-vector` | release, if a lane has raw records | `SIEM_RAW` (`vector-<lane>`) | `samma.logs.<lane>` | `--config /etc/vector/vector-k8s.yaml`, the config baked into the image |
| `<release>-detection-engine-<lane>` | entry of `lanes` | `SIEM_LOGS` (`detection-engine-<lane>`) | `samma.alerts.<lane>` | `ENGINE_TRANSPORT=nats`, rules baked in at `/rules`, ClusterIP Service on `:9090` |
| `<release>-alert-destination` | release | `SIEM_ALERTS` (`alert-destination`) | `siem_alerts`, `alert_ledger` | `ALERTDEST_TRANSPORT=nats`, routes from ConfigMap `<release>-alert-routes` |

All of them use the chart's NATS URL: the in-release Service with
`nats.enabled`, else `externalNats.url`. Until the streams Job has created their
consumers on a first install, the workloads exit at start and are restarted.

**Images** are `ghcr.io/samma-io/<repo>` at a commit tag, set per component
(`<component>.tag`, or `.digest`, which wins). `latest` is refused. The defaults
are the tags running on v2:

| Component | Tag | Note |
|---|---|---|
| `ingester` | `89ed408` | NATS transport (ingester#5) |
| `vector` | `f2f2dea` | `config/vector-k8s.yaml`, the Workspace lane |
| `detectionEngine` | `d5d7439` | NATS transport; knows the SaaS lanes only |
| `alertDestination` | `779befa` | NATS transport, Postgres ledger and destination |

**Lanes that need a newer image.** The `k8s` and `scanner` lanes and their rules
are in detection-engine `main` from `0c5b5ce` on, and `d5d7439` refuses
`ENGINE_LOG_SOURCE=k8s`. Set `detectionEngine.tag` to an image built from there
before adding them. The baked Vector config reads only `vector-workspace`, so a
raw lane other than `workspace` needs a Vector image whose config reads it.

**Ingester sources.** A source publishes to `samma.raw.<lane>` (`workspace` for
`google-workspace`), so its lane must be in `lanes` with raw records; the chart
refuses to render otherwise. Only `google-workspace` works on Kubernetes so far:
Slack, 1Password and Cloudflare still read their token from SSM. The Workspace
ingester ships at `replicas: 0`. To go live:

1. Create the Secret named in `ingester.perSource.google-workspace.existingSecret`
   (default `ingester-google`, key `key.json`): a service-account key that may
   impersonate the delegated service account (`samma-io/ingester` README,
   "Credential setup"). It is mounted at `/var/run/secrets/ingester`.
2. Set `ingester.perSource.google-workspace.env.INGESTER_GWS_SUBJECT` and
   `INGESTER_GCP_TARGET_SERVICE_ACCOUNT`, and `replicas: 1`. The chart refuses
   `replicas: 1` without them, and more than one replica.

**Routes.** The default table sends everything to the `postgres` destination,
table `siem_alerts`, with `require_slack: false`. `alertDestination.routes`
replaces it with a whole table. The NATS transport of alert-destination
`779befa` builds only the `postgres` destination and refuses a table that names
`slack` or `github`, so `alertDestination.slack.enabled` stays `false` until the
image supports them. `alertDestination.existingSecret` names the Secret with the
Slack and GitHub tokens, mounted at `/var/run/secrets/alert-destination`; tokens
never go in values.

**Extra env.** `vector.env`, `detectionEngine.env`, `alertDestination.env` and
`ingester.perSource.<source>.env` take `NAME: value` settings from the service's
README. A name the chart sets (the transport, NATS, Postgres, routes) is refused,
and an empty value is left out.

## Values

| Key | Default | What |
|---|---|---|
| `lanes` | `[workspace]` | Deployed lanes, see "Lanes" |
| `ingester.sources` | `[google-workspace]` | Ingester sources with a slice consumer |
| `nats.enabled` | `true` | Install the `nats` chart (2.15.0) with JetStream |
| `nats.config.jetstream.fileStore.pvc.size` | `1Gi` | JetStream PVC; must hold the stream caps |
| `nats.config.jetstream.fileStore.pvc.storageClassName` | empty | StorageClass of the PVC |
| `nats.natsBox.enabled` | `false` | The upstream chart's always-on nats-box Deployment |
| `nats.*` | | Passed to the [nats chart](https://github.com/nats-io/k8s/tree/main/helm/charts/nats) |
| `externalNats.url` | empty | NATS URL when `nats.enabled` is false (required then) |
| `streams.enabled` | `true` | Render the streams ConfigMap and Job |
| `streams.{raw,logs,alerts,ingesterSlices}.maxAge` | see table | Whole number with `s`, `m`, `h` or `d` |
| `streams.{raw,logs,alerts,ingesterSlices}.maxBytes` | see table | Whole number with `B`, `KiB`, `MiB`, `GiB` or `TiB` |
| `streams.{raw,logs,alerts,ingesterSlices}.duplicateWindow` | see table | Duration as above |
| `consumers.maxDeliver` | `5` | Deliveries before a message is given up |
| `consumers.ackWait.*` | see table | Per consumer kind |
| `natsBox.image`, `.tag`, `.digest` | `natsio/nats-box` `0.18.1` + digest | Image of the streams Job; a digest wins over the tag |
| `natsBox.runAsUser` | `65532` | uid of the streams Job |
| `s3.endpoint` | empty | S3 endpoint; empty with `minio.enabled` means the bundled MinIO |
| `s3.bucket` | `samma-siem-archive` | Archive bucket (`s3://<bucket>/<lane>/date=YYYY-MM-DD/...`) |
| `s3.region` | `us-east-1` | Region |
| `s3.existingSecret` | empty | Secret with the S3 keys; empty with `minio.enabled` means the MinIO root Secret |
| `s3.accessKeyIdKey`, `s3.secretAccessKeyKey` | `accessKeyId`, `secretAccessKey` | Key names in `s3.existingSecret` |
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
| `<component>.enabled` | `true` | `ingester`, `vector`, `detectionEngine`, `alertDestination` |
| `<component>.image`, `.tag`, `.digest`, `.pullPolicy` | see "Workloads" | A digest wins over the tag; `latest` is refused |
| `<component>.resources` | as on v2 | Requests and limits |
| `vector.replicas`, `detectionEngine.replicas`, `alertDestination.replicas` | `1` | Replicas |
| `vector.configPath` | `/etc/vector/vector-k8s.yaml` | Config file in the image |
| `detectionEngine.workers` | `2` | `ENGINE_WORKERS` |
| `alertDestination.messageTimeout` | `60s` | `ALERTDEST_DAEMON_MESSAGE_TIMEOUT`; must be below `consumers.ackWait.alertDestination` |
| `alertDestination.routes` | empty | A whole routing table; empty is the postgres-only table |
| `alertDestination.slack.enabled` | `false` | `require_slack`; needs `routes` and an image with Slack in its NATS transport |
| `alertDestination.existingSecret` | empty | Secret with the Slack and GitHub tokens |
| `ingester.replicas`, `.scheduleInterval`, `.reconcileInterval` | `0`, `10m`, `1h` | Defaults for every source |
| `ingester.perSource.<source>.replicas` | `0` for `google-workspace` | 0 or 1 |
| `ingester.perSource.<source>.existingSecret`, `.secretOptional` | `ingester-google`, `true` | Credential Secret of the source |
| `ingester.perSource.<source>.env` | Workspace subject and service account, empty | Extra `INGESTER_*` settings |
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
  alert-destination `alert_ledger` and `siem_alerts`; both create their tables at
  start. The DSN is mounted from `postgres.existingSecret` as a file
  (`*_POSTGRES_DSN_FILE`), never put in env. The chart creates neither the
  Secret nor the database: create the role, database and Secret as in
  `samma-io/deploy` `siem/README.md` ("First install").

## Checking a change

```bash
helm dependency build   # after the two `helm repo add` above chart/samma-siem
helm lint --strict chart/samma-siem
helm lint --strict chart/samma-siem -f chart/samma-siem/ci/all-lanes-values.yaml
helm template ci chart/samma-siem --namespace samma
hack/check-chart.sh            # streams, consumers and workloads, default and all lanes
```

CI (`.github/workflows/chart.yml`) runs the same steps with Helm 3 and Helm 4.
