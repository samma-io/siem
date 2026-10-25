# samma-siem chart

The Helm chart of the Kubernetes SIEM: ingester, Vector, detection-engine and
alert-destination talking over NATS JetStream. This version installs the
foundation only:

- NATS with JetStream on a file store (the official `nats` chart, `nats.enabled`)
- the streams `SIEM_RAW`, `SIEM_LOGS`, `SIEM_ALERTS` and `INGESTER_SLICES`, and
  their durable consumers, created by a hook Job
- MinIO and an archive bucket (the official `minio` chart, `minio.enabled`), or
  any S3-compatible store you point it at
- a reference to the existing TimescaleDB through a Secret (no Postgres is deployed)

The workloads come in later versions. The message contract is in
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
| `postgres.existingSecret` | empty | Secret holding a DSN for the existing TimescaleDB (database `siem`, never `scan_results`) |
| `postgres.dsnKey` | `dsn` | Key of the DSN in that Secret |

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
- **Postgres.** The values are a contract for the workloads to come. The ingester
  will keep `ingester_checkpoint` there, and alert-destination `alert_ledger` and
  `siem_alerts`. Create the role, database and Secret as in `samma-io/deploy`
  `siem/README.md` ("First install").

## Checking a change

```bash
helm dependency build   # after the two `helm repo add` above chart/samma-siem
helm lint --strict chart/samma-siem
helm template ci chart/samma-siem --namespace samma
hack/check-chart.sh            # the render has the streams and consumers
```

CI (`.github/workflows/chart.yml`) runs the same steps with Helm 3 and Helm 4.
