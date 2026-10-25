{{- /*
samma-siem.fullname is the prefix of every object this chart (not its
subcharts) creates.
*/ -}}
{{- define "samma-siem.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "samma-siem.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: siem
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- /*
samma-siem.image renders an image reference from a values block with image,
tag and digest: image@sha256:... when a digest is set, else image:tag.

  {{ include "samma-siem.image" .Values.natsBox }}
*/ -}}
{{- define "samma-siem.image" -}}
{{- if .digest -}}
{{- $digest := .digest -}}
{{- if not (hasPrefix "sha256:" $digest) }}{{ $digest = printf "sha256:%s" $digest }}{{ end -}}
{{ .image }}@{{ $digest }}
{{- else -}}
{{ .image }}:{{ required "an image needs a tag or a digest" .tag }}
{{- end -}}
{{- end -}}

{{- /*
samma-siem.subchartFullname mirrors the fullname helper of the nats and
minio charts, which is how their Services and Secrets are named.

  {{ include "samma-siem.subchartFullname" (dict "name" "nats" "values" .Values.nats "release" .Release) }}
*/ -}}
{{- define "samma-siem.subchartFullname" -}}
{{- if .values.fullnameOverride -}}
{{- .values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .name .values.nameOverride -}}
{{- if contains $name .release.Name -}}
{{- .release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
samma-siem.natsUrl: the subchart's Service with nats.enabled, else
externalNats.url.
*/ -}}
{{- define "samma-siem.natsUrl" -}}
{{- if .Values.nats.enabled -}}
{{- $port := 4222 -}}
{{- with .Values.nats.config }}{{ with .nats }}{{ with .port }}{{ $port = . }}{{ end }}{{ end }}{{ end -}}
nats://{{ include "samma-siem.subchartFullname" (dict "name" "nats" "values" .Values.nats "release" .Release) }}.{{ .Release.Namespace }}.svc:{{ $port }}
{{- else -}}
{{- required "externalNats.url is required when nats.enabled is false" .Values.externalNats.url -}}
{{- end -}}
{{- end -}}

{{- /*
samma-siem.minioFullname names the MinIO Service and root Secret.
*/ -}}
{{- define "samma-siem.minioFullname" -}}
{{- include "samma-siem.subchartFullname" (dict "name" "minio" "values" .Values.minio "release" .Release) -}}
{{- end -}}

{{- /*
samma-siem.s3Endpoint: s3.endpoint, else the bundled MinIO.
*/ -}}
{{- define "samma-siem.s3Endpoint" -}}
{{- if .Values.s3.endpoint -}}
{{- .Values.s3.endpoint -}}
{{- else if .Values.minio.enabled -}}
http://{{ include "samma-siem.minioFullname" . }}.{{ .Release.Namespace }}.svc:{{ .Values.minio.service.port | default 9000 }}
{{- else -}}
{{- fail "s3.endpoint is required when minio.enabled is false" -}}
{{- end -}}
{{- end -}}

{{- /*
samma-siem.s3Credentials returns a dict (as JSON) with secret, idKey and
secretKey: s3.existingSecret with its key names, else the MinIO root Secret.
*/ -}}
{{- define "samma-siem.s3Credentials" -}}
{{- if .Values.s3.existingSecret -}}
{{- dict "secret" .Values.s3.existingSecret "idKey" .Values.s3.accessKeyIdKey "secretKey" .Values.s3.secretAccessKeyKey | toJson -}}
{{- else if .Values.minio.enabled -}}
{{- dict "secret" (.Values.minio.existingSecret | default (include "samma-siem.minioFullname" .)) "idKey" "rootUser" "secretKey" "rootPassword" | toJson -}}
{{- else -}}
{{- fail "s3.existingSecret is required when minio.enabled is false" -}}
{{- end -}}
{{- end -}}

{{- /*
samma-siem.nanos converts a duration like 300s, 20m, 24h or 7d to
nanoseconds, the unit of JetStream's JSON configs.
*/ -}}
{{- define "samma-siem.nanos" -}}
{{- $s := toString . -}}
{{- $units := dict "s" 1 "m" 60 "h" 3600 "d" 86400 -}}
{{- $n := regexFind "^[0-9]+" $s -}}
{{- $u := trimPrefix $n $s -}}
{{- if or (not $n) (not (hasKey $units $u)) -}}
{{- fail (printf "duration %q: use a whole number with s, m, h or d, like 7d" $s) -}}
{{- end -}}
{{- mul (atoi $n) (get $units $u) 1000000000 -}}
{{- end -}}

{{- /*
samma-siem.bytes converts a size like 400MiB to bytes.
*/ -}}
{{- define "samma-siem.bytes" -}}
{{- $s := toString . -}}
{{- $units := dict "B" 1 "KiB" 1024 "MiB" 1048576 "GiB" 1073741824 "TiB" 1099511627776 -}}
{{- $n := regexFind "^[0-9]+" $s -}}
{{- $u := trimPrefix $n $s -}}
{{- if or (not $n) (not (hasKey $units $u)) -}}
{{- fail (printf "size %q: use a whole number with B, KiB, MiB, GiB or TiB, like 400MiB" $s) -}}
{{- end -}}
{{- mul (atoi $n) (get $units $u) -}}
{{- end -}}

{{- /*
samma-siem.lanes returns the lanes as a JSON list of {name, raw}. A lane is
a lowercase name (lane-names.md); a plain string has raw: true.
*/ -}}
{{- define "samma-siem.lanes" -}}
{{- $out := list -}}
{{- if not .Values.lanes }}{{ fail "lanes must list at least one deployed lane" }}{{ end -}}
{{- range .Values.lanes -}}
{{- $lane := dict "name" "" "raw" true -}}
{{- if kindIs "map" . -}}
{{- $_ := set $lane "name" (toString (.name | default "")) -}}
{{- if hasKey . "raw" }}{{ $_ := set $lane "raw" .raw }}{{ end -}}
{{- else -}}
{{- $_ := set $lane "name" (toString .) -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]+(-[a-z0-9]+)*$" $lane.name) -}}
{{- fail (printf "lane %q: a lane is a lowercase name like workspace, never a wildcard" $lane.name) -}}
{{- end -}}
{{- $out = append $out $lane -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{- /*
samma-siem.podSecurity / samma-siem.containerSecurity: the hardened
contexts every hook Job here runs with.
*/ -}}
{{- define "samma-siem.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .runAsUser }}
runAsGroup: {{ .runAsUser }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "samma-siem.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{- /*
samma-siem.workloadImage: samma-siem.image for a workload, which must be
pinned: a tag that is a commit (never latest) or a digest.

  {{ include "samma-siem.workloadImage" (dict "name" "vector" "values" .Values.vector) }}
*/ -}}
{{- define "samma-siem.workloadImage" -}}
{{- $v := .values -}}
{{- if not $v.image }}{{ fail (printf "%s.image is required" .name) }}{{ end -}}
{{- if and (not $v.digest) (or (not $v.tag) (eq (toString $v.tag) "latest")) -}}
{{- fail (printf "%s.tag must be an image tag like a commit sha, never latest (or set %s.digest)" .name .name) -}}
{{- end -}}
{{- include "samma-siem.image" (dict "image" $v.image "tag" (toString ($v.tag | default "")) "digest" $v.digest) -}}
{{- end -}}

{{- /*
samma-siem.workloadName: <fullname>-<suffix>, at most 63 characters, so it
is also a valid Service name.
*/ -}}
{{- define "samma-siem.workloadName" -}}
{{- printf "%s-%s" (include "samma-siem.fullname" .root) .suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
samma-siem.selectorLabels: the immutable selector of a workload, from
component (detection-engine) and an optional lane or source.

  {{ include "samma-siem.selectorLabels" (dict "root" $ "component" "ingester" "instance" "google-workspace") }}
*/ -}}
{{- define "samma-siem.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- with .instance }}
siem.samma.io/instance: {{ . }}
{{- end }}
{{- end -}}

{{- /*
samma-siem.workloadPodSpec: the pod-level fields every workload shares:
scheduling, pull Secrets, no service account token and the hardened pod
security context.
*/ -}}
{{- define "samma-siem.workloadPodSpec" -}}
{{- $w := .Values.workloads -}}
automountServiceAccountToken: false
{{- with $w.imagePullSecrets }}
imagePullSecrets:
  {{- range . }}
  - name: {{ if kindIs "map" . }}{{ .name }}{{ else }}{{ . }}{{ end }}
  {{- end }}
{{- end }}
{{- with $w.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $w.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $w.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
securityContext:
  {{- include "samma-siem.podSecurity" $w | nindent 2 }}
{{- end -}}

{{- /*
samma-siem.extraEnv renders a name: value map as env entries, sorted, and
leaves out empty values. A name the chart sets itself is refused.

  {{ include "samma-siem.extraEnv" (dict "env" .Values.vector.env "reserved" (list "NATS_URL") "what" "vector.env") }}
*/ -}}
{{- define "samma-siem.extraEnv" -}}
{{- $env := .env | default dict -}}
{{- range $name := keys $env | sortAlpha }}
{{- if has $name $.reserved }}{{ fail (printf "%s.%s is set by the chart" $.what $name) }}{{ end -}}
{{- $value := get $env $name -}}
{{- if not (eq (toString $value) "") }}
- name: {{ $name }}
  value: {{ toString $value | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- /*
samma-siem.postgresSecret: postgres.existingSecret, required by the
workloads that keep state in Postgres.
*/ -}}
{{- define "samma-siem.postgresSecret" -}}
{{- required "postgres.existingSecret (a Secret with the DSN of the siem database) is required by the ingester and alert-destination" .Values.postgres.existingSecret -}}
{{- end -}}

{{- /*
samma-siem.seconds: a duration like 60s or 2m in whole seconds.
*/ -}}
{{- define "samma-siem.seconds" -}}
{{- div (include "samma-siem.nanos" .) 1000000000 -}}
{{- end -}}
