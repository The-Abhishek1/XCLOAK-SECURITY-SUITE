{{/*
Base name for the release.
*/}}
{{- define "xcloak.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "xcloak.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "xcloak.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "xcloak.labels" -}}
helm.sh/chart: {{ include "xcloak.chart" . }}
{{ include "xcloak.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "xcloak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xcloak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Per-component names — keep "backend"/"frontend" as the component label so Services/Deployments are unambiguous. */}}
{{- define "xcloak.backend.fullname" -}}
{{ include "xcloak.fullname" . }}-backend
{{- end -}}

{{- define "xcloak.frontend.fullname" -}}
{{ include "xcloak.fullname" . }}-frontend
{{- end -}}

{{- define "xcloak.backend.labels" -}}
{{ include "xcloak.labels" . }}
app.kubernetes.io/component: backend
{{- end -}}

{{- define "xcloak.backend.selectorLabels" -}}
{{ include "xcloak.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end -}}

{{- define "xcloak.frontend.labels" -}}
{{ include "xcloak.labels" . }}
app.kubernetes.io/component: frontend
{{- end -}}

{{- define "xcloak.frontend.selectorLabels" -}}
{{ include "xcloak.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end -}}

{{/*
Bitnami subcharts name themselves "<release>-<dependency-name>" by default
(no nameOverride/fullnameOverride set on them here) — these helpers just
spell that out so backend env vars and this chart's own templates agree on
one source of truth instead of duplicating the hostname string everywhere.
*/}}
{{- define "xcloak.postgresql.host" -}}
{{ .Release.Name }}-postgresql
{{- end -}}

{{- define "xcloak.redis.host" -}}
{{ .Release.Name }}-redis-master
{{- end -}}

{{/*
Global ingress host is the single source of truth for FRONTEND_URL /
BACKEND_PUBLIC_URL / CORS_ALLOWED_ORIGINS, so these three can't drift apart
and silently break OIDC SSO redirect callbacks (services/oidc_service.go
reads FRONTEND_URL and BACKEND_PUBLIC_URL independently — if either one is
hand-set differently from the Ingress host, SSO breaks in a way that only
shows up on the redirect step, not on direct API calls).
*/}}
{{- define "xcloak.scheme" -}}
{{- if .Values.ingress.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}

{{- define "xcloak.frontendURL" -}}
{{- if .Values.global.frontendURL -}}
{{ .Values.global.frontendURL }}
{{- else -}}
{{ include "xcloak.scheme" . }}://{{ .Values.global.ingress.host }}
{{- end -}}
{{- end -}}

{{- define "xcloak.backendPublicURL" -}}
{{- if .Values.global.backendPublicURL -}}
{{ .Values.global.backendPublicURL }}
{{- else -}}
{{ include "xcloak.scheme" . }}://{{ .Values.global.ingress.host }}
{{- end -}}
{{- end -}}

{{/*
Preserve an auto-generated secret value across `helm upgrade` instead of
re-randomizing it on every release — without this, JWT_SECRET (and any
other randAlphaNum-generated default) would rotate on every upgrade and log
out every active session. Looks up the existing Secret's key first; only
generates a fresh random value the very first time (no existing Secret, or
key not yet set).
*/}}
{{- define "xcloak.preservedSecretValue" -}}
{{- $secretName := index . 0 -}}
{{- $key := index . 1 -}}
{{- $ctx := index . 2 -}}
{{- $existing := lookup "v1" "Secret" $ctx.Release.Namespace $secretName -}}
{{- if and $existing (index $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
