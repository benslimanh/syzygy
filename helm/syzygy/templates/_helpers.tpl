{{/*
Expand the name of the chart.
*/}}
{{- define "syzygy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "syzygy.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride }}
{{- else -}}{{ printf "%s-%s" .Release.Name (include "syzygy.name" .) | trimSuffix "-" }}
{{- end }}{{- end }}

{{- define "syzygy.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "syzygy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "syzygy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "syzygy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
