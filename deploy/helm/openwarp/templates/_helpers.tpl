{{- define "openwarp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openwarp.fullname" -}}
{{- default (printf "%s-%s" .Release.Name (include "openwarp.name" .)) .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openwarp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openwarp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "openwarp.labels" -}}
{{ include "openwarp.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "openwarp.eso.fullname" -}}
{{- printf "%s-eso" (include "openwarp.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /* The name label differs from the server's so the API Service selector
       cannot match bridge pods and route API traffic to them. */ -}}
{{- define "openwarp.eso.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openwarp.name" . }}-eso
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: eso
{{- end -}}

{{- define "openwarp.eso.labels" -}}
{{ include "openwarp.eso.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
