{{- define "fqdn-network-policy.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fqdn-network-policy.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "fqdn-network-policy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "fqdn-network-policy.selectorLabels" -}}
app.kubernetes.io/name: fqdn-network-policy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "fqdn-network-policy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "fqdn-network-policy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
