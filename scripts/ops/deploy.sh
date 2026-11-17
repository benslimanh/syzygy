#!/usr/bin/env bash
# Explicit opt-in only. Verify an immutable image, apply atomically, then smoke
# test through a localhost port-forward. A failed smoke test rolls back to the
# last deployed Helm revision (or uninstalls a failed first installation).
set -euo pipefail
cd "$(dirname "$0")/../.."
image=${1:?Usage: deploy.sh repository@sha256:digest [values-file]}
values=${2:-ops/helm/local-values.yaml}
namespace=${NAMESPACE:-syzygy}
release=${HELM_RELEASE:-syzygy}
timeout=${ROLLOUT_TIMEOUT:-5m}
port=${SMOKE_PORT:-18081}
[[ "$image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || { echo 'A GHCR image digest is required' >&2; exit 1; }
[[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#namespace} -le 63 ]]
[[ "$release" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#release} -le 53 ]]
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]]
[[ "$timeout" =~ ^[1-9][0-9]*[smh]$ ]]
: "${COSIGN_CERTIFICATE_IDENTITY:?Set the exact trusted release workflow identity}"
for tool in helm kubectl cosign curl python3; do command -v "$tool" >/dev/null; done
[[ -f "$values" ]]
cosign verify --certificate-identity "$COSIGN_CERTIFICATE_IDENTITY" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image" >/dev/null
# Require the namespace to exist. Do not turn permission/API errors into a
# "not installed" result or implicitly create infrastructure.
kubectl get namespace "$namespace" >/dev/null
history=$(helm list --namespace "$namespace" --all --filter "^$release$" --output json)
present=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' <<< "$history")
previous=0
if [[ "$present" -gt 0 ]]; then
    revisions=$(helm history "$release" --namespace "$namespace" --output json)
    previous=$(python3 -c 'import json,sys; r=[int(x["revision"]) for x in json.load(sys.stdin) if x["status"]=="deployed"]; print(max(r, default=0))' <<< "$revisions")
    [[ "$previous" -gt 0 ]] || { echo 'Existing release has no deployed revision; recover it manually.' >&2; exit 1; }
fi
repository=${image%@*}
digest=${image#*@}
# --atomic rolls back readiness failures. Never run helm dependency update or
# accept arbitrary chart paths/commands from deployment inputs.
helm upgrade --install "$release" helm/syzygy --namespace "$namespace" \
    --values "$values" --set-string "fullnameOverride=$release" \
    --set-string "image.repository=$repository" --set-string "image.digest=$digest" \
    --atomic --wait --timeout "$timeout" --history-max 10
forward_pid=''
cleanup() {
    if [[ -n "$forward_pid" ]]; then
        kill "$forward_pid" 2>/dev/null || true
        wait "$forward_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
# The smoke test requires the chart's HTTP service port (80 by default).
# Do not expose the port-forward on public interfaces.
kubectl --namespace "$namespace" port-forward "service/$release" "$port:80" \
    --address=127.0.0.1 >/dev/null 2>&1 &
forward_pid=$!
healthy=false
for _ in {1..15}; do
    if ! kill -0 "$forward_pid" 2>/dev/null; then break; fi
    if [[ $(curl --fail --silent --max-time 2 "http://127.0.0.1:$port/healthz" || true) == ok ]] &&
       [[ $(curl --fail --silent --max-time 2 "http://127.0.0.1:$port/ok.txt" || true) == ok ]]; then
        healthy=true; break
    fi
    sleep 1
done
if [[ "$healthy" == true ]]; then echo 'Verified deployment and smoke checks passed'; exit 0; fi
cleanup
forward_pid=''
echo 'Post-deploy smoke failed; reverting deployment.' >&2
if [[ "$previous" -gt 0 ]]; then
    helm rollback "$release" "$previous" --namespace "$namespace" --wait --timeout "$timeout"
else
    helm uninstall "$release" --namespace "$namespace" --wait --timeout "$timeout"
fi
exit 1
