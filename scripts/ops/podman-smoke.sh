#!/usr/bin/env bash
set -euo pipefail
image=${1:-localhost/syzygy:dev}
name="syzygy-smoke-$$"
trap 'podman rm -f "$name" >/dev/null 2>&1 || true' EXIT
podman run --detach --name "$name" --read-only --cap-drop=all \
    --security-opt=no-new-privileges --pids-limit=128 --memory=256m --cpus=1 \
    --publish 127.0.0.1::8080 "$image"
port=$(podman port "$name" 8080/tcp | awk -F: '{print $NF}')
for _ in {1..30}; do
    if body=$(curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$port/healthz" 2>/dev/null); then
        [[ "$body" == ok ]]
        [[ $(curl -fsS --max-time 2 "http://127.0.0.1:$port/ok.txt") == ok ]]
        echo 'Podman HTTP smoke test passed'; exit 0
    fi
    sleep 1
done
podman logs "$name" >&2
exit 1
