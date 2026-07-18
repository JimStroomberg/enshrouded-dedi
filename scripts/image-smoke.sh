#!/usr/bin/env bash
set -euo pipefail

kind="${1:?usage: image-smoke.sh server|ui image}"
image="${2:?usage: image-smoke.sh server|ui image}"
suffix="${GITHUB_RUN_ID:-local}-$$"
container_name="enshrouded-${kind}-smoke-${suffix}"
volume_name="enshrouded-server-smoke-${suffix}"

cleanup() {
  docker stop "$container_name" >/dev/null 2>&1 || true
  if [ "$kind" = "server" ]; then
    docker volume rm "$volume_name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for() {
  local command="$1"
  local attempt=0
  while [ "$attempt" -lt 30 ]; do
    attempt=$((attempt + 1))
    if docker exec "$container_name" sh -c "$command"; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container_name"
  return 1
}

case "$kind" in
  ui)
    docker run -d --rm \
      --name "$container_name" \
      --platform linux/amd64 \
      --read-only \
      --tmpfs /tmp:size=32m,mode=1777 \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      -e UI_ADMIN_USERNAME=admin \
      -e UI_ADMIN_PASSWORD=smoke-password \
      -e UI_SESSION_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      -e UI_SESSION_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef \
      -e UI_CSRF_KEY=abcdef0123456789abcdef0123456789 \
      -e UI_INTERNAL_TOKEN=internal-token-0123456789abcdef0 \
      -e BACKUP_API_URL=http://127.0.0.1:1 \
      "$image" >/dev/null
    wait_for 'curl -fsS http://127.0.0.1:8080/health >/dev/null'
    ;;
  server)
    docker volume create "$volume_name" >/dev/null
    docker run -d --rm \
      --name "$container_name" \
      --platform linux/amd64 \
      --read-only \
      --tmpfs /tmp:size=64m,mode=1777 \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      -e UPDATE_ON_START=false \
      -e SERVER_NAME=smoke \
      -e MAX_PLAYERS=4 \
      -e GAME_PORT=15636 \
      -e QUERY_PORT=15637 \
      -v "$volume_name:/data" \
      "$image" >/dev/null
    wait_for 'test -x /data/steamcmd/steamcmd.sh && test -f /data/steamcmd_win/steamcmd.exe && test -s /data/server/server_config.txt'
    ;;
  *)
    printf 'unsupported smoke kind: %s\n' "$kind" >&2
    exit 2
    ;;
esac

printf 'image_smoke=passed kind=%s image=%s read_only=true\n' "$kind" "$image"
