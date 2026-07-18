#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repo_dir/tests/restore-drill.compose.yml"
project_name="enshrouded-restore-drill-${RANDOM}"
backup_container="${project_name}-backup-1"
auth_header="Authorization: Bearer restore-drill-internal-token-32chars"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker buildx build \
  --platform linux/amd64 \
  --file "$repo_dir/docker/backup/Dockerfile" \
  --tag enshrouded-backup:restore-drill \
  --load \
  "$repo_dir" >/dev/null

docker buildx build \
  --platform linux/amd64 \
  --file "$repo_dir/docker/controller/Dockerfile" \
  --tag enshrouded-controller:restore-drill \
  --load \
  "$repo_dir" >/dev/null

docker compose -p "$project_name" -f "$compose_file" up -d --wait

wait_for_job() {
  local job_id="$1"
  local response state
  for _ in $(seq 1 180); do
    response=$(docker exec "$backup_container" curl -fsS -H "$auth_header" "http://localhost:7000/jobs/${job_id}")
    state=$(printf '%s' "$response" | jq -er '.state')
    case "$state" in
      succeeded)
        printf '%s' "$response"
        return 0
        ;;
      failed)
        printf '%s\n' "$response" >&2
        return 1
        ;;
    esac
    sleep 1
  done
  printf 'job %s timed out\n' "$job_id" >&2
  return 1
}

create_response=$(docker exec "$backup_container" curl -fsS -H "$auth_header" -X POST http://localhost:7000/backup)
create_job=$(printf '%s' "$create_response" | jq -er '.id')
create_result=$(wait_for_job "$create_job")
backup_name=$(printf '%s' "$create_result" | jq -er '.result.name')

docker exec "$backup_container" curl -fsS -H "$auth_header" "http://localhost:7000/backups/contents?name=${backup_name}" \
  | jq -e '.items | index("enshrouded-backup-manifest.json") != null' >/dev/null

download_path=$(mktemp "${TMPDIR:-/tmp}/enshrouded-restore-drill.XXXXXX.tar.gz")
docker exec "$backup_container" curl -fsS -H "$auth_header" "http://localhost:7000/backups/download?name=${backup_name}" >"$download_path"
gzip -t "$download_path"
unlink "$download_path"

docker exec enshrouded-restore-drill-game sh -c "printf 'mutated-world\\n' >/data/savegame/3ad85aea"
docker exec enshrouded-restore-drill-game sh -c "printf '{\"name\":\"mutated\",\"saveDirectory\":\"/data/savegame\"}\\n' >/data/server/enshrouded_server.json"

restore_response=$(docker exec "$backup_container" curl -fsS \
  -H "$auth_header" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${backup_name}\",\"backup_before\":false}" \
  http://localhost:7000/restore)
restore_job=$(printf '%s' "$restore_response" | jq -er '.id')
wait_for_job "$restore_job" >/dev/null

world=$(docker exec enshrouded-restore-drill-game cat /data/savegame/3ad85aea)
config_name=$(docker exec enshrouded-restore-drill-game cat /data/server/enshrouded_server.json | jq -er '.name')
test "$world" = "original-world"
test "$config_name" = "restore-drill"

rollback_count=$(docker exec "$backup_container" sh -c 'find /data -maxdepth 1 -type d -name ".enshrouded-restore-rollback-*" | wc -l')
test "$rollback_count" -ge 1

printf 'restore_drill=passed backup=%s rollback_dirs=%s\n' "$backup_name" "$rollback_count"
