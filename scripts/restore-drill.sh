#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repo_dir/tests/restore-drill.compose.yml"
project_name="enshrouded-restore-drill-${RANDOM}"
backup_container="${project_name}-backup-1"

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

docker compose -p "$project_name" -f "$compose_file" up -d --wait

create_response=$(docker exec "$backup_container" curl -fsS -X POST http://localhost:7000/backup)
backup_name=$(printf '%s' "$create_response" | jq -er '.name')

docker exec "$backup_container" curl -fsS "http://localhost:7000/backups/contents?name=${backup_name}" \
  | jq -e '.items | index("enshrouded-backup-manifest.json") != null' >/dev/null

download_path=$(mktemp "${TMPDIR:-/tmp}/enshrouded-restore-drill.XXXXXX.tar.gz")
docker exec "$backup_container" curl -fsS "http://localhost:7000/backups/download?name=${backup_name}" >"$download_path"
gzip -t "$download_path"
unlink "$download_path"

docker exec enshrouded-restore-drill-game sh -c "printf 'mutated-world\\n' >/data/savegame/3ad85aea"
docker exec enshrouded-restore-drill-game sh -c "printf '{\"name\":\"mutated\",\"saveDirectory\":\"/data/savegame\"}\\n' >/data/server/enshrouded_server.json"

docker exec "$backup_container" curl -fsS \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${backup_name}\",\"backup_before\":false}" \
  http://localhost:7000/restore >/dev/null

world=$(docker exec enshrouded-restore-drill-game cat /data/savegame/3ad85aea)
config_name=$(docker exec enshrouded-restore-drill-game cat /data/server/enshrouded_server.json | jq -er '.name')
test "$world" = "original-world"
test "$config_name" = "restore-drill"

rollback_count=$(docker exec "$backup_container" sh -c 'find /data -maxdepth 1 -type d -name ".enshrouded-restore-rollback-*" | wc -l')
test "$rollback_count" -ge 1

printf 'restore_drill=passed backup=%s rollback_dirs=%s\n' "$backup_name" "$rollback_count"
