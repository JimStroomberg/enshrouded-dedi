# Enshrouded Dedicated Server Stack

One-command Docker Compose stack to run an Enshrouded dedicated server with:
- Wine-based server container (amd64).
- Minimal Go admin UI (login-protected) to restart/update, trigger backups, restore, upload saves, and download logs.
- Backup sidecar with scheduled + manual backups to MinIO (S3-compatible) and retention (14 daily / 8 weekly / 12 monthly by default).
- MinIO for bundled S3 storage (versioning on, retention ready).

## Quickstart
1) `cp .env.example .env` and set at least `SERVER_NAME`, `UI_ADMIN_USERNAME`, `UI_ADMIN_PASSWORD`, `MINIO_ROOT_PASSWORD`, `UI_SESSION_SECRET`.  
2) Run `docker compose up -d`.  
3) Visit `http://localhost:8080` for status; log in with the admin creds to manage the server.

## Stack
- `enshrouded`: SteamCMD auto-update on start (`app_update 2278520 validate`), runs `enshrouded_server.exe` via Wine. Ports are pre-mapped (UDP/TCP 15636, 15637). Data volume `enshrouded_data` holds install, saves, logs.
- `backup`: Go HTTP API on `:7000` (internal). Creates scheduled backups (default every 24h), manual backups, restore (stops container, restores, restarts), validates archives to avoid path traversal, retention pruning (14/8/12). Uses Docker socket to restart/update the game container.
- `ui`: Go web UI on `:8080`. Public status page + admin login. Actions: restart/update, backup now, restore backup, upload+restore save archive, download logs, list backups.
- `minio`: S3-compatible storage; console bound to `127.0.0.1:9001` by default. `minio-init` bootstraps bucket + versioning + retention rule.

## Ports
- Game: `15636/udp` + `15636/tcp`
- Query: `15637/udp` + `15637/tcp`
- UI: `8080` (HTTP)
- MinIO console: `127.0.0.1:9001` (optional; not exposed publicly by default)

## Key environment variables
Copy `.env.example` and adjust:
- Server: `SERVER_NAME`, `SERVER_PASSWORD` (optional), `MAX_PLAYERS`, `GAME_PORT`, `QUERY_PORT`, `SAVE_DIR`, `TZ`, `UPDATE_ON_START` (true/false).
- Steam download: default is anonymous. If you see `Failed to install app '2278520' (No subscription)` or Steam Guard prompts, use the UI “Steam Login” form (admin only) to save your Steam credentials (and Guard code) to the shared volume, then restart the server from the UI. You can also set `STEAM_USERNAME`/`STEAM_PASSWORD`/`STEAM_GUARD_CODE` in `.env` if you prefer.
- UI: `UI_ADMIN_USERNAME`, `UI_ADMIN_PASSWORD`, `UI_SESSION_SECRET` (long random), `STACK_NAME`.
- Backup: `BACKUP_INTERVAL_HOURS` (default 24), `BACKUP_RETENTION_DAILIES`/`WEEKLIES`/`MONTHLIES`, `BACKUP_SAVE_DIR`, `BACKUP_BIND_ADDR`, `ENSHROUDED_CONTAINER_NAME` (default `enshrouded`), S3 settings (`BACKUP_S3_*`).
- MinIO: `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `MINIO_BUCKET` (default `enshrouded-backups`), `MINIO_RETENTION_DAYS` (for bucket ILM), `MINIO_REGION`.

## Admin UI usage
- Public status at `http://localhost:8080`.
- Log in with `UI_ADMIN_USERNAME` / `UI_ADMIN_PASSWORD`. Sessions expire after 24h by default (`UI_SESSION_HOURS`).
- Status shows current server state plus live player count (via A2S on the query port).
- Admin actions:
  - Restart or “trigger update” (restart → SteamCMD runs on start).
  - Backup now.
  - Restore a selected backup.
  - Upload a save archive (tar.gz) → restore.
  - Download latest logs.

## Backups & retention
- Scheduled backup every `BACKUP_INTERVAL_HOURS` (24 by default) plus manual trigger.
- Stored in MinIO bucket `enshrouded-backups` (configurable) with versioning on.
- Retention: keep last 14 daily, 8 weekly, 12 monthly backups (configurable). Extra backups are pruned after each new backup.
- Restore flow stops the game container, restores files, then restarts.

## Data persistence
- `enshrouded_data`: game install, configs, savegames, logs.
- `minio_data`: MinIO data.
- To migrate to a new host: stop the stack, copy volumes (or MinIO bucket), start on the new host with the same `.env`.

## Platform support
- AMD64 only (`linux/amd64`). Build and run on an x86_64 host (or via Docker Desktop’s amd64 emulation if you just need to build on an ARM Mac). ARM images and box64/qemu shims have been removed due to instability.

## Running multiple stacks on one host
- Change `GAME_PORT`/`QUERY_PORT` (and host port mappings) per stack.
- Use a unique compose project name (`COMPOSE_PROJECT_NAME`) to avoid volume name collisions.

## Troubleshooting
- SteamCMD download issues: retry `docker compose up -d --force-recreate enshrouded` (ensures `app_update 2278520 validate` runs).
- Wine/arm64 failures: confirm box64/qemu availability; see ARM64 notes above.
- Permissions on mounted host dirs: ensure the host path is writable by the container user (steam, UID/GID default).
- Backups not showing: check `backup` logs and MinIO bucket; verify S3 creds match `.env`.
- Logs: use the UI “Download Logs” or `docker compose logs -f enshrouded backup ui`.

## CI/CD and publishing
- GitHub Actions (`.github/workflows/ci.yml`): validates compose, runs Go fmt + tests, and on release tags posts to a Docker Hub webhook (`DOCKER_HUB_HOOK_URL` secret) to trigger multi-arch builds (`powermountain/enshrouded-dedi-server`, `powermountain/enshrouded-dedi-ui`, `powermountain/enshrouded-dedi-backup`).
- Compose-first setup: build locally with `docker compose build` or rely on the published images on tag.

## Spec reference
See `docs/specification.md` for the full goals, non-goals, and acceptance criteria.
