# Enshrouded Dedicated Server Stack

An AMD64 Docker Compose stack for Enshrouded with a Wine/SteamCMD game server, a lightweight admin UI, transactional backups, bundled MinIO storage, and a narrow Docker controller.

The stack is intentionally single-host and database-free. It prioritizes preserving an existing world, reproducible deployments, and recoverable operations.

## Quickstart

1. Copy the example configuration: `cp .env.example .env`.
2. Replace every `change-me` value. Keep `ALLOW_INSECURE_DEFAULTS=false`.
3. Generate independent random values for the session, CSRF, internal API, Docker-controller, and MinIO secrets. `UI_SESSION_ENCRYPTION_KEY` must be exactly 32 characters.
4. Start the stack: `docker compose up -d`.
5. Open `http://localhost:8080`, sign in, and set the Friend access password in Server Settings.

The services reject known default credentials at startup. The admin UI is HTTP by default; restrict it with a firewall or place it behind an HTTPS reverse proxy before exposing it outside a trusted network. Set `UI_SECURE_COOKIES=true` when the browser reaches it over HTTPS.

## Services

- `enshrouded`: AMD64 Wine server. SteamCMD updates on startup and runs from the persistent data volume so the container root filesystem remains read-only.
- `backup`: authenticated internal API for jobs, transactional snapshot/restore, retention, readiness, diagnostics, audit events, metrics, and notifications.
- `ui`: public server status plus a login-protected operator interface. State-changing forms use CSRF protection.
- `controller`: exposes only inspect/start/stop/restart for the configured game container; the UI and backup services never receive the raw Docker socket.
- `minio` and `minio-init`: bundled S3-compatible storage with bucket versioning and lifecycle configuration.

## Ports

- Game: `GAME_HOST_PORT` → `GAME_PORT`, UDP and TCP; default `15636`.
- Query/A2S: `QUERY_HOST_PORT` → `QUERY_PORT`, UDP and TCP; default `15637`.
- Admin UI: `UI_HOST_BIND:UI_HOST_PORT`; default `0.0.0.0:8080`.
- MinIO console: `MINIO_CONSOLE_HOST_BIND:MINIO_CONSOLE_HOST_PORT`; default `127.0.0.1:9001`.

Only forward the game and query ports for players. The backup API, controller, and MinIO API stay on the internal Compose network.

## Admin UI

After login, the UI provides:

- restart and Steam update jobs;
- consistent backup creation, download, upload, preview, and transactional restore;
- exact restore-file and game-build compatibility previews;
- server settings and access-group password changes without echoing current passwords into HTML;
- recent queued/running/succeeded/failed operations, latest backup metadata, and next scheduled backup;
- redacted diagnostics and server log downloads.

Long operations run through a serialized background queue. The audit trail is stored at `BACKUP_AUDIT_PATH` in the persistent game volume.

## Backups and recovery

Backups briefly stop the game only while save/config files are copied to staging. Compression and S3 upload happen after the game restarts. New archives contain:

- the complete save directory;
- `enshrouded_server.json` and launch configuration when present;
- game build and archive schema metadata;
- per-file size and SHA-256 checksums.

Restore downloads, extracts, and validates the complete archive before stopping the game. It atomically swaps the save, keeps the previous files as a rollback, waits for an A2S-backed healthy state, and automatically rolls back if startup fails. Legacy `.tar.gz`, `.tgz`, and `.zip` save archives remain supported.

Default retention is 14 daily, 8 weekly, and 12 monthly backups. Unrecognized S3 objects are never deleted by retention. Run the isolated recovery proof with `./scripts/restore-drill.sh`; it uses disposable Docker/MinIO volumes and never touches the live world.

Bundled MinIO protects against bad restores and operator mistakes on the same host. For host/storage loss, configure `BACKUP_S3_*` for an off-host S3-compatible provider or replicate the MinIO bucket. See [operations.md](docs/operations.md).

## Operations and optional controls

- `BACKUP_RESTART_REQUIRE_EMPTY=true` defers restart, update, and config jobs while A2S reports players online.
- `BACKUP_MAINTENANCE_WINDOW=HH:MM-HH:MM` restricts update jobs to that window in `TZ`; overnight windows are supported.
- `BACKUP_NOTIFICATION_WEBHOOK_URL` receives JSON job completion/failure events.
- `BACKUP_PLAYER_NOTIFICATIONS=true` also emits online/offline transitions.
- `/metrics` on the internal backup API exposes Prometheus text metrics and requires the internal bearer token.
- Host binds, ports, Compose project name, and controlled game-container name are configurable for multiple instances.

## Data and migration

- `enshrouded_data`: game install, Steam/Wine state, savegames, config, audit log, and staged uploads.
- `minio_data`: bundled object storage.

For migration, take and verify a fresh backup, stop the stack, copy both volumes or the game volume plus off-host bucket, copy the `.env` securely, and start the same immutable image versions on the new host.

## Platform support

The game stack is AMD64 only (`linux/amd64`). ARM64 game-server support and host emulation are intentionally out of scope. Docker Desktop can build under emulation, but the final game/Wine smoke test belongs on a real x86_64 host.

## Multiple instances

Use a unique `COMPOSE_PROJECT_NAME`, `ENSHROUDED_CONTAINER_NAME`, host game/query ports, UI port, and MinIO console port for each instance. Keep internal `GAME_PORT` and `QUERY_PORT` consistent with the game config and `BACKUP_A2S_ADDR`.

## CI/CD

GitHub Actions validates formatting, race-enabled tests, a 30% aggregate coverage floor, vet, ShellCheck, Compose, Python healthcheck syntax, `govulncheck`, and the disposable restore drill. It then builds all four AMD64 project images.

`main` publishes `main-<commit>` and `latest`; semantic tags publish `<version>` and `latest`. Production should always use the recorded immutable tag. Dependabot covers Go modules, Actions, and each Dockerfile.

## More documentation

- [Operations, deployment, rollback, and restore drills](docs/operations.md)
- [Architecture and acceptance criteria](docs/specification.md)
- [Modernization roadmap and completion record](ROADMAP.md)
