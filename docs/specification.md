

# Enshrouded Dedicated Server Stack (AMD64) — Specification

## 1. Project summary

Build a public GitHub repository that provides a **one-command Docker Compose stack** for running an **Enshrouded dedicated server** plus a **simple admin web UI** and an **S3-compatible backup store**.

Primary goal: **extremely easy** for users who can run `docker compose up -d`.

Repository: `JimStroomberg/enshrouded-dedi`

Container registry: Docker Hub org `powermountain`; GitHub Actions publishes tested AMD64 images.

## 2. Goals

### 2.1 Core goals

1. **AMD64-only images** (`linux/amd64`) for the stack.
2. **Game server auto-update on startup** using SteamCMD (`app_update 2278520 validate`).
3. **Simple defaults via compose**: env vars provide first-boot defaults; runtime server settings are edited in the UI and persisted to the server config (not overwritten on restart).
4. **Status/admin web UI**:
   - Public status page (limited info).
   - Admin login (single admin user/pass from compose env vars).
   - Admin actions: **restart** server, **trigger update** (and restart), **download logs**, and **backup/restore savegames**.
   - Edit server settings (server name, friend/server password, slots, voice/text chat, voice chat mode, preset, day/night durations, tags) with validation (e.g., unique group passwords).
5. **S3 backup storage** included in the stack (MinIO):
   - Web UI supports **upload savegame from PC → restore on server**, and **download backups**.
   - Default retention policy enabled (basic users are covered).
6. **Pre-mapped ports** in compose (no host networking) so multiple stacks can run on one host.

### 2.2 Target users

- “Basic”: wants a working server locally or with simple port-forwarding.
- “Pro”: wants to run multiple stacks, add a reverse proxy, change retention, etc.

## 3. Non-goals

- TLS / reverse proxy included (explicitly out of scope).
- Full user management / RBAC (single admin only).
- Cluster orchestration (Kubernetes charts etc.)—compose only.

## 4. Constraints and risk notes

### 4.1 Platform scope

The stack is **AMD64-only** (`linux/amd64`). ARM64 and box64/Proton shims have been removed due to instability. Running on ARM would require host-level emulation (e.g., qemu/binfmt) outside this project’s scope.

## 5. Architecture overview

Compose stack services (single `docker-compose.yml`):

1. `enshrouded` (game server)
2. `ui` (web status/admin)
3. `minio` (S3-compatible storage)
4. `backup` (required job/API service used by the UI)
5. `controller` (narrow Docker-socket boundary)
6. `minio-init` (one-shot bucket configuration)

Notes:
- `ui` must not need direct access to MinIO admin APIs; it should use S3 keys and a dedicated bucket.
- All project images are AMD64-only to match the game stack and its tested deployment target.
- Only `controller` receives the Docker socket. It permits inspect/start/stop/restart for one configured container.

## 6. Service specs

### 6.1 Game server container (`enshrouded`)

**Responsibilities**
- Install/Update Enshrouded dedicated server on startup via SteamCMD.
- Run the Windows dedicated server with Wine on AMD64.
- Persist server install and savegames.

**Networking (must match compose)**
Expose and document these ports (both UDP and TCP) in compose:
- `15636:15636/udp`
- `15636:15636/tcp`
- `15637:15637/udp`
- `15637:15637/tcp`

**Volumes**
- `enshrouded_data` (persistent install + config + savegames)
  - Must contain a dedicated `savegame` directory.

**Environment variables (compose-driven)**
- Provide first-boot defaults for non-secret server settings (for example `SERVER_NAME`, `MAX_PLAYERS`, and `SAVE_DIR`). Access-group passwords and later runtime values are stored in `enshrouded_server.json` and edited via the UI, not overwritten by env on restart.
- Networking/env still configure ports and basics: `GAME_PORT` (default 15636), `QUERY_PORT` (default 15637), `SAVE_DIR` (default `/data/savegame`), `TZ`.

**Entrypoint behavior**
1. Ensure required directories exist and have correct ownership.
2. Run SteamCMD update:
   - anonymous install supported
   - `app_update 2278520 validate`
3. Generate a default server config if missing (idempotent) and keep a simple `server_config.txt` for launch flags.
4. Start server using values from the persisted config (name/password/slots), not re-applying env overrides on every restart.

**Health check**
- Require a valid A2S/query response from the configured query port, not only a running process.

**Logging**
- Logs must go to stdout/stderr.
- Optionally write rotating log files under `/data/logs`.

### 6.2 Web UI (`ui`)

**Responsibilities**
- Public status view:
  - stack name (from env)
  - server name
  - server status (Up/Down)
  - optional: player count if feasible (nice-to-have)
- Admin UI:
  - login button → admin session
  - actions:
    - restart server container
    - trigger update (calls server update endpoint in backup service or uses docker socket approach)
    - create backup now
    - list backups
    - restore backup
    - upload local savegame files (zip) → restore
    - download latest logs / server logs bundle
    - edit server settings (name, friend/server password, slots, voice/text chat toggles, voice chat mode, preset, day/night durations, tags) with validation (e.g., group passwords must be unique) and display the live config from `enshrouded_server.json`

**Authentication model**
- Single admin account.
- Credentials set in compose only:
  - `UI_ADMIN_USERNAME`
  - `UI_ADMIN_PASSWORD`
- No user registration.
- Password changes require compose change + restart.

**Implementation constraints**
- Must be lightweight and AMD64-compatible.
- Must not require a database; use signed and encrypted cookies.
- Enforce CSRF protection, login throttling, constant-time credential checks, secure-cookie configuration, and HTTP timeouts.
- Never render current game passwords back into HTML or status JSON.
- UI may call:
  - backup service over internal network
  - MinIO S3 using access key/secret
  - backup service endpoints that read/write the server config to keep the UI in sync with the running server

### 6.3 S3-compatible storage (`minio`)

**Responsibilities**
- Provide S3 bucket for backups and optional uploads.

**Defaults**
- Create bucket `enshrouded-backups` automatically (via MinIO init job or entrypoint).
- Enable **bucket versioning** by default.
- Provide a default **retention policy** configuration (see below).

**Environment variables (compose-driven)**
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`
- `MINIO_BUCKET` (default `enshrouded-backups`)

**Ports**
- Expose MinIO Console only on localhost by default (or documented as optional). Basic users should not need it.

### 6.4 Backup service (`backup`)

Implement a small authenticated HTTP API service that:
- Knows where savegames live (`/data/savegame`)
- Can create a consistent snapshot (tar/zip) with timestamped name
- Uploads to S3 bucket
- Lists available backups
- Restores a backup to the save dir
- Accepts an uploaded zip/tar and restores it
- Runs long changes as serialized background jobs with status and audit records
- Exposes liveness, dependency readiness, restore preview, diagnostics, and metrics

**Retention policy**
- Implement default retention (documented and configurable):
  - keep last 14 daily backups
  - keep last 8 weekly backups
  - keep last 12 monthly backups
- Provide env vars to change these.

**Safety**
- Snapshot must stop the game only for the staging copy, then restart before compression/upload.
- Archives must carry a versioned manifest, game build, file sizes, and SHA-256 checksums.
- Restore must fully download, extract, and validate before stopping the game.
- Apply restore with an atomic save swap, retained pre-restore directory, health wait, and automatic rollback.
- Reject traversal, symlinks, duplicate paths, excessive files/bytes, and incomplete save pairs.

## 7. Repository layout

suggested top-level structure:

```
.
├─ docker/
│  ├─ enshrouded/
│  │  ├─ Dockerfile
│  │  ├─ entrypoint.sh
│  │  └─ ...
│  ├─ ui/
│  │  ├─ Dockerfile
│  │  └─ ...
│  ├─ controller/
│  │  └─ Dockerfile
│  └─ backup/
│     ├─ Dockerfile
│     └─ ...
├─ docker-compose.yml
├─ .env.example
├─ README.md
└─ docs/
   ├─ specification.md
   └─ ...
```

## 8. Docker build requirements

### 8.1 Builds

- Images target `linux/amd64` only and are built with Buildx in CI.

### 8.2 Base images

- Prefer small, maintained base images.
- Avoid glibc/musl incompatibilities with Wine/Proton where relevant.

### 8.3 Enshrouded image specifics

- Include SteamCMD in the image or install it at runtime.
- Include Wine (64/32-bit) to run the Windows server binary.

## 9. Docker Compose requirements

### 9.1 Single-file compose

- Provide **one** `docker-compose.yml`.
- Optional advanced features may be included as commented blocks.

### 9.2 Minimal user steps

README must instruct:
1. `cp .env.example .env`
2. Edit `.env` (server name, passwords)
3. `docker compose up -d`

### 9.3 Compose features

- Healthchecks for services.
- Named volumes.
- Stable container names (or at least stable service names).
- Use an internal network for `ui`, `backup`, `minio`.

## 10. CI/CD and publishing

### 10.1 Source control

- GitHub repo is the source of truth.

### 10.2 Published images

- GitHub Actions produces AMD64 images under:
  - `powermountain/enshrouded-dedi-server`
  - `powermountain/enshrouded-dedi-ui`
  - `powermountain/enshrouded-dedi-backup`
  - `powermountain/enshrouded-dedi-control`

### 10.3 GitHub workflow triggers

- GitHub Actions should:
  - lint/validate compose
  - run basic tests (UI/backup unit tests)
- publish immutable commit tags from `main` and version tags from semantic Git tags
- run race tests, coverage, vet, vulnerability checks, ShellCheck, Compose validation, image builds, and an isolated restore drill before publishing

## 11. Documentation requirements (README is critical)

README must be extremely clear and include:

1. **What this is** (stack components)
2. **Quickstart** (copy `.env`, run compose)
3. **Ports** and firewall/port-forwarding notes
4. **Admin UI** usage:
   - where it runs
   - how to login
   - what actions are available
5. **Backups & restore**:
   - how backups are scheduled/triggered
   - retention defaults
   - how to upload a local save and restore it
6. **Data persistence**:
   - which volumes matter
   - how to migrate to a new host
7. **AMD64-only platform notes**:
   - tested platforms
   - expected limitations
   - troubleshooting steps
8. **Multiple stacks on one host**:
   - how to change ports
   - unique volume names (or project names)
9. **Troubleshooting**:
   - common failure modes (SteamCMD download issues, runtime errors, permissions)
   - how to collect logs

## 12. Acceptance criteria

1. A user can clone repo, set `.env`, run `docker compose up -d`, and connect to the server.
2. Server updates itself on restart.
3. UI loads and shows server status.
4. Admin can:
   - login
   - trigger restart
   - trigger backup
   - list backups
   - restore backup
   - upload save archive and restore
5. Backups are stored in MinIO bucket and retention default is applied.
6. All four project images are published for AMD64 with immutable tags on Docker Hub.

## 13. Implementation notes (guidance for Codex)

- Prefer simplicity and maintainability over feature richness.
- Favor deterministic behavior: startup update is idempotent.
- Keep secrets out of logs.
- Validate all uploaded archives to prevent path traversal.
