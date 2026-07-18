# Enshrouded Dedicated Server Modernization Roadmap

Updated: 2026-07-18

## Outcome

The seven-month-old live world was recovered without data loss and remains playable. Modernization is implemented in staged checkpoints so every risky change is backed by an immutable image, verified archive, transactional restore path, and isolated recovery drill.

## Phase 0 — Reproducible rescue release

Status: complete

- Password/save-path/retention production fixes are merged and deployed from an immutable image.
- CI derives its environment from `.env.example`, validates Compose, and builds all project images.
- Main-commit and semantic-version tag rules are defined.
- Deployment and image-first rollback procedures are documented in `docs/operations.md`.
- The final `v1.0.0` tag is intentionally created only after the complete modernized stack passes the live GS2 rollout.

## Phase 1 — Disaster-safe backup and restore

Status: complete

- Backup stops the game only for a consistent staging copy, then restarts before compression/upload.
- Archives include save/config data, game build, schema, sizes, and SHA-256 manifest checksums.
- Object names include nanoseconds and use write-once S3 semantics.
- Restore validates the complete archive before stopping the game, enforces path/file/size limits, atomically swaps the save, and automatically rolls back an unhealthy start.
- Archive traversal, duplicate paths, symlinks, expansion limits, required save pairs, manifest tampering, restart guarantees, and rollback are regression-tested.
- `scripts/restore-drill.sh` proves backup/download/mutation/restore/checksum behavior against disposable Docker and MinIO volumes.
- Monthly drill and off-host S3/replication procedures are documented.

## Phase 2 — Current supported runtime and dependencies

Status: complete

- Go `1.26.0` with toolchain `1.26.5`.
- MinIO Go `v7.2.1`, Gorilla Sessions `v1.4.0`, Gorilla CSRF `v1.7.3`, and reviewed transitive updates.
- `govulncheck` reports no reachable vulnerabilities. It records one uncalled Gorilla CSRF `TrustedOrigins` advisory (that option is not used) and an uncalled transitive `x/crypto/openpgp` module advisory with no upstream fixed release.
- Debian, Alpine, MinIO, MinIO Client, and GitHub Actions are pinned to tested digests/SHAs.
- Dependabot covers Go, Actions, and every Dockerfile.
- Debian Bookworm/Wine remains the compatibility baseline; final AMD64 game startup is verified on GS2 rather than ARM Docker Desktop emulation.

## Phase 3 — Admin/control-plane hardening

Status: complete and verified on GS2

- CSRF protection on every state-changing form.
- Constant-time login checks and per-IP throttling.
- Startup rejection of default admin, session, CSRF, internal API, controller, and S3 credentials.
- Signed/encrypted sessions, configurable Secure cookies, restrictive response headers, and HTTP/graceful-shutdown timeouts.
- Current game passwords are never returned to the UI; Steam credentials are stored with base64-safe shell transport.
- Authenticated UI-to-backup requests.
- A narrow Docker controller allows only inspect/start/stop/restart for one configured game container.
- Docker requests have timeouts/retries; services run read-only with temporary filesystems, dropped capabilities, and resource ceilings where practical.
- SteamCMD was moved into persistent writable storage so read-only game roots still update correctly.

## Phase 4 — Testable responsibilities and CI

Status: complete for the current single-binary architecture

- Backup responsibilities are split into snapshot, restore transaction, Docker client, retention, jobs/audit, operations, security, maintenance, and config-transaction files.
- UI authentication/client logic is split out; HTML, logo, and static assets are embedded from dedicated files.
- A2S is a shared internal package with challenge-response tests.
- Table-driven/regression tests cover retention boundaries, archive safety, restore rollback, configuration preservation/rollback, auth, CSRF, upstream timeouts, controller allow-listing, diagnostics redaction, webhooks, and maintenance windows.
- Race tests, 30% aggregate coverage floor, vet, ShellCheck, Compose validation, healthcheck syntax, `govulncheck`, restore drill, and four-image builds run in CI.
- Safety-focused functions have materially higher coverage than the repository aggregate; the backup package is currently about 37% and retention/A2S/security primitives are mostly 75–100%.

## Phase 5 — Operations and user experience

Status: complete and verified on GS2

- Serialized background jobs expose queued/running/succeeded/failed states, IDs, durations, results, and sanitized errors.
- The UI shows recent jobs, latest backup metadata, checksum presence, and next scheduled backup.
- Restore preview fully validates an archive and shows build compatibility plus the exact files replaced.
- Game readiness uses A2S; backup readiness verifies save writability, Docker control, and real S3 write/read/delete; UI readiness verifies backup readiness.
- Structured operation logs and a durable JSONL audit trail are included.
- Bundled static logo/template removes third-party asset dependencies.
- One-click diagnostics packages redacted config/logs, health, versions, jobs, and backup state.

## Phase 6 — Optional operational improvements

Status: complete as configurable features

- Any compatible remote S3 endpoint can replace bundled MinIO.
- Generic JSON job webhooks cover update, backup failure, and restore completion; optional A2S monitoring adds players-online/offline transitions.
- Player-aware restart/config/update protection and timezone-aware maintenance windows are configurable.
- Container names, project name, host game/query/UI/console ports, and resource ceilings support multiple named instances.
- Authenticated Prometheus text metrics are exposed by the backup service.
- Mobile layout and form-submit confirmation cover keyboard and touch use.

## Final release gate

Status: complete

- Hardening and the Portainer/HTTP compatibility follow-up merged through PRs #4 and #5. The live release candidate uses immutable tag `main-7781e48` for all four project images.
- The final live backup is `backup-20260718-202112.951819598.tar.gz` (12,899,001 bytes; SHA-256 `550d1d156f827700f0756cccc77b9f0a0e80ab533887e215086d504a05a33864`). Its schema-1 manifest, game build `23178631`, 35 file sizes/checksums, required world/character pairs, download, and matching-build restore preview were independently verified.
- Non-default UI encryption, CSRF, internal API, controller, and MinIO credentials are active. Internal API authentication, controller token enforcement, and the single-container allow-list returned the expected 200/401/404 responses.
- The image-only Portainer stack is deployed on GS2. Controller, MinIO, game, backup, and UI are healthy; the UI is reachable on port 8555; direct-HTTP CSRF login, security headers, password omission, readiness, and A2S status passed live checks.
- Diagnostics contained the expected seven files and passed checks against UI, control-plane, S3, Steam, and game-password values. Password fields are omitted from the redacted config.
- A queued production restart succeeded in 48.5 seconds and returned to A2S build `0.0.15.0`. The user confirmed the recovered world was playable before rollout; post-rollout A2S and live save-pair checks confirm the same persistent world remains mounted.
- The isolated restore drill ran with the exact `main-7781e48` backup/controller production images, restored the disposable world/config, and retained one pre-restore rollback directory.
- Release tag: `v1.0.0`. Verified rollback image: `main-7781e48`. Independent recovery artifacts remain in `/home/adminjim`.

## Explicitly deferred

- Kubernetes or other cluster orchestration.
- ARM64 game-server support.
- A database, registration, or full RBAC.
- A JavaScript frontend rewrite.
- Bundling a public TLS/reverse-proxy solution into the core stack.

These remain outside the stack's single-host, simple-operations design.
