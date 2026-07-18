# Enshrouded Dedicated Server Modernization Roadmap

Updated: 2026-07-18

## Guiding priorities

1. Never risk the existing world to modernize the stack.
2. Prove backups by restoring them into an isolated volume, not only by creating or downloading archives.
3. Make deployments reproducible before changing dependencies or the UI.
4. Keep the project simple: single-host Docker Compose, AMD64, Portainer-compatible, and no database.

## Current baseline

- The live server is healthy and loads the existing version-12 save.
- A verified stopped-server ZIP exists outside the Docker volume.
- The backup retention bug is fixed locally and deployed on GS2 as `backupfix-20260718`.
- The live backup service successfully created, retained, listed, downloaded, and inspected a MinIO archive.
- The repository still has the rescue changes uncommitted and the fixed image has not yet been published to Docker Hub.
- Go baseline: `go 1.22`; current verified toolchain available during this review: Go 1.26.5.
- Key available updates include MinIO Go `v7.0.69 -> v7.2.1` and Gorilla Sessions `v1.2.2 -> v1.4.0`.
- `govulncheck` reports no reachable vulnerabilities. It does report an imported `golang.org/x/net` vulnerability fixed in `v0.55.0`, plus older vulnerable modules that are not currently reached by the application.
- Test coverage is 1.5% for `cmd/backup` and 0% for `cmd/ui`.
- `cmd/backup/main.go` and `cmd/ui/main.go` are currently large single-file programs, at roughly 1,850 and 1,475 lines.

## Phase 0 — Turn the rescue into a reproducible release

Priority: immediate

Estimated effort: half a day

- Review and commit the current password, save-path, and retention fixes.
- Add the new backup path variables to CI's generated environment or derive CI configuration from `.env.example` so the two cannot drift.
- Build all three images in CI and publish immutable version and commit-SHA tags.
- Replace the GS2-only `backupfix-20260718` image with the published immutable tag through Portainer.
- Record a short deployment and rollback procedure.
- Create the project's first semantic release tag instead of relying only on `latest`.

Done when:

- A clean clone can build and test the same images.
- Portainer references a published immutable backup image.
- Normal container restart and full stack redeploy both preserve the world and use the fixed backup service.
- Rollback requires selecting the previous image tag, not rebuilding code on GS2.

## Phase 1 — Make backup and restore genuinely disaster-safe

Priority: highest

Estimated effort: 1–2 days

### Consistent snapshots

- Briefly stop the game, copy the save and configuration into a staging directory, restart the game, then compress and upload the staged copy. This limits downtime to the file-copy window instead of the full upload.
- Include `enshrouded_server.json`, launch configuration, save files, and a generated manifest in every backup.
- Put archive format version, game build, timestamps, file sizes, and SHA-256 checksums in the manifest.
- Prevent two backups from running concurrently and prevent timestamp-name collisions. Use write-once object creation rather than overwriting an existing name.

### Transactional restore

- Download and fully validate the archive before stopping the game.
- Extract into a new staging directory with file-count, expanded-size, and path limits to prevent corrupt archives and archive bombs.
- Validate required world and character files plus manifest checksums.
- Stop the game only after validation, atomically swap the save directory, then restart.
- Always attempt to restart the game on every failure path.
- Keep the pre-restore directory until the restored server has become healthy; automatically roll back if startup validation fails.

### Prove recovery

- Add an integration test using a temporary MinIO container and temporary save volume.
- Perform a restore drill into a disposable Docker volume and compare checksums with the source.
- Add a documented monthly restore drill.
- Add optional off-host S3 storage or replication. MinIO on the same host protects against application mistakes, but not loss of GS2 or its storage.

Done when:

- Killing a backup or restore at each major step cannot destroy the last known-good save.
- A malformed archive is rejected before production files change.
- The game restarts even when restore validation fails.
- A backup has been restored successfully into an isolated volume and its manifest verified.

## Phase 2 — Upgrade the supported runtime and dependencies

Priority: high

Estimated effort: 1 day

- Move `go.mod`, builder images, and GitHub Actions from Go 1.22 to Go 1.26 in one controlled change.
- Update direct dependencies, starting with MinIO Go and Gorilla Sessions, then run `go mod tidy` and inspect transitive changes.
- Ensure `golang.org/x/net` is at least the currently fixed release reported by `govulncheck`.
- Keep Gorilla Mux for now; replacing a working router adds little value compared with fixing backup and HTTP behavior.
- Pin Debian, MinIO, MinIO Client, and published project images to tested release tags or digests rather than mutable `latest` tags.
- Keep Debian Bookworm for Wine initially unless a disposable-server test proves a newer base image works; Wine/game compatibility matters more than cosmetic base-image churn.
- Add Dependabot or Renovate for Go modules, GitHub Actions, and container images.

Done when:

- Tests and images build on Go 1.26.
- `govulncheck` reports no reachable or imported-package vulnerability.
- A disposable server starts, updates through SteamCMD, and reaches healthy state with the new images.
- Production uses immutable, recorded image versions.

## Phase 3 — Harden the admin and control plane

Priority: high

Estimated effort: 1–2 days

- Add CSRF protection to every state-changing UI form.
- Add login throttling and constant-time credential comparison.
- Fail startup when production still uses default UI or MinIO credentials/session keys.
- Add configurable secure-cookie behavior for reverse-proxy HTTPS deployments.
- Stop placing the current game password back into rendered HTML; use an explicit “replace password” field.
- Authenticate UI-to-backup requests with an internal token.
- Reduce Docker socket exposure. Prefer a tightly scoped socket proxy or a small controller that permits only status/start/stop/restart for the configured game container.
- Add HTTP server read-header, read, write, idle, and graceful-shutdown timeouts to both Go services.
- Give the Docker API client a timeout and bounded retry policy.
- Run containers read-only where practical, use temporary filesystems for scratch data, drop unnecessary capabilities, and set resource limits.
- Document that the admin UI should be firewall-restricted or placed behind HTTPS when exposed outside the trusted network.

Done when:

- Cross-site form submissions and repeated login guessing are blocked.
- Compromising the UI does not automatically provide unrestricted Docker control.
- Hung clients or Docker calls cannot hold a service forever.
- No password is echoed into HTML, logs, or status responses.

## Phase 4 — Refactor around testable responsibilities

Priority: medium

Estimated effort: 2–3 days

- Split the backup program into configuration, S3 store, archive, retention, restore transaction, Docker control, and HTTP packages.
- Split the UI into handlers, backup client, A2S client, authentication middleware, templates, and static assets.
- Embed templates/static files rather than keeping a very large template string in `main.go`.
- Introduce interfaces only at external boundaries: object storage, Docker control, filesystem operations, and time.
- Add table-driven tests for:
  - retention across daily/weekly/monthly boundaries;
  - archive traversal, symlinks, duplicate paths, and expansion limits;
  - restore rollback and guaranteed restart behavior;
  - configuration preservation when Enshrouded adds unknown fields;
  - UI authentication, CSRF, actions, timeouts, and upstream errors.
- Add `go vet`, `govulncheck`, race tests, coverage reporting, shell checks, Compose validation, and image smoke tests to CI.
- Set a meaningful target for safety-critical packages (for example 80%) rather than chasing a repository-wide vanity number.

Done when:

- Backup and restore behavior can be tested without Docker or a real S3 server, with one separate end-to-end test proving the adapters.
- Every previously observed production bug has a regression test.
- CI blocks unsafe archive handling, retention regressions, stale Compose variables, and vulnerable reachable dependencies.

## Phase 5 — Improve operations and user experience

Priority: medium

Estimated effort: 1–2 days

- Replace long synchronous UI requests with background jobs and status polling for update, backup, upload, and restore.
- Show backup progress, last successful backup, age, size, checksum status, next scheduled run, and last error.
- Add a restore preview that displays manifest/game-build compatibility and the exact files that will be replaced.
- Separate liveness from readiness:
  - game readiness should include a successful A2S/query response;
  - backup readiness should verify the save path, Docker control, bucket access, and write/read capability;
  - UI readiness should verify its backup dependency.
- Add structured logs with operation IDs and durations without logging credentials.
- Add a simple audit trail for restart, update, backup, configuration change, and restore actions.
- Bundle the logo/static assets so the admin page does not depend on a third-party URL.
- Add a one-click diagnostics bundle containing redacted config, health, versions, recent logs, and backup status.

Done when:

- The UI accurately distinguishes queued, running, succeeded, and failed operations.
- Operators can see whether backups are recent and restorable without reading container logs.
- A diagnostics bundle can be shared without exposing secrets.

## Phase 6 — Optional improvements after the foundation is stable

- Configurable remote S3 providers in addition to bundled MinIO.
- Notifications for server update, backup failure, restore completion, and players online.
- Scheduled maintenance windows and player-aware restarts.
- Multiple named server instances without hard-coded container names.
- Prometheus/OpenTelemetry metrics if the operational need appears.
- Better mobile layout and accessible confirmation flows for destructive actions.

## Explicitly deferred

- Kubernetes or other cluster orchestration.
- ARM64 game-server support.
- A database, registration, or full RBAC.
- A JavaScript frontend rewrite.
- Bundling a public TLS/reverse-proxy solution into the core stack.

These remain outside the project's current simplicity and reliability goals.

## Recommended execution order

1. Phase 0: publish and pin today's rescue fixes.
2. Phase 1: transactional backup/restore plus a real restore drill.
3. Phase 2: runtime/dependency/container upgrades.
4. Phase 3: control-plane hardening.
5. Phase 4: refactor and raise test confidence.
6. Phase 5: operational UX.
7. Phase 6 only when a concrete need justifies it.
