# Operations Guide

## Safety rules

1. Keep at least one verified stopped-server archive outside the Docker volume.
2. Deploy only immutable project image tags such as `main-<commit>` or a semantic version.
3. Take a fresh backup and wait for its job to succeed before changing images or restoring data.
4. Treat a backup as proven only after an isolated restore drill validates its files and manifest.
5. Never test a restore against the live save merely to confirm that restore works.

## Deployment through Portainer

Before deployment:

- record the current stack definition, environment, image tags, and game-container health;
- confirm the latest backup name, timestamp, size, and checksum metadata in the UI;
- download one recent archive and verify that it opens, or run the isolated restore drill;
- ensure the game data volume is writable by UID/GID 1000;
- preserve all existing Portainer environment values when adding new variables.

Deploy:

1. Change all four project images to the same tested immutable tag: server, backup, UI, and controller.
2. Pull the images and redeploy the complete stack. Pruning is not required for the first rollout.
3. Watch the controller, MinIO, game, backup, and UI in that order.
4. Wait for the game healthcheck to receive an A2S response. SteamCMD may make the first boot take longer than later restarts.
5. Confirm backup and UI readiness, then sign in and inspect Recent Operations.
6. Trigger a fresh backup, wait for success, preview it, download it, and validate its archive/manifest.
7. Confirm that a normal game-container restart preserves the same save path and world.

The game container is read-only except for `/data` and `/tmp`. SteamCMD, Wine, Steam state, the server installation, and save data all live under `/data`.

## Admin UI login troubleshooting

The admin UI keeps CSRF form-token validation enabled in every mode. In local HTTP mode (`UI_SECURE_COOKIES=false`), it also supports sandboxed webviews that send the opaque `Origin: null`; the form token and CSRF cookie must still match. Parseable cross-origin requests remain rejected.

If login reports `invalid or expired form`:

1. Refresh the page to obtain a new form token.
2. Confirm the browser reaches the UI over the same HTTP address shown in its address bar.
3. If an HTTPS reverse proxy is in front of the UI, set `UI_SECURE_COOKIES=true` and preserve the public `Host` header.
4. Check the UI log's `csrf rejected` reason before changing credentials; CSRF failures occur before username/password validation.

## Rollback

If the new stack cannot become healthy:

1. Do not delete or recreate either named volume.
2. Reapply the previously recorded stack definition and immutable image tags.
3. Redeploy without pruning volumes.
4. Wait for the previous game image to become healthy and verify the world through A2S/login.
5. If an operation changed the save, use the restore transaction's retained rollback directory or restore the last verified archive only after inspecting its preview.

Image rollback and data restore are separate decisions. Prefer image rollback first when the save itself was not changed.

## Monthly restore drill

Run at least monthly and after any backup/restore code change:

```sh
./scripts/restore-drill.sh
```

The drill builds the current backup/controller images, creates a disposable game volume and MinIO server, creates a backup, validates that the manifest exists, downloads and gzip-checks the archive, mutates the disposable world/config, restores the backup through a queued job, and compares the restored contents. It also verifies that the pre-restore rollback directory was retained.

Success ends with `restore_drill=passed`. The script removes its temporary containers, network, and volume on exit.

For an additional production-image proof, run the same workflow after replacing the drill image tags with the immutable deployed images. Never mount the production data volume into the drill.

## Backup freshness and restore preview

The UI shows the latest backup, age, size, checksum metadata, and next scheduled run. Before restore:

1. Open Restore Preview.
2. Require `Validation: passed`.
3. Compare backup and current game builds. A different build is a warning for operator review, not an automatic rejection.
4. Review the exact save/config files that will be replaced.
5. Leave “Backup before restore” enabled unless the current save is known corrupt and cannot be snapshotted.

All archive validation happens before the game stops. Expansion bytes, file counts, traversal, symlinks, duplicate paths, required save pairs, and manifest checksums are enforced.

## Off-host S3

Set `BACKUP_S3_ENDPOINT`, access key, secret key, bucket, and SSL mode for any compatible provider. Use credentials limited to the backup bucket with list/get/put/delete permissions required by retention and readiness probes.

When switching away from bundled MinIO:

- create and version the remote bucket first;
- copy existing archives with an S3-aware tool and compare object counts/checksums;
- keep the old MinIO volume until a remote archive has passed an isolated restore drill;
- review provider lifecycle rules so they do not expire backups sooner than application retention.

Alternatively, keep bundled MinIO active and configure bucket replication externally.

## Notifications and maintenance

`BACKUP_NOTIFICATION_WEBHOOK_URL` receives compact JSON for every completed operation, including its ID, type, state, duration, and sanitized error. Enable `BACKUP_PLAYER_NOTIFICATIONS` to add transitions between empty and players-online states.

`BACKUP_RESTART_REQUIRE_EMPTY=true` makes restart, update, and config-change jobs fail safely when players are online or player count cannot be verified. `BACKUP_MAINTENANCE_WINDOW` applies an additional local-time window to update jobs. Example: `23:00-02:00` permits updates across midnight.

Restore remains an explicit operator action and is not blocked by the optional restart policy. Check players before an emergency restore.

## Diagnostics and metrics

The UI diagnostics button downloads a gzip-compressed tar containing readiness, operations, game status, versions, recent jobs, redacted server config, and redacted recent logs. Password values discovered in the server config and Steam auth file are replaced before packaging.

The internal backup API exposes Prometheus text at `/metrics`. It requires `Authorization: Bearer <BACKUP_INTERNAL_TOKEN>` and should be scraped only over the private Compose network or a protected proxy.

## Multiple instances

For every instance, set unique values for:

- `COMPOSE_PROJECT_NAME`;
- `ENSHROUDED_CONTAINER_NAME`;
- `GAME_HOST_PORT` and `QUERY_HOST_PORT`;
- `UI_HOST_PORT`;
- `MINIO_CONSOLE_HOST_PORT` when the console is exposed.

The controller authorizes exactly one configured game-container name. Never reuse its token between unrelated stacks.
