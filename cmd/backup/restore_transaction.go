package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type preparedRestore struct {
	root      string
	saveDir   string
	configDir string
	manifest  *backupManifest
}

func (s *BackupService) restoreLocalArchive(ctx context.Context, archivePath string, backupBefore bool) error {
	prepared, err := s.prepareRestoreArchive(archivePath)
	if err != nil {
		return err
	}
	defer prepared.cleanup()

	if backupBefore {
		if _, err := s.createBackupUnlocked(ctx); err != nil {
			return fmt.Errorf("create pre-restore backup: %w", err)
		}
	}
	rollbackRoot, err := s.applyPreparedRestore(ctx, prepared)
	if err != nil {
		return err
	}
	s.logger.Printf("restore complete; pre-restore files retained at %s", rollbackRoot)
	return nil
}

func (s *BackupService) prepareRestoreArchive(archivePath string) (*preparedRestore, error) {
	parent := filepath.Dir(filepath.Clean(s.cfg.SaveDir))
	root, err := os.MkdirTemp(parent, ".enshrouded-restore-stage-")
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(root)
		}
	}()
	limits := archiveLimits{MaxFiles: s.cfg.MaxExtractFiles, MaxBytes: s.cfg.MaxExtractBytes}
	if err := extractArchiveWithLimits(archivePath, root, limits); err != nil {
		return nil, fmt.Errorf("validate restore archive: %w", err)
	}
	saveDir, configDir, manifest, err := restorePayload(root)
	if err != nil {
		return nil, fmt.Errorf("validate restore payload: %w", err)
	}
	cleanup = false
	return &preparedRestore{root: root, saveDir: saveDir, configDir: configDir, manifest: manifest}, nil
}

func (p *preparedRestore) cleanup() {
	if p != nil && p.root != "" {
		_ = os.RemoveAll(p.root)
	}
}

func (s *BackupService) applyPreparedRestore(ctx context.Context, prepared *preparedRestore) (rollbackRoot string, err error) {
	wasRunning, err := s.containerRunning(ctx)
	if err != nil {
		return "", fmt.Errorf("inspect game container before restore: %w", err)
	}
	stopped := false
	oldSaveMoved := false
	completed := false
	configBackup := map[string]string{}
	defer func() {
		if completed {
			return
		}
		var recoveryErr error
		if oldSaveMoved {
			recoveryErr = s.rollbackAppliedRestore(rollbackRoot, configBackup, wasRunning)
		} else if stopped && wasRunning {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			recoveryErr = s.startContainer(recoveryCtx)
			cancel()
		}
		if recoveryErr != nil {
			err = errors.Join(err, fmt.Errorf("restore recovery failed: %w", recoveryErr))
		}
	}()

	if wasRunning {
		if err := s.stopContainer(ctx); err != nil {
			return "", fmt.Errorf("stop game container for restore: %w", err)
		}
		stopped = true
	}

	parent := filepath.Dir(filepath.Clean(s.cfg.SaveDir))
	rollbackRoot, err = os.MkdirTemp(parent, ".enshrouded-restore-rollback-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(rollbackRoot, 0o700); err != nil {
		return rollbackRoot, err
	}
	configBackup, err = s.captureCurrentConfig(filepath.Join(rollbackRoot, "config"))
	if err != nil {
		return rollbackRoot, err
	}
	rollbackSave := filepath.Join(rollbackRoot, "savegame")
	if err := os.Rename(s.cfg.SaveDir, rollbackSave); err != nil {
		return rollbackRoot, fmt.Errorf("move current save to rollback: %w", err)
	}
	oldSaveMoved = true

	if err := os.Rename(prepared.saveDir, s.cfg.SaveDir); err != nil {
		return rollbackRoot, fmt.Errorf("activate restored save: %w", err)
	}
	prepared.saveDir = ""
	if prepared.configDir != "" {
		if err := s.installRestoredConfig(prepared.configDir); err != nil {
			return rollbackRoot, err
		}
	}

	if wasRunning {
		if err := s.startContainer(ctx); err != nil {
			return rollbackRoot, fmt.Errorf("start restored game container: %w", err)
		}
		stopped = false
		healthCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HealthTimeout)
		defer cancel()
		if err := s.waitContainerHealthy(healthCtx); err != nil {
			return rollbackRoot, fmt.Errorf("restored game did not become healthy: %w", err)
		}
	}

	completed = true
	return rollbackRoot, nil
}

func (s *BackupService) captureCurrentConfig(destDir string) (map[string]string, error) {
	targets := map[string]string{
		"enshrouded_server.json": s.serverConfigPath(),
		"server_config.txt":      s.serverConfigTxtPath(),
	}
	backup := make(map[string]string, len(targets))
	for name, source := range targets {
		info, err := os.Stat(source)
		if errors.Is(err, os.ErrNotExist) {
			backup[source] = ""
			continue
		}
		if err != nil {
			return nil, err
		}
		dest := filepath.Join(destDir, name)
		if err := copyRegularFile(source, dest, info.Mode().Perm()); err != nil {
			return nil, err
		}
		backup[source] = dest
	}
	return backup, nil
}

func (s *BackupService) installRestoredConfig(sourceDir string) error {
	targets := map[string]string{
		"enshrouded_server.json": s.serverConfigPath(),
		"server_config.txt":      s.serverConfigTxtPath(),
	}
	for name, target := range targets {
		source := filepath.Join(sourceDir, name)
		raw, err := os.ReadFile(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read restored config %s: %w", name, err)
		}
		if err := s.writeAtomic(target, raw); err != nil {
			return fmt.Errorf("install restored config %s: %w", name, err)
		}
	}
	return nil
}

func (s *BackupService) restoreCapturedConfig(backup map[string]string) error {
	var result error
	for target, source := range backup {
		if source == "" {
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
			continue
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if err := s.writeAtomic(target, raw); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *BackupService) rollbackAppliedRestore(rollbackRoot string, configBackup map[string]string, shouldStart bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HealthTimeout)
	defer cancel()
	var result error
	running, err := s.containerRunning(ctx)
	if err != nil {
		result = errors.Join(result, err)
	} else if running {
		if err := s.stopContainer(ctx); err != nil {
			return errors.Join(result, err)
		}
	}

	parent := filepath.Dir(filepath.Clean(s.cfg.SaveDir))
	failedRoot, err := os.MkdirTemp(parent, ".enshrouded-failed-restore-")
	if err != nil {
		result = errors.Join(result, err)
	} else if _, statErr := os.Stat(s.cfg.SaveDir); statErr == nil {
		if err := os.Rename(s.cfg.SaveDir, filepath.Join(failedRoot, "savegame")); err != nil {
			result = errors.Join(result, err)
		}
	}
	rollbackSave := filepath.Join(rollbackRoot, "savegame")
	if err := os.Rename(rollbackSave, s.cfg.SaveDir); err != nil {
		return errors.Join(result, err)
	}
	if err := s.restoreCapturedConfig(configBackup); err != nil {
		result = errors.Join(result, err)
	}
	if shouldStart {
		if err := s.startContainer(ctx); err != nil {
			return errors.Join(result, err)
		}
		if err := s.waitContainerHealthy(ctx); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *BackupService) waitContainerHealthy(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		var inspect struct {
			State struct {
				Running bool `json:"Running"`
				Health  struct {
					Status string `json:"Status"`
				} `json:"Health"`
			} `json:"State"`
		}
		if err := s.docker.get(ctx, fmt.Sprintf("/containers/%s/json", s.cfg.EnshroudedContainer), &inspect); err == nil {
			if inspect.State.Running && (inspect.State.Health.Status == "" || inspect.State.Health.Status == "healthy") {
				return nil
			}
			if inspect.State.Health.Status == "unhealthy" {
				return errors.New("container is unhealthy")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
