package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

type fileSnapshot struct {
	path   string
	data   []byte
	exists bool
}

func (s *BackupService) applyConfigTransaction(ctx context.Context, mutate func() error) (err error) {
	wasRunning, err := s.containerRunning(ctx)
	if err != nil {
		return fmt.Errorf("inspect game before config update: %w", err)
	}
	snapshots, err := captureFiles(s.serverConfigPath(), s.serverConfigTxtPath())
	if err != nil {
		return err
	}
	if wasRunning {
		if err := s.stopContainer(ctx); err != nil {
			return fmt.Errorf("stop game for config update: %w", err)
		}
	}
	defer func() {
		if err == nil {
			return
		}
		if wasRunning {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HealthTimeout)
			running, inspectErr := s.containerRunning(recoveryCtx)
			if inspectErr != nil {
				err = errors.Join(err, fmt.Errorf("inspect failed config before rollback: %w", inspectErr))
			} else if running {
				if recoveryErr := s.stopContainer(recoveryCtx); recoveryErr != nil {
					err = errors.Join(err, fmt.Errorf("stop failed config before rollback: %w", recoveryErr))
				}
			}
			cancel()
		}
		if recoveryErr := restoreFiles(s, snapshots); recoveryErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous config: %w", recoveryErr))
		}
		if wasRunning {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HealthTimeout)
			defer cancel()
			if recoveryErr := s.startAndWait(recoveryCtx); recoveryErr != nil {
				err = errors.Join(err, fmt.Errorf("restart previous config: %w", recoveryErr))
			}
		}
	}()
	if err := mutate(); err != nil {
		return err
	}
	if wasRunning {
		if err := s.startAndWait(ctx); err != nil {
			return fmt.Errorf("updated config did not become healthy: %w", err)
		}
	}
	return nil
}

func captureFiles(paths ...string) ([]fileSnapshot, error) {
	items := make([]fileSnapshot, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			items = append(items, fileSnapshot{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		items = append(items, fileSnapshot{path: path, data: data, exists: true})
	}
	return items, nil
}

func restoreFiles(s *BackupService, snapshots []fileSnapshot) error {
	var result error
	for _, item := range snapshots {
		if !item.exists {
			if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
			continue
		}
		if err := s.writeAtomic(item.path, item.data); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
