package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/JimStroomberg/enshrouded-dedi/internal/a2s"
)

type maintenanceWindow struct {
	startMinute int
	endMinute   int
}

func parseMaintenanceWindow(raw string) (*maintenanceWindow, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("maintenance window must use HH:MM-HH:MM")
	}
	start, err := parseClock(parts[0])
	if err != nil {
		return nil, err
	}
	end, err := parseClock(parts[1])
	if err != nil {
		return nil, err
	}
	if start == end {
		return nil, fmt.Errorf("maintenance window start and end must differ")
	}
	return &maintenanceWindow{startMinute: start, endMinute: end}, nil
}

func parseClock(raw string) (int, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("maintenance window must use HH:MM-HH:MM")
	}
	hour, hourErr := strconv.Atoi(parts[0])
	minute, minuteErr := strconv.Atoi(parts[1])
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid maintenance window time %q", raw)
	}
	return hour*60 + minute, nil
}

func (w maintenanceWindow) contains(now time.Time) bool {
	minute := now.Hour()*60 + now.Minute()
	if w.startMinute < w.endMinute {
		return minute >= w.startMinute && minute < w.endMinute
	}
	return minute >= w.startMinute || minute < w.endMinute
}

func (s *BackupService) checkRestartPolicy(ctx context.Context, enforceWindow bool) error {
	if enforceWindow && strings.TrimSpace(s.cfg.MaintenanceWindow) != "" {
		window, err := parseMaintenanceWindow(s.cfg.MaintenanceWindow)
		if err != nil {
			return err
		}
		location, err := time.LoadLocation(getenv("TZ", "UTC"))
		if err != nil {
			return fmt.Errorf("load maintenance timezone: %w", err)
		}
		if !window.contains(time.Now().In(location)) {
			return fmt.Errorf("update is outside maintenance window %s (%s)", s.cfg.MaintenanceWindow, location)
		}
	}
	if !s.cfg.RestartRequireEmpty {
		return nil
	}
	running, err := s.containerRunning(ctx)
	if err != nil {
		return fmt.Errorf("inspect game before restart policy check: %w", err)
	}
	if !running {
		return nil
	}
	info, err := a2s.Query(s.cfg.A2SAddr, s.cfg.A2STimeout)
	if err != nil {
		return fmt.Errorf("cannot verify that the server is empty: %w", err)
	}
	if info.Players > 0 {
		return fmt.Errorf("restart deferred because %d player(s) are online", info.Players)
	}
	return nil
}

func (s *BackupService) startPlayerMonitor(ctx context.Context) {
	interval := s.cfg.PlayerPollInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	wasOnline := false
	observed := false
	for {
		select {
		case <-ticker.C:
			info, err := a2s.Query(s.cfg.A2SAddr, s.cfg.A2STimeout)
			if err != nil {
				s.logger.Printf("player monitor query error: %v", err)
				continue
			}
			online := info.Players > 0
			if (!observed && online) || (observed && online != wasOnline) {
				event := "players_offline"
				if online {
					event = "players_online"
				}
				s.jobs.notifyEvent(map[string]interface{}{
					"type":        event,
					"players":     info.Players,
					"max_players": info.MaxPlayers,
					"observed_at": time.Now().UTC(),
				})
			}
			observed = true
			wasOnline = online
		case <-ctx.Done():
			return
		}
	}
}
