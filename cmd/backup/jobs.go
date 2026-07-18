package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type jobState string

const (
	jobQueued    jobState = "queued"
	jobRunning   jobState = "running"
	jobSucceeded jobState = "succeeded"
	jobFailed    jobState = "failed"
)

type job struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	State      jobState               `json:"state"`
	Actor      string                 `json:"actor"`
	CreatedAt  time.Time              `json:"created_at"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	DurationMS int64                  `json:"duration_ms,omitempty"`
	Result     map[string]interface{} `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

type queuedJob struct {
	id  string
	run func(context.Context) (map[string]interface{}, error)
}

type jobManager struct {
	ctx        context.Context
	logger     *log.Logger
	auditPath  string
	webhookURL string
	httpClient *http.Client

	mu    sync.RWMutex
	jobs  map[string]*job
	order []string
	queue chan queuedJob
}

func newJobManager(ctx context.Context, logger *log.Logger, auditPath, webhookURL string) *jobManager {
	m := &jobManager{
		ctx:        ctx,
		logger:     logger,
		auditPath:  auditPath,
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		jobs:       make(map[string]*job),
		queue:      make(chan queuedJob, 64),
	}
	go m.worker()
	return m
}

func (m *jobManager) enqueue(kind, actor string, run func(context.Context) (map[string]interface{}, error)) (*job, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	item := &job{ID: id, Type: kind, State: jobQueued, Actor: actor, CreatedAt: time.Now().UTC()}
	m.mu.Lock()
	m.jobs[id] = item
	m.order = append(m.order, id)
	if len(m.order) > 200 {
		oldest := m.order[0]
		delete(m.jobs, oldest)
		m.order = m.order[1:]
	}
	copy := *item
	m.mu.Unlock()
	select {
	case m.queue <- queuedJob{id: id, run: run}:
		return &copy, nil
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	default:
		m.mu.Lock()
		delete(m.jobs, id)
		m.order = m.order[:len(m.order)-1]
		m.mu.Unlock()
		return nil, fmt.Errorf("operation queue is full")
	}
}

func (m *jobManager) worker() {
	for {
		select {
		case queued := <-m.queue:
			m.run(queued)
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *jobManager) run(queued queuedJob) {
	started := time.Now().UTC()
	m.mu.Lock()
	item := m.jobs[queued.id]
	item.State = jobRunning
	item.StartedAt = &started
	m.mu.Unlock()
	m.logger.Printf("event=operation_started operation_id=%s type=%s actor=%s", item.ID, item.Type, item.Actor)

	result, err := queued.run(m.ctx)
	finished := time.Now().UTC()
	m.mu.Lock()
	item.FinishedAt = &finished
	item.DurationMS = finished.Sub(started).Milliseconds()
	item.Result = result
	if err != nil {
		item.State = jobFailed
		item.Error = sanitizeError(err)
	} else {
		item.State = jobSucceeded
	}
	copy := *item
	m.mu.Unlock()

	m.logger.Printf("event=operation_finished operation_id=%s type=%s state=%s duration_ms=%d", copy.ID, copy.Type, copy.State, copy.DurationMS)
	m.writeAudit(copy)
	m.notify(copy)
}

func (m *jobManager) get(id string) (*job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.jobs[id]
	if !ok {
		return nil, false
	}
	copy := *item
	return &copy, true
}

func (m *jobManager) list(limit int) []job {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]job, 0, limit)
	for i := len(m.order) - 1; i >= 0 && len(items) < limit; i-- {
		if item := m.jobs[m.order[i]]; item != nil {
			items = append(items, *item)
		}
	}
	return items
}

func (m *jobManager) lastSuccessful(kind string) *job {
	items := m.list(100)
	sort.SliceStable(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	for _, item := range items {
		if item.Type == kind && item.State == jobSucceeded {
			copy := item
			return &copy
		}
	}
	return nil
}

func (m *jobManager) writeAudit(item job) {
	if m.auditPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.auditPath), 0o700); err != nil {
		m.logger.Printf("audit mkdir error: %v", err)
		return
	}
	line, _ := json.Marshal(item)
	f, err := os.OpenFile(m.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		m.logger.Printf("audit open error: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		m.logger.Printf("audit write error: %v", err)
	}
}

func (m *jobManager) notify(item job) {
	m.sendNotification(map[string]interface{}{
		"operation_id": item.ID,
		"type":         item.Type,
		"state":        item.State,
		"finished_at":  item.FinishedAt,
		"duration_ms":  item.DurationMS,
		"error":        item.Error,
	})
}

func (m *jobManager) notifyEvent(payload map[string]interface{}) {
	m.sendNotification(payload)
}

func (m *jobManager) sendNotification(payload map[string]interface{}) {
	if m.webhookURL == "" {
		return
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(m.ctx, http.MethodPost, m.webhookURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.logger.Printf("notification error: %v", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		m.logger.Printf("notification returned status=%s", resp.Status)
	}
}

func randomID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
