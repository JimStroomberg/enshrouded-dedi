package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type dockerClient struct {
	http    *http.Client
	baseURL string
	token   string
}

func newDockerClient(endpoint, token string) *dockerClient {
	if endpoint == "" {
		endpoint = "/var/run/docker.sock"
	}
	baseURL := strings.TrimRight(endpoint, "/")
	transport := http.DefaultTransport
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		baseURL = "http://unix"
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "unix", endpoint)
			},
		}
	}
	return &dockerClient{
		http:    &http.Client{Transport: transport, Timeout: 30 * time.Second},
		baseURL: baseURL,
		token:   token,
	}
}

func (d *dockerClient) post(ctx context.Context, path string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, body)
	if err != nil {
		return err
	}
	d.authorize(req)
	resp, err := d.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (d *dockerClient) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+path, nil)
	if err != nil {
		return err
	}
	d.authorize(req)
	resp, err := d.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (d *dockerClient) authorize(req *http.Request) {
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
}

func (d *dockerClient) do(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := d.http.Do(req.Clone(req.Context()))
		if err == nil && resp.StatusCode < http.StatusInternalServerError {
			return resp, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("docker temporary status %s", resp.Status)
			_ = resp.Body.Close()
		} else {
			lastErr = err
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 200 * time.Millisecond)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}
