package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHubEvent is the minimal structure we need from the Events API.
type GitHubEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Repo struct {
		Name string `json:"name"` // "owner/repo"
	} `json:"repo"`
	Payload json.RawMessage `json:"payload"`
	// CreatedAt is informational only.
	CreatedAt string `json:"created_at"`
}

// PushPayload contains the commits of a PushEvent.
type PushPayload struct {
	Commits []struct {
		SHA     string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commits"`
	Ref string `json:"ref"`
}

// CommitJob is sent to the extraction workers.
type CommitJob struct {
	Repo      string
	CommitSHA string
	Ref       string
}

// GitHubMonitor continuously polls the GitHub Events API and emits new commits.
type GitHubMonitor struct {
	token      string
	client     *http.Client
	seenEvents sync.Map // event ID -> struct{}
}

func NewGitHubMonitor(token string) *GitHubMonitor {
	return &GitHubMonitor{
		token: token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Run starts the monitoring loop and sends CommitJobs to out until ctx is cancelled.
func (m *GitHubMonitor) Run(ctx context.Context, out chan<- CommitJob) {
	// We poll the public events endpoint. With a token you get 5000 req/hr
	// and can receive up to 300 events per page.
	interval := 1 * time.Second
	if m.token == "" {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, pollInterval, err := m.fetchEvents(ctx)
			if err != nil {
				logger.Printf("[monitor] fetch error: %v", err)
				continue
			}
			if pollInterval > 0 {
				ticker.Reset(pollInterval)
			}
			for _, ev := range events {
				if ev.Type != "PushEvent" {
					continue
				}
				// Deduplicate events we've already seen.
				if _, loaded := m.seenEvents.LoadOrStore(ev.ID, struct{}{}); loaded {
					continue
				}

				var payload PushPayload
				if err := json.Unmarshal(ev.Payload, &payload); err != nil {
					continue
				}
				for _, commit := range payload.Commits {
					if commit.SHA == "" {
						continue
					}
					job := CommitJob{
						Repo:      ev.Repo.Name,
						CommitSHA: commit.SHA,
						Ref:       payload.Ref,
					}
					select {
					case out <- job:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}

// fetchEvents calls the GitHub Events API and returns events plus a suggested
// poll interval derived from the X-Poll-Interval header.
func (m *GitHubMonitor) fetchEvents(ctx context.Context) ([]GitHubEvent, time.Duration, error) {
	// https://docs.github.com/en/rest/activity/events
	url := "https://api.github.com/events?per_page=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		return nil, 60 * time.Second, fmt.Errorf("rate limited or forbidden (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	// Respect X-Poll-Interval (seconds).
	var pollInterval time.Duration
	if v := resp.Header.Get("X-Poll-Interval"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			pollInterval = time.Duration(secs) * time.Second
		}
	}

	var events []GitHubEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, pollInterval, err
	}
	return events, pollInterval, nil
}

var diffRateLimit = time.NewTicker(2 * time.Second) // max 30 diff fetches/min = 1800/hr, leaves room for search+monitor

// FetchCommitDiff retrieves the unified diff for a single commit from the GitHub API.
func (m *GitHubMonitor) FetchCommitDiff(ctx context.Context, repo, sha string) (string, error) {
	select {
	case <-diffRateLimit.C:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	// "owner/repo" -> owner, repo
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repo %q", repo)
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", parts[0], parts[1], sha)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// Request the diff media type.
	req.Header.Set("Accept", "application/vnd.github.diff")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("commit not found: %s/%s", repo, sha)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	// Limit diff size to 1 MB to avoid runaway memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
