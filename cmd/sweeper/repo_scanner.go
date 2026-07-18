package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type RepoScanner struct {
	token  string
	client *http.Client
}

func NewRepoScanner(token string) *RepoScanner {
	return &RepoScanner{
		token: token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type ghCommitItem struct {
	SHA   string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
}

// ScanRepoCommits fetches recent commits for a repo and queues them for processing.
func (s *RepoScanner) ScanRepoCommits(ctx context.Context, owner, repo string, commitJobs chan<- CommitJob) (int, error) {
	page := 1
	total := 0

	for page <= 4 {
		u := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=100&page=%d", owner, repo, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return total, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return total, err
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return total, fmt.Errorf("rate limited (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return total, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}

		var commits []ghCommitItem
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			resp.Body.Close()
			return total, err
		}
		resp.Body.Close()

		if len(commits) == 0 {
			break
		}

		for _, c := range commits {
			if c.SHA == "" {
				continue
			}
			job := CommitJob{
				Repo:      fmt.Sprintf("%s/%s", owner, repo),
				CommitSHA: c.SHA,
				Ref:       "refs/heads/main",
			}
			select {
			case commitJobs <- job:
			case <-ctx.Done():
				return total, ctx.Err()
			}
			total++
		}

		if len(commits) < 100 {
			break
		}
		page++
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return total, ctx.Err()
		}
	}

	return total, nil
}

func runTargetRepoScan(ctx context.Context, cfg *Config, commitJobs chan<- CommitJob) {
	reposStr := os.Getenv("TARGET_REPOS")
	if reposStr == "" {
		return
	}

	scanner := NewRepoScanner(cfg.GitHubToken)
	repos := strings.Split(reposStr, ",")

	var scan func()
	scan = func() {
		for _, r := range repos {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			parts := strings.SplitN(r, "/", 2)
			if len(parts) != 2 {
				logger.Printf("[repo-scan] invalid repo %q (expected owner/repo)", r)
				continue
			}
			owner, repo := parts[0], parts[1]
			count, err := scanner.ScanRepoCommits(ctx, owner, repo, commitJobs)
			if err != nil {
				logger.Printf("[repo-scan] %s/%s error: %v", owner, repo, err)
			} else {
				logger.Printf("[repo-scan] %s/%s: queued %d commits", owner, repo, count)
			}
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}

	scan()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logger.Printf("[repo-scan] daily scan of target repos")
			scan()
		}
	}
}
