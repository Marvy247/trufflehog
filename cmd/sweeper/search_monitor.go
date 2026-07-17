package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// CommitSearchResult from the GitHub Search Commits API.
type CommitSearchResult struct {
	SHA   string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Repo  struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
}

// SearchMonitor polls the GitHub commit search API for leaked key patterns.
type SearchMonitor struct {
	token        string
	client       *http.Client
	seenCommits  sync.Map
}

func NewSearchMonitor(token string) *SearchMonitor {
	return &SearchMonitor{
		token: token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

var commitSearchQueries = []string{
	`"BEGIN EC PRIVATE KEY"`,
	`"BEGIN ETH PRIVATE KEY"`,
	`"mnemonic" ` + `"wallet" ` + `"phrase"`,
	`"private key" ` + `"wallet" ` + `"ethereum"`,
	`"xprv" ` + `"private"`,
	`"seed phrase" ` + `"wallet"`,
	`"keystore" ` + `"password" ` + `"wallet"`,
	`"secret recovery phrase"`,
}

func (m *SearchMonitor) Run(ctx context.Context, out chan<- CommitJob) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	var queryIdx int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q := commitSearchQueries[queryIdx%len(commitSearchQueries)]
			queryIdx++

			jobs, err := m.searchCommits(ctx, q)
			if err != nil {
				logger.Printf("[search] %q error: %v", q, err)
				continue
			}
			for _, j := range jobs {
				select {
				case out <- j:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (m *SearchMonitor) searchCommits(ctx context.Context, query string) ([]CommitJob, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("sort", "committer-date")
	params.Set("order", "desc")
	params.Set("per_page", "30")

	u := "https://api.github.com/search/commits?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.cloak-preview")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var body struct {
		Items []CommitSearchResult `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	var jobs []CommitJob
	for _, item := range body.Items {
		if item.SHA == "" || item.Repo.FullName == "" {
			continue
		}
		key := item.Repo.FullName + "@" + item.SHA
		if _, loaded := m.seenCommits.LoadOrStore(key, struct{}{}); loaded {
			continue
		}
		jobs = append(jobs, CommitJob{
			Repo:      item.Repo.FullName,
			CommitSHA: item.SHA,
		})
	}

	return jobs, nil
}
