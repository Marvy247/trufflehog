package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GitLabMonitor struct {
	token  string
	client *http.Client
	seen   sync.Map
}

func NewGitLabMonitor(token string) *GitLabMonitor {
	return &GitLabMonitor{
		token: token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type gitLabBlobResult struct {
	ProjectID int    `json:"project_id"`
	Path      string `json:"path"`
	Ref       string `json:"ref"`
	Data      string `json:"data"`
	WebURL    string `json:"web_url"`
}

var gitLabSearchQueries = []string{
	"0x" + " PRIVATE KEY",
	`"BEGIN EC PRIVATE KEY"`,
	`"BEGIN RSA PRIVATE KEY"`,
	"mnemonic phrase",
	"seed phrase",
	"secret recovery phrase",
	"private_key",
	"wallet private key",
	"keystore password",
	"sui private key",
	"solana private key",
	"stellar secret key",
}

func (m *GitLabMonitor) Run(ctx context.Context, foundOut chan<- FoundKey) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[gitlab] FATAL: monitor panicked: %v", r)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var queryIdx int
	heartbeat := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q := gitLabSearchQueries[queryIdx%len(gitLabSearchQueries)]
			queryIdx++

			results, err := m.searchBlobs(ctx, q)
			if err != nil {
				logger.Printf("[gitlab] search %q error: %v", q, err)
				select {
				case <-time.After(30 * time.Second):
				case <-ctx.Done():
				}
				continue
			}

			for _, r := range results {
				key := fmt.Sprintf("%d/%s@%s", r.ProjectID, r.Path, r.Ref)
				if _, loaded := m.seen.LoadOrStore(key, struct{}{}); loaded {
					continue
				}

				content, err := m.fetchRaw(ctx, r.ProjectID, r.Path, r.Ref)
				if err != nil {
					continue
				}

				projectName := fmt.Sprintf("gitlab:project/%d", r.ProjectID)
				keys := ExtractKeys(ctx, content, projectName, r.Ref, false)
				for _, k := range keys {
					select {
					case foundOut <- k:
					case <-ctx.Done():
						return
					}
				}
			}

			if time.Since(heartbeat) > 5*time.Minute {
				logger.Printf("[gitlab] heartbeat: alive, scanned blobs for %q", q)
				heartbeat = time.Now()
			}
		}
	}
}

func (m *GitLabMonitor) searchBlobs(ctx context.Context, query string) ([]gitLabBlobResult, error) {
	u := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=50", urlQueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if m.token != "" {
		req.Header.Set("PRIVATE-TOKEN", m.token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("rate limited (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var results []gitLabBlobResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	return results, nil
}

func (m *GitLabMonitor) fetchRaw(ctx context.Context, projectID int, path, ref string) (string, error) {
	u := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s",
		projectID, urlQueryEscape(path), urlQueryEscape(ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if m.token != "" {
		req.Header.Set("PRIVATE-TOKEN", m.token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body), nil
}

func urlQueryEscape(s string) string {
	hexChars := "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(hexChars[c>>4])
			out.WriteByte(hexChars[c&0x0f])
		}
	}
	return out.String()
}
