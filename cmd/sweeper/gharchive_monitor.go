package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var archiveSuspiciousKeywords = []string{
	"private key",
	"private_key",
	"mnemonic",
	"seed phrase",
	"secret phrase",
	"secret recovery phrase",
	"keystore",
	"bip39",
	"wallet.dat",
	"id.json",
	"xprv",
	"tprv",
}

func msgMatchesKeywords(msg string) bool {
	lower := strings.ToLower(msg)
	for _, kw := range archiveSuspiciousKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

type archiveEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Repo    struct {
		Name string `json:"name"`
	} `json:"repo"`
	Payload json.RawMessage `json:"payload"`
}

type archivePushPayload struct {
	Ref     string `json:"ref"`
	Commits []struct {
		SHA     string `json:"id"`
		Message string `json:"message"`
	} `json:"commits"`
}

type GHArchiveScanner struct {
	client *http.Client
	seen   sync.Map
}

func NewGHArchiveScanner() *GHArchiveScanner {
	return &GHArchiveScanner{
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (s *GHArchiveScanner) RunHistoricalScan(ctx context.Context, out chan<- CommitJob, from, to time.Time) {
	now := time.Now().UTC()
	if to.After(now) {
		to = now
	}
	if from.After(to) {
		logger.Printf("[gharchive] from date %s is after to date %s, nothing to do", from.Format(time.RFC3339), to.Format(time.RFC3339))
		return
	}

	logger.Printf("[gharchive] scanning %s to %s", from.Format("2006-01-02"), to.Format("2006-01-02"))
	totalMatched := int64(0)
	totalHours := int64(0)
	lastLog := time.Now()

	for t := from; t.Before(to) || t.Equal(to); t = t.Add(time.Hour) {
		select {
		case <-ctx.Done():
			logger.Printf("[gharchive] cancelled at %s: %d hours, %d matched",
				t.Format(time.RFC3339), totalHours, totalMatched)
			return
		default:
		}

		// GH Archive lags ~3 hours behind real time.
		if t.After(now.Add(-3 * time.Hour)) {
			break
		}

		url := fmt.Sprintf("https://data.gharchive.org/%s.json.gz", t.Format("2006-01-02-15"))
		n, err := s.processFile(ctx, url, out)
		if err != nil {
			logger.Printf("[gharchive] error %s: %v", t.Format("2006-01-02-15"), err)
		}
		totalMatched += n
		totalHours++

		if time.Since(lastLog) > 30*time.Second || totalHours%24 == 0 {
			logger.Printf("[gharchive] progress: %d hours, %d matched", totalHours, totalMatched)
			lastLog = time.Now()
		}
	}

	logger.Printf("[gharchive] DONE: %d hours scanned, %d matched (unique)", totalHours, totalMatched)
}

func (s *GHArchiveScanner) processFile(ctx context.Context, url string, out chan<- CommitJob) (int64, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 1<<20), 10<<20)

	matched := int64(0)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev archiveEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.Type != "PushEvent" {
			continue
		}

		var payload archivePushPayload
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			continue
		}

		for _, c := range payload.Commits {
			if c.SHA == "" || ev.Repo.Name == "" {
				continue
			}
			if !msgMatchesKeywords(c.Message) {
				continue
			}

			key := ev.Repo.Name + "@" + c.SHA
			if _, loaded := s.seen.LoadOrStore(key, struct{}{}); loaded {
				continue
			}
			matched++

			select {
			case out <- CommitJob{Repo: ev.Repo.Name, CommitSHA: c.SHA, Ref: payload.Ref}:
			case <-ctx.Done():
				return matched, ctx.Err()
			}
		}
	}

	return matched, scanner.Err()
}
