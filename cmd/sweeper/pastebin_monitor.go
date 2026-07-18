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

type PastebinMonitor struct {
	client *http.Client
	seen   sync.Map
}

func NewPastebinMonitor() *PastebinMonitor {
	return &PastebinMonitor{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type pastebinEntry struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Size      string `json:"size"`
	Date      string `json:"date"`
	Expire    string `json:"expire"`
	URL       string `json:"url"`
	ScrapeURL string `json:"scrape_url"`
}

func (m *PastebinMonitor) Run(ctx context.Context, foundOut chan<- FoundKey) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[pastebin] FATAL: monitor panicked: %v", r)
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	heartbeat := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pastes, err := m.fetchRecent(ctx)
			if err != nil {
				logger.Printf("[pastebin] fetch error: %v", err)
				select {
				case <-time.After(30 * time.Second):
				case <-ctx.Done():
				}
				continue
			}

			for _, p := range pastes {
				if _, loaded := m.seen.LoadOrStore(p.Key, struct{}{}); loaded {
					continue
				}

				content, err := m.fetchContent(ctx, p.ScrapeURL)
				if err != nil {
					continue
				}

				keys := ExtractKeys(ctx, content, fmt.Sprintf("pastebin:%s", p.Key), p.Key, false)
				for _, k := range keys {
					select {
					case foundOut <- k:
					case <-ctx.Done():
						return
					}
				}

				select {
				case <-ctx.Done():
					return
				default:
				}
			}

			if time.Since(heartbeat) > 5*time.Minute {
				logger.Printf("[pastebin] heartbeat: alive, scanned %d pastes, %d seen", len(pastes), syncMapLen(&m.seen))
				heartbeat = time.Now()
			}
		}
	}
}

func (m *PastebinMonitor) fetchRecent(ctx context.Context) ([]pastebinEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://scrape.pastebin.com/api_scraping.php?limit=250", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var entries []pastebinEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (m *PastebinMonitor) fetchContent(ctx context.Context, scrapeURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scrapeURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return string(body), nil
}


