package main

import (
	"context"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blockchain"
)

// FoundKey is a validated private key found in a commit diff.
type FoundKey struct {
	Chain     string // "Ethereum", "Bitcoin", "Solana", …
	Raw       string // the raw secret as found
	Repo      string
	CommitSHA string
	Verified  bool   // true if the verify function confirmed activity
}

var blockchainScanner = blockchain.Scanner{}

// ExtractKeys runs the blockchain detector over diff text and returns every
// valid key it finds. When verifyOnline is true, the detector's network
// verification functions are also called (slower but more useful).
func ExtractKeys(ctx context.Context, diff, repo, sha string, verifyOnline bool) []FoundKey {
	results, err := blockchainScanner.FromData(ctx, verifyOnline, []byte(diff))
	if err != nil {
		logger.Printf("[extractor] detector error: %v", err)
		return nil
	}

	var found []FoundKey
	for _, r := range results {
		chain := ""
		if r.ExtraData != nil {
			chain = r.ExtraData["chain"]
		}
		raw := strings.TrimSpace(string(r.Raw))
		if raw == "" {
			continue
		}
		found = append(found, FoundKey{
			Chain:     chain,
			Raw:       raw,
			Repo:      repo,
			CommitSHA: sha,
			Verified:  r.Verified,
		})
	}
	return found
}
