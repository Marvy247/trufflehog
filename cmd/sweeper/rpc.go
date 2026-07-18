package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var ethFallbackURLs = []string{
	"https://cloudflare-eth.com",
	"https://1rpc.io/eth",
	"https://ethereum.publicnode.com",
	"https://rpc.ankr.com/eth",
}

var solFallbackURLs = []string{
	"https://api.mainnet-beta.solana.com",
	"https://solana-api.projectserum.com",
	"https://rpc.ankr.com/solana",
}

var suiFallbackURLs = []string{
	"https://fullnode.mainnet.sui.io",
	"https://sui-rpc.publicnode.com",
	"https://rpc.ankr.com/sui",
}

func tryETHBalance(ctx context.Context, address string, preferredURL string) (*big.Int, string, error) {
	urls := ethFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, ethFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		bal, err := ethGetBalanceRaw(shortCtx, address, url)
		cancel()
		if err == nil {
			return bal, url, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

func tryETHGasPrice(ctx context.Context, preferredURL string) (*big.Int, error) {
	urls := ethFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, ethFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		gp, err := ethGasPrice(shortCtx, url)
		cancel()
		if err == nil {
			return gp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func tryETHNonce(ctx context.Context, address string, preferredURL string, tag string) (uint64, error) {
	urls := ethFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, ethFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var nonce uint64
		var err error
		if tag == "pending" {
			nonce, err = ethGetNoncePending(shortCtx, address, url)
		} else {
			nonce, err = ethGetNonce(shortCtx, address, url)
		}
		cancel()
		if err == nil {
			return nonce, nil
		}
		lastErr = err
	}
	return 0, lastErr
}

func tryETHBroadcast(ctx context.Context, rawTx []byte, preferredURL string) (string, error) {
	urls := ethFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, ethFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		txHash, err := ethSendRaw(shortCtx, rawTx, url)
		cancel()
		if err == nil {
			return txHash, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func tryERC20Balance(ctx context.Context, address, tokenAddr, preferredURL string) (*big.Int, error) {
	urls := ethFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, ethFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	data := erc20BalanceCallData(address)
	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		raw, err := erc20Call(shortCtx, tokenAddr, data, url)
		cancel()
		if err == nil {
			bal := new(big.Int).SetBytes(raw)
			return bal, nil
		}
		lastErr = err
	}
	return big.NewInt(0), lastErr
}

func trySOLBalance(ctx context.Context, address string, preferredURL string) (uint64, error) {
	urls := solFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, solFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		bal, err := solGetBalanceFallback(shortCtx, address, url)
		cancel()
		if err == nil {
			return bal, nil
		}
		lastErr = err
	}
	return 0, lastErr
}

func trySUIBalance(ctx context.Context, address string, preferredURL string) (*big.Int, error) {
	urls := suiFallbackURLs
	if preferredURL != "" {
		urls = append([]string{preferredURL}, suiFallbackURLs...)
	}
	urls = dedupeURLs(urls)

	var lastErr error
	for _, url := range urls {
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		bal, err := suiGetBalanceFallback(shortCtx, address, url)
		cancel()
		if err == nil {
			return bal, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func solGetBalanceFallback(ctx context.Context, address, nodeURL string) (uint64, error) {
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["%s"]}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result struct {
			Value uint64 `json:"value"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return 0, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result.Value, nil
}

func suiGetBalanceFallback(ctx context.Context, address, nodeURL string) (*big.Int, error) {
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"suix_getBalance","params":["%s","0x2::sui::SUI"]}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result struct {
			TotalBalance string `json:"totalBalance"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	mist, ok := new(big.Int).SetString(rpcResp.Result.TotalBalance, 10)
	if !ok {
		return nil, fmt.Errorf("invalid SUI balance: %q", rpcResp.Result.TotalBalance)
	}
	return mist, nil
}

func dedupeURLs(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func getActiveETHURL(preferredURL string) string {
	if preferredURL != "" {
		for _, u := range ethFallbackURLs {
			if u == preferredURL {
				return preferredURL
			}
		}
	}
	return ethFallbackURLs[0]
}

func getActiveSOLURL(preferredURL string) string {
	if preferredURL != "" {
		for _, u := range solFallbackURLs {
			if u == preferredURL {
				return preferredURL
			}
		}
	}
	return solFallbackURLs[0]
}

func getActiveSUIURL(preferredURL string) string {
	if preferredURL != "" {
		for _, u := range suiFallbackURLs {
			if u == preferredURL {
				return preferredURL
			}
		}
	}
	return suiFallbackURLs[0]
}
