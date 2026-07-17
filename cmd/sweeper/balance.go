package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// BalanceResult holds the balance of a single address.
type BalanceResult struct {
	Chain   string
	Address string
	// Balance in smallest unit (wei for ETH, satoshi for BTC, lamports for SOL).
	Balance *big.Int
	// BalanceHuman is a human-readable string like "0.00123 ETH".
	BalanceHuman string
	HasFunds     bool
}

var balanceHTTPClient = &http.Client{Timeout: 20 * time.Second}

// CheckBalances queries the balance for every non-empty address in addrs.
func CheckBalances(ctx context.Context, addrs DerivedAddresses, cfg *Config) ([]BalanceResult, error) {
	var results []BalanceResult

	if addrs.ETH != "" {
		r, err := checkETHBalance(ctx, addrs.ETH, cfg.ETHNodeURL)
		if err != nil {
			logger.Printf("[balance] ETH error for %s: %v", addrs.ETH, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.BTC != "" {
		r, err := checkBTCBalance(ctx, addrs.BTC)
		if err != nil {
			logger.Printf("[balance] BTC error for %s: %v", addrs.BTC, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.DOGE != "" {
		r, err := checkDOGEBalance(ctx, addrs.DOGE)
		if err != nil {
			logger.Printf("[balance] DOGE error for %s: %v", addrs.DOGE, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.LTC != "" {
		r, err := checkLTCBalance(ctx, addrs.LTC)
		if err != nil {
			logger.Printf("[balance] LTC error for %s: %v", addrs.LTC, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.STX != "" {
		r, err := checkSTXBalance(ctx, addrs.STX)
		if err != nil {
			logger.Printf("[balance] STX error for %s: %v", addrs.STX, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.Sui != "" {
		r, err := checkSuiBalance(ctx, addrs.Sui, cfg.SuiNodeURL)
		if err != nil {
			logger.Printf("[balance] Sui error for %s: %v", addrs.Sui, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.XLM != "" {
		r, err := checkXLMBalance(ctx, addrs.XLM)
		if err != nil {
			logger.Printf("[balance] XLM error for %s: %v", addrs.XLM, err)
		} else {
			results = append(results, r)
		}
	}

	if addrs.Solana != "" {
		r, err := checkSolanaBalance(ctx, addrs.Solana, cfg.SolanaNodeURL)
		if err != nil {
			logger.Printf("[balance] Solana error for %s: %v", addrs.Solana, err)
		} else {
			results = append(results, r)
		}
	}

	return results, nil
}

// ---- Dogecoin (BlockCypher API) ----

func checkDOGEBalance(ctx context.Context, address string) (BalanceResult, error) {
	url := "https://api.blockcypher.com/v1/doge/main/addrs/" + address + "/balance"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BalanceResult{}, err
	}
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		Balance uint64 `json:"balance"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	dogeVal, _ := new(big.Float).Quo(
		new(big.Float).SetUint64(result.Balance),
		new(big.Float).SetFloat64(1e8),
	).Float64()

	return BalanceResult{
		Chain:        "Dogecoin",
		Address:      address,
		Balance:      new(big.Int).SetUint64(result.Balance),
		BalanceHuman: fmt.Sprintf("%.8f DOGE", dogeVal),
		HasFunds:     result.Balance > 0,
	}, nil
}

// ---- Litecoin (BlockCypher API) ----

func checkLTCBalance(ctx context.Context, address string) (BalanceResult, error) {
	url := "https://api.blockcypher.com/v1/ltc/main/addrs/" + address + "/balance"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BalanceResult{}, err
	}
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		Balance uint64 `json:"balance"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	ltcVal, _ := new(big.Float).Quo(
		new(big.Float).SetUint64(result.Balance),
		new(big.Float).SetFloat64(1e8),
	).Float64()

	return BalanceResult{
		Chain:        "Litecoin",
		Address:      address,
		Balance:      new(big.Int).SetUint64(result.Balance),
		BalanceHuman: fmt.Sprintf("%.8f LTC", ltcVal),
		HasFunds:     result.Balance > 0,
	}, nil
}

// ---- Stacks (Hiro API) ----

func checkSTXBalance(ctx context.Context, address string) (BalanceResult, error) {
	url := "https://api.hiro.so/extended/v1/address/" + address + "/balances"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BalanceResult{}, err
	}
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		STX struct {
			Balance string `json:"balance"` // microSTX as string
		} `json:"stx"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	microSTX, ok := new(big.Int).SetString(result.STX.Balance, 10)
	if !ok {
		return BalanceResult{}, fmt.Errorf("invalid STX balance: %q", result.STX.Balance)
	}
	stxVal, _ := new(big.Float).Quo(
		new(big.Float).SetInt(microSTX),
		new(big.Float).SetFloat64(1e6),
	).Float64()

	return BalanceResult{
		Chain:        "Stacks",
		Address:      address,
		Balance:      microSTX,
		BalanceHuman: fmt.Sprintf("%.6f STX", stxVal),
		HasFunds:     microSTX.Sign() > 0,
	}, nil
}

// ---- Sui (Sui RPC) ----

func checkSuiBalance(ctx context.Context, address, nodeURL string) (BalanceResult, error) {
	if nodeURL == "" {
		nodeURL = "https://fullnode.mainnet.sui.io"
	}
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"suix_getBalance","params":["%s","0x2::sui::SUI"]}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return BalanceResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result struct {
			TotalBalance string `json:"totalBalance"` // MIST as string
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return BalanceResult{}, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	mist, ok := new(big.Int).SetString(rpcResp.Result.TotalBalance, 10)
	if !ok {
		return BalanceResult{}, fmt.Errorf("invalid SUI balance: %q", rpcResp.Result.TotalBalance)
	}
	suiVal, _ := new(big.Float).Quo(
		new(big.Float).SetInt(mist),
		new(big.Float).SetFloat64(1e9),
	).Float64()

	return BalanceResult{
		Chain:        "Sui",
		Address:      address,
		Balance:      mist,
		BalanceHuman: fmt.Sprintf("%.9f SUI", suiVal),
		HasFunds:     mist.Sign() > 0,
	}, nil
}

// ---- Stellar (Horizon API) ----

func checkXLMBalance(ctx context.Context, address string) (BalanceResult, error) {
	url := "https://horizon.stellar.org/accounts/" + address
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BalanceResult{}, err
	}
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

	var result struct {
		Balances []struct {
			Balance    string `json:"balance"`
			AssetType  string `json:"asset_type"`
		} `json:"balances"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	var xlmBalance string
	for _, b := range result.Balances {
		if b.AssetType == "native" {
			xlmBalance = b.Balance
			break
		}
	}
	if xlmBalance == "" {
		return BalanceResult{}, errors.New("no native XLM balance found")
	}
	// XLM balances are decimal strings like "1000.0000000"
	xlmVal, err := parseDecimalStr(xlmBalance)
	if err != nil {
		return BalanceResult{}, err
	}
	return BalanceResult{
		Chain:        "Stellar",
		Address:      address,
		Balance:      xlmVal,
		BalanceHuman: fmt.Sprintf("%.7f XLM", float64(xlmVal.Int64())/1e7),
		HasFunds:     xlmVal.Sign() > 0,
	}, nil
}

func parseDecimalStr(s string) (*big.Int, error) {
	parts := strings.SplitN(s, ".", 2)
	intPart := parts[0]
	fracPart := ""
	if len(parts) == 2 {
		fracPart = parts[1]
	}
	// Pad/truncate to 7 decimal places (Stellar uses 7-digit precision).
	if len(fracPart) > 7 {
		fracPart = fracPart[:7]
	}
	fracPart = fmt.Sprintf("%-7s", fracPart)
	fracPart = strings.ReplaceAll(fracPart, " ", "0")
	combined := intPart + fracPart
	val, ok := new(big.Int).SetString(combined, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal: %q", s)
	}
	return val, nil
}

// ---- Ethereum (eth_getBalance via JSON-RPC) ----

func checkETHBalance(ctx context.Context, address, nodeURL string) (BalanceResult, error) {
	if nodeURL == "" {
		nodeURL = "https://cloudflare-eth.com" // free public node
	}

	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","method":"eth_getBalance","params":["%s","latest"],"id":1}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL,
		strings.NewReader(payload))
	if err != nil {
		return BalanceResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return BalanceResult{}, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// Result is hex wei, e.g. "0x38d7ea4c68000"
	weiHex := strings.TrimPrefix(rpcResp.Result, "0x")
	if weiHex == "" {
		weiHex = "0"
	}
	wei, ok := new(big.Int).SetString(weiHex, 16)
	if !ok {
		return BalanceResult{}, fmt.Errorf("invalid wei hex: %q", rpcResp.Result)
	}

	// Convert to ETH (1 ETH = 1e18 wei).
	ethVal := new(big.Float).Quo(
		new(big.Float).SetInt(wei),
		new(big.Float).SetFloat64(1e18),
	)
	human, _ := ethVal.Float64()

	return BalanceResult{
		Chain:        "Ethereum",
		Address:      address,
		Balance:      wei,
		BalanceHuman: fmt.Sprintf("%.8f ETH", human),
		HasFunds:     wei.Sign() > 0,
	}, nil
}

// ---- Bitcoin (blockchain.info API) ----

func checkBTCBalance(ctx context.Context, address string) (BalanceResult, error) {
	url := "https://blockchain.info/q/addressbalance/" + address + "?confirmations=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BalanceResult{}, err
	}
	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))

	satStr := strings.TrimSpace(string(body))
	sat, ok := new(big.Int).SetString(satStr, 10)
	if !ok {
		return BalanceResult{}, fmt.Errorf("invalid satoshi response: %q", satStr)
	}

	btcVal, _ := new(big.Float).Quo(
		new(big.Float).SetInt(sat),
		new(big.Float).SetFloat64(1e8),
	).Float64()

	return BalanceResult{
		Chain:        "Bitcoin",
		Address:      address,
		Balance:      sat,
		BalanceHuman: fmt.Sprintf("%.8f BTC", btcVal),
		HasFunds:     sat.Sign() > 0,
	}, nil
}

// ---- Solana (getBalance via JSON-RPC) ----

func checkSolanaBalance(ctx context.Context, address, nodeURL string) (BalanceResult, error) {
	if nodeURL == "" {
		nodeURL = "https://api.mainnet-beta.solana.com"
	}

	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["%s"]}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL,
		strings.NewReader(payload))
	if err != nil {
		return BalanceResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := balanceHTTPClient.Do(req)
	if err != nil {
		return BalanceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result struct {
			Value uint64 `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return BalanceResult{}, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return BalanceResult{}, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	lamports := big.NewInt(int64(rpcResp.Result.Value))
	solVal, _ := new(big.Float).Quo(
		new(big.Float).SetUint64(rpcResp.Result.Value),
		new(big.Float).SetFloat64(1e9),
	).Float64()

	return BalanceResult{
		Chain:        "Solana",
		Address:      address,
		Balance:      lamports,
		BalanceHuman: fmt.Sprintf("%.9f SOL", solVal),
		HasFunds:     lamports.Sign() > 0,
	}, nil
}


