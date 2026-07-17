package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa_decred "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SweepETH moves all ETH from the private key to destAddress.
func SweepETH(ctx context.Context, privHex, destAddress, nodeURL string) (string, error) {
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

	nonce, err := ethGetNonce(ctx, from, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}
	gasPrice, err := ethGasPrice(ctx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("gas price: %w", err)
	}
	balance, err := ethGetBalanceRaw(ctx, from, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get balance: %w", err)
	}

	const gasLimit = uint64(21000)
	gasCost := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasLimit))
	value := new(big.Int).Sub(balance, gasCost)
	if value.Sign() <= 0 {
		return "", errors.New("insufficient balance to cover gas")
	}

	const chainID = int64(1) // mainnet
	rawTx, err := buildAndSignEthTx(privKey, nonce, gasPrice, gasLimit, destAddress, value, chainID)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}

	txHash, err := ethSendRaw(ctx, rawTx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txHash, nil
}

// keccakAddress returns the 20-byte ETH address hex from a 64-byte uncompressed public key (no prefix).
func keccakAddress(pubBytes64 []byte) string {
	hash := keccak256Hash(pubBytes64)
	return hex.EncodeToString(hash[12:])
}

// ---- RPC helpers ----

func ethRPC(ctx context.Context, nodeURL, method string, params []interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1,
		"method": method, "params": params,
	})
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &rpc); err != nil {
		return nil, fmt.Errorf("decode: %w; body: %s", err, raw)
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("RPC %s: %s", method, rpc.Error.Message)
	}
	return rpc.Result, nil
}

func ethGetNonce(ctx context.Context, address, nodeURL string) (uint64, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_getTransactionCount", []interface{}{address, "latest"})
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

func ethGasPrice(ctx context.Context, nodeURL string) (*big.Int, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, err
	}
	var hexPrice string
	if err := json.Unmarshal(result, &hexPrice); err != nil {
		return nil, err
	}
	p, ok := new(big.Int).SetString(strings.TrimPrefix(hexPrice, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad gas price: %s", hexPrice)
	}
	return p, nil
}

func ethGetBalanceRaw(ctx context.Context, address, nodeURL string) (*big.Int, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_getBalance", []interface{}{address, "latest"})
	if err != nil {
		return nil, err
	}
	var hexBal string
	if err := json.Unmarshal(result, &hexBal); err != nil {
		return nil, err
	}
	b, ok := new(big.Int).SetString(strings.TrimPrefix(hexBal, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad balance: %s", hexBal)
	}
	return b, nil
}

func ethSendRaw(ctx context.Context, rawTx []byte, nodeURL string) (string, error) {
	result, err := ethRPC(ctx, nodeURL, "eth_sendRawTransaction",
		[]interface{}{"0x" + hex.EncodeToString(rawTx)})
	if err != nil {
		return "", err
	}
	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", err
	}
	return txHash, nil
}

// ---- Transaction signing (EIP-155 legacy, RLP-encoded) ----

func buildAndSignEthTx(
	privKey *secp.PrivateKey,
	nonce uint64,
	gasPrice *big.Int,
	gasLimit uint64,
	to string,
	value *big.Int,
	chainID int64,
) ([]byte, error) {
	toBytes, err := hex.DecodeString(strings.TrimPrefix(to, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid to address: %w", err)
	}
	if len(toBytes) != 20 {
		return nil, errors.New("to address must be 20 bytes")
	}

	// EIP-155 signing hash: keccak256(RLP([nonce, gasPrice, gas, to, value, data, chainID, 0, 0]))
	unsigned := rlpList(
		rlpUint(nonce),
		rlpBigInt(gasPrice),
		rlpUint(gasLimit),
		rlpBytes(toBytes),
		rlpBigInt(value),
		rlpBytes(nil),               // data empty
		rlpBigInt(big.NewInt(chainID)), // chainID
		rlpBytes(nil),               // v = 0
		rlpBytes(nil),               // r = 0
	)
	hash := keccak256Hash(unsigned)

	// Sign using decred's secp256k1 — gives us a compact 65-byte signature with recovery ID.
	sig := ecdsa_decred.SignCompact(privKey, hash, false)
	// SignCompact format: [recoveryID+27 (1 byte)] [R (32 bytes)] [S (32 bytes)]
	recoveryID := int64(sig[0] - 27)
	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:65])
	// EIP-155: v = recoveryID + chainID*2 + 35
	v := big.NewInt(recoveryID + chainID*2 + 35)

	signed := rlpList(
		rlpUint(nonce),
		rlpBigInt(gasPrice),
		rlpUint(gasLimit),
		rlpBytes(toBytes),
		rlpBigInt(value),
		rlpBytes(nil),
		rlpBigInt(v),
		rlpBigInt(r),
		rlpBigInt(s),
	)
	return signed, nil
}

// ---- Minimal RLP encoder ----

func rlpUint(n uint64) []byte {
	return rlpBigInt(new(big.Int).SetUint64(n))
}

func rlpBigInt(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return rlpBytes(nil)
	}
	return rlpBytes(n.Bytes())
}

func rlpBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0x80}
	}
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	prefix := rlpLength(len(b), 0x80)
	return append(prefix, b...)
}

func rlpList(items ...[]byte) []byte {
	var payload []byte
	for _, item := range items {
		payload = append(payload, item...)
	}
	prefix := rlpLength(len(payload), 0xC0)
	return append(prefix, payload...)
}

func rlpLength(length int, offset byte) []byte {
	if length < 56 {
		return []byte{offset + byte(length)}
	}
	lenBytes := rlpBigEndianBytes(uint64(length))
	return append([]byte{offset + 55 + byte(len(lenBytes))}, lenBytes...)
}

func rlpBigEndianBytes(n uint64) []byte {
	var buf [8]byte
	i := 7
	for n > 0 {
		buf[i] = byte(n)
		n >>= 8
		i--
	}
	return buf[i+1:]
}

// hexToPrivBytes strips optional 0x prefix and returns 32 bytes.
func hexToPrivBytes(h string) ([]byte, error) {
	h = strings.TrimPrefix(h, "0x")
	h = strings.TrimPrefix(h, "0X")
	if len(h) != 64 {
		return nil, fmt.Errorf("expected 64 hex chars, got %d", len(h))
	}
	return hex.DecodeString(h)
}
