package main

import (
	"context"
	"encoding/binary"
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
	ecdsa_d "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func SweepSTX(ctx context.Context, privRaw, destAddress string) (string, error) {
	privBytes, err := rawToPrivBytes(privRaw)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pubKey := privKey.PubKey().SerializeCompressed()

	fromAddress, err := DeriveSTXAddress(privRaw)
	if err != nil {
		return "", fmt.Errorf("derive address: %w", err)
	}

	nonce, err := stxGetNonce(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	balance, err := stxGetBalance(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("get balance: %w", err)
	}

	// Reserve 540 microSTX for the tx fee (standard for simple token transfers).
	const fee = uint64(540)
	if balance <= fee {
		return "", fmt.Errorf("balance %d microSTX too low to cover fee %d", balance, fee)
	}
	amount := balance - fee

	destBytes, err := stxAddrToBytes(destAddress)
	if err != nil {
		return "", fmt.Errorf("parse dest address: %w", err)
	}

	rawTx, err := buildSTXTx(privKey, pubKey, nonce, destBytes, amount)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	txID, err := stxBroadcast(ctx, rawTx)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txID, nil
}

func stxGetNonce(ctx context.Context, address string) (uint64, error) {
	url := "https://api.hiro.so/extended/v1/address/" + address + "/nonces"
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		LastExecutedTxNonce *uint64 `json:"last_executed_tx_nonce"`
		PossibleNextNonce   uint64  `json:"possible_next_nonce"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if result.LastExecutedTxNonce != nil {
		return *result.LastExecutedTxNonce + 1, nil
	}
	return result.PossibleNextNonce, nil
}

func stxGetBalance(ctx context.Context, address string) (uint64, error) {
	url := "https://api.hiro.so/extended/v1/address/" + address + "/balances"
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		STX struct {
			Balance string `json:"balance"`
		} `json:"stx"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	bal, ok := new(big.Int).SetString(result.STX.Balance, 10)
	if !ok {
		return 0, fmt.Errorf("invalid STX balance: %q", result.STX.Balance)
	}
	return bal.Uint64(), nil
}

// stxAddrToBytes decodes a Stacks SP... address to [version(1) + hash160(20)].
func stxAddrToBytes(addr string) ([]byte, error) {
	if !strings.HasPrefix(addr, "SP") {
		return nil, fmt.Errorf("invalid Stacks address prefix: %s", addr)
	}
	decoded := c32Decode(addr[2:])
	if len(decoded) < 25 {
		return nil, errors.New("invalid Stacks address length")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	h := doubleSHA256(payload)
	for i, b := range checksum {
		if h[i] != b {
			return nil, errors.New("invalid Stacks address checksum")
		}
	}
	return payload, nil // [version(1) + hash160(20)]
}

func c32Decode(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	lookup := make(map[byte]byte, 32)
	for i := 0; i < len(c32Alphabet); i++ {
		lookup[c32Alphabet[i]] = byte(i)
	}
	var zeroes int
	for zeroes < len(s) && s[zeroes] == '0' {
		zeroes++
	}
	val := new(big.Int)
	for _, c := range []byte(s[zeroes:]) {
		v, ok := lookup[c]
		if !ok {
			return nil
		}
		val.Mul(val, big.NewInt(32))
		val.Add(val, big.NewInt(int64(v)))
	}
	decoded := val.Bytes()
	result := make([]byte, zeroes+len(decoded))
	copy(result[zeroes:], decoded)
	return result
}

func buildSTXTx(privKey *secp.PrivateKey, pubKey []byte, nonce uint64, destAddrBytes []byte, amount uint64) ([]byte, error) {
	memo := []byte("swept by trufflehog-sweeper")
	memoLen := uint32(len(memo))

	var buf []byte
	// Version + chain ID
	buf = append(buf, 0x00)                         // version (mainnet)
	buf = append(buf, 0x01, 0x00, 0x00, 0x00)       // chain ID (mainnet, LE)

	// Auth type: 0x04 (standard) + 0x00 (no signatures)
	buf = append(buf, 0x04, 0x00)

	// Origin condition
	buf = append(buf, 0x00)      // hash mode: none
	buf = append(buf, pubKey...) // signer: compressed public key

	// Dummy signature for hash computation (will be replaced)
	dummySig := make([]byte, 66) // 0x09 + 65 bytes
	buf = append(buf, 0x09)      // compressed signature type
	buf = append(buf, dummySig...)

	// Anchor mode: 0x03 (on-chain)
	buf = append(buf, 0x03)

	// Post condition mode: 0x01 (allow)
	buf = append(buf, 0x01)

	// Post conditions: none
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // length prefix 0

	// Payload type: token transfer
	buf = append(buf, 0x00)

	// Recipient address
	buf = append(buf, destAddrBytes...) // [version(1) + hash160(20)]

	// Amount (8 bytes, big-endian)
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, amount)
	buf = append(buf, amountBytes...)

	// Memo length (4 bytes, BE)
	memoLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoLenBytes, memoLen)
	buf = append(buf, memoLenBytes...)
	buf = append(buf, memo...) // memo data

	// Nonce (8 bytes, big-endian) appended to tx for signing
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	buf = append(buf, nonceBytes...)

	// Sign: doubleSHA256 of the tx buffer
	txHash := doubleSHA256(buf)
	sig := ecdsa_d.SignCompact(privKey, txHash, false)
	// SignCompact returns [recID+27][R(32)][S(32)] — Stacks expects [R(32)][S(32)][recID]
	stxSig := make([]byte, 65)
	recID := sig[0] - 27
	copy(stxSig[0:32], sig[1:33])   // R
	copy(stxSig[32:64], sig[33:65]) // S
	stxSig[64] = recID              // recovery ID

	// Build final tx with real signature
	var final []byte
	final = append(final, 0x00)                   // version
	final = append(final, 0x01, 0x00, 0x00, 0x00) // chain ID
	final = append(final, 0x04, 0x00)             // auth type
	final = append(final, 0x00)                  // hash mode
	final = append(final, pubKey...)             // signer

	// Real signature (Stacks format: R(32) + S(32) + recID(1))
	final = append(final, 0x09) // compressed
	final = append(final, stxSig...) // 65 bytes

	final = append(final, 0x03) // anchor mode
	final = append(final, 0x01) // post condition mode
	final = append(final, 0x00, 0x00, 0x00, 0x00) // no post conditions
	final = append(final, 0x00) // token transfer payload
	final = append(final, destAddrBytes...)
	final = append(final, amountBytes...)
	final = append(final, memoLenBytes...)
	final = append(final, memo...)

	return final, nil
}

func stxBroadcast(ctx context.Context, rawTx []byte) (string, error) {
	txHex := hex.EncodeToString(rawTx)
	body, _ := json.Marshal(map[string]string{"tx": txHex})
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.hiro.so/v2/transactions",
		strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("broadcast HTTP %d: %s", resp.StatusCode, respBody)
	}
	var result struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	return result.TxID, nil
}
