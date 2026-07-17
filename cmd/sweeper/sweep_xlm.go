package main

import (
	"context"
	stdEd25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

func SweepXLM(ctx context.Context, privBase58, destAddress string) (string, error) {
	decoded, ok := decodeBase58BTC(privBase58)
	if !ok {
		return "", errors.New("invalid base58 private key")
	}
	var seed []byte
	switch len(decoded) {
	case 32:
		seed = decoded
	case 64:
		seed = decoded[:32]
	default:
		return "", fmt.Errorf("unexpected key length: %d", len(decoded))
	}

	privKey := stdEd25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(stdEd25519.PublicKey)

	fromAddress := stellarStrKeyEncode(pubKey)

	account, err := xlmGetAccount(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("get account: %w", err)
	}

	var xlmBalance string
	for _, b := range account.Balances {
		if b.AssetType == "native" {
			xlmBalance = b.Balance
			break
		}
	}
	if xlmBalance == "" {
		return "", errors.New("no native XLM balance")
	}

	balVal, err := parseDecimalStr(xlmBalance)
	if err != nil {
		return "", fmt.Errorf("parse balance: %w", err)
	}
	baseFee := uint32(100)
	fee := baseFee

	stroopsU64 := balVal.Uint64()
	feeU64 := uint64(fee)
	if stroopsU64 <= feeU64 {
		return "", fmt.Errorf("balance %d stroops too low to cover fee %d", stroopsU64, feeU64)
	}
	amount := stroopsU64 - feeU64

	destPubKey, err := xlmAddressToPubKey(destAddress)
	if err != nil {
		return "", fmt.Errorf("parse dest address: %w", err)
	}

	seqNum := account.SeqNum + 1

	txEnv, err := buildXLMTx(pubKey, seqNum, fee, destPubKey, amount)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	txHash := xlmTxHash(txEnv.TxBytes)
	sig := stdEd25519.Sign(privKey, txHash)
	hint := pubKey[len(pubKey)-4:]

	txEnvB64 := xlmFinalize(txEnv, sig, hint)

	txID, err := xlmBroadcast(ctx, txEnvB64)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txID, nil
}

type xlmAccount struct {
	Balances []struct {
		Balance   string `json:"balance"`
		AssetType string `json:"asset_type"`
	} `json:"balances"`
	SeqNum int64 `json:"sequence_number,string"`
}

func xlmGetAccount(ctx context.Context, address string) (*xlmAccount, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://horizon.stellar.org/accounts/"+address, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	var acct xlmAccount
	if err := json.Unmarshal(body, &acct); err != nil {
		return nil, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	return &acct, nil
}

func xlmAddressToPubKey(addr string) ([]byte, error) {
	if !strings.HasPrefix(addr, "G") {
		return nil, errors.New("Stellar address must start with G")
	}
	decoded := xlmBase32DecodeStellar(addr)
	if len(decoded) < 35 {
		return nil, errors.New("invalid Stellar address length")
	}
	payload := decoded[:len(decoded)-2]
	checksum := decoded[len(decoded)-2:]
	crc := crc16XModem(payload)
	if byte(crc>>8) != checksum[0] || byte(crc) != checksum[1] {
		return nil, errors.New("invalid Stellar address checksum")
	}
	if payload[0] != 0x30 {
		return nil, fmt.Errorf("unexpected version: 0x%02x", payload[0])
	}
	return payload[1:], nil
}

func xlmBase32DecodeStellar(s string) []byte {
	lookup := make(map[byte]byte, 32)
	for i := 0; i < len(stellarBase32Alphabet); i++ {
		lookup[stellarBase32Alphabet[i]] = byte(i)
	}
	var result []byte
	buf := uint64(0)
	bits := 0
	for _, c := range []byte(s) {
		v, ok := lookup[c]
		if !ok {
			return nil
		}
		buf = (buf << 5) | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			result = append(result, byte(buf>>bits))
			buf &= (1 << bits) - 1
		}
	}
	return result
}

type xdrBuilder struct {
	buf []byte
}

func (x *xdrBuilder) uint32(v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	x.buf = append(x.buf, b...)
}

func (x *xdrBuilder) int64(v int64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	x.buf = append(x.buf, b...)
}

func (x *xdrBuilder) fixedOpaque(data []byte) {
	x.buf = append(x.buf, data...)
	for len(x.buf)%4 != 0 {
		x.buf = append(x.buf, 0x00)
	}
}

func (x *xdrBuilder) opaque(data []byte) {
	x.uint32(uint32(len(data)))
	x.buf = append(x.buf, data...)
	for len(x.buf)%4 != 0 {
		x.buf = append(x.buf, 0x00)
	}
}

func (x *xdrBuilder) optionNone() {
	x.uint32(0)
}

type xlmTx struct {
	TxBytes []byte
}

func buildXLMTx(pubKey []byte, seqNum int64, fee uint32, destPubKey []byte, amount uint64) (*xlmTx, error) {
	var tx xdrBuilder
	tx.uint32(0) // PublicKeyType::PUBLIC_KEY_TYPE_ED25519
	tx.fixedOpaque(pubKey)
	tx.uint32(fee)
	tx.int64(seqNum)
	tx.optionNone() // TimeBounds
	tx.uint32(0)    // Memo none
	tx.uint32(1)    // Operations count

	// Operation
	tx.optionNone() // source account
	tx.uint32(0)    // PAYMENT

	// Payment body: destination
	tx.uint32(0) // PUBLIC_KEY_TYPE_ED25519
	tx.fixedOpaque(destPubKey)

	// Asset: ASSET_TYPE_NATIVE
	tx.uint32(0)

	// Amount (stroops)
	tx.int64(int64(amount))

	// Ext v0
	tx.uint32(0)

	txBytes := make([]byte, len(tx.buf))
	copy(txBytes, tx.buf)

	return &xlmTx{TxBytes: txBytes}, nil
}

func xlmTxHash(txBytes []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte("Stellar Transaction "))
	h.Write(txBytes)
	hash := make([]byte, 32)
	h.Read(hash)
	return hash
}

func xlmFinalize(tx *xlmTx, sig, hint []byte) string {
	var env xdrBuilder
	env.buf = append(env.buf, tx.TxBytes...)
	for len(env.buf)%4 != 0 {
		env.buf = append(env.buf, 0x00)
	}

	// Signatures
	env.uint32(1)
	// Hint
	hint4 := make([]byte, 4)
	copy(hint4, hint)
	env.fixedOpaque(hint4)
	// Signature
	env.opaque(sig)

	return base64.StdEncoding.EncodeToString(env.buf)
}

func xlmBroadcast(ctx context.Context, txB64 string) (string, error) {
	form := url.Values{}
	form.Set("tx", txB64)
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://horizon.stellar.org/transactions",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("broadcast HTTP %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	return result.Hash, nil
}
