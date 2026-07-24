package main

import (
	"context"
	stdEd25519 "crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SweepSolana sends all SOL (minus fees) from privBase58 to destAddress.
// destAddress must be a base58-encoded Solana public key.
func SweepSolana(ctx context.Context, privBase58, destAddress, nodeURL string) (string, error) {
	if nodeURL == "" {
		nodeURL = "https://api.mainnet-beta.solana.com"
	}

	// Decode private key (32-byte seed or 64-byte keypair).
	decoded, ok := decodeBase58BTC(privBase58)
	if !ok {
		return "", errors.New("invalid base58 private key")
	}

	var privKey stdEd25519.PrivateKey
	switch len(decoded) {
	case 32:
		privKey = stdEd25519.NewKeyFromSeed(decoded)
	case 64:
		privKey = stdEd25519.PrivateKey(decoded)
	default:
		return "", fmt.Errorf("unexpected key length %d", len(decoded))
	}
	pubKey := privKey.Public().(stdEd25519.PublicKey)
	fromAddr := encodeBase58(pubKey)

	// Get balance in lamports.
	lamports, err := solGetBalance(ctx, fromAddr, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get balance: %w", err)
	}

	// Solana fee per signature is 5000 lamports (one signature for a simple transfer).
	const feePerSig = uint64(5000)

	// Get the minimum rent-exempt balance for a 0-byte account.
	rentExempt, err := solGetMinRentExempt(ctx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get rent exempt: %w", err)
	}

	// We must leave at least the rent-exempt minimum in the source account.
	// Available = balance - fee - rentExempt. If negative, skip.
	if lamports < feePerSig+rentExempt {
		return "", fmt.Errorf("balance %d lamports too low: need %d for fee + %d rent-exempt",
			lamports, feePerSig, rentExempt)
	}
	amount := lamports - feePerSig - rentExempt

	// Get recent blockhash (required for transaction construction).
	recentBlockhash, err := solGetRecentBlockhash(ctx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get recent blockhash: %w", err)
	}

	// Decode destination address.
	destPubKey, ok := decodeBase58BTC(destAddress)
	if !ok || len(destPubKey) != 32 {
		return "", errors.New("invalid destination address")
	}

	// Build and sign a SOL transfer transaction.
	rawTx, err := buildSolTransferTx(privKey, pubKey, destPubKey, amount, recentBlockhash)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	// Broadcast.
	sig, err := solSendTransaction(ctx, rawTx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return sig, nil
}

// ---- Solana RPC helpers ----

func solRPC(ctx context.Context, nodeURL, method string, params interface{}) (json.RawMessage, error) {
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

func solGetBalance(ctx context.Context, address, nodeURL string) (uint64, error) {
	result, err := solRPC(ctx, nodeURL, "getBalance", []interface{}{address})
	if err != nil {
		return 0, err
	}
	var resp struct {
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return 0, err
	}
	return resp.Value, nil
}

func solGetMinRentExempt(ctx context.Context, nodeURL string) (uint64, error) {
	result, err := solRPC(ctx, nodeURL, "getMinimumBalanceForRentExemption", []interface{}{0})
	if err != nil {
		return 0, err
	}
	var val uint64
	if err := json.Unmarshal(result, &val); err != nil {
		return 0, err
	}
	return val, nil
}

func solGetRecentBlockhash(ctx context.Context, nodeURL string) ([]byte, error) {
	result, err := solRPC(ctx, nodeURL, "getLatestBlockhash", []interface{}{
		map[string]string{"commitment": "finalized"},
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, err
	}
	decoded, ok := decodeBase58BTC(resp.Value.Blockhash)
	if !ok || len(decoded) != 32 {
		return nil, errors.New("invalid blockhash from RPC")
	}
	return decoded, nil
}

func solSendTransaction(ctx context.Context, rawTx []byte, nodeURL string) (string, error) {
	// Encode as base64.
	encoded := solBase64Encode(rawTx)
	result, err := solRPC(ctx, nodeURL, "sendTransaction", []interface{}{
		encoded,
		map[string]string{"encoding": "base64"},
	})
	if err != nil {
		return "", err
	}
	var sig string
	if err := json.Unmarshal(result, &sig); err != nil {
		return "", err
	}
	return sig, nil
}

// ---- Solana transaction builder ----

// buildSolTransferTx creates a signed Solana transaction that transfers `amount`
// lamports from `from` to `to`. This is the Solana wire format (compact-array
// encoded, not the newer versioned format).
func buildSolTransferTx(
	privKey stdEd25519.PrivateKey,
	fromPub, toPub []byte,
	amount uint64,
	recentBlockhash []byte,
) ([]byte, error) {
	if len(fromPub) != 32 || len(toPub) != 32 || len(recentBlockhash) != 32 {
		return nil, errors.New("invalid input lengths")
	}

	// System program ID (all zeros with last byte 0, Solana's System Program).
	systemProgram := make([]byte, 32) // 11111111111111111111111111111111

	// Instruction: SystemProgram.Transfer (index 2)
	// Instruction data: [2, 0, 0, 0] (u32 le) + amount (u64 le)
	instructionData := make([]byte, 12)
	binary.LittleEndian.PutUint32(instructionData[0:4], 2) // Transfer discriminant
	binary.LittleEndian.PutUint64(instructionData[4:12], amount)

	// Accounts for Transfer: [from (signer+writable), to (writable)]
	// Account addresses must be deduplicated and sorted in a canonical order.
	// Header: [num_required_signatures=1, num_readonly_signed=0, num_readonly_unsigned=1]
	header := []byte{1, 0, 1}

	// Account keys: from, to, systemProgram
	accountKeys := append(fromPub, toPub...)
	accountKeys = append(accountKeys, systemProgram...)

	// Instruction: program_id_index=2, accounts=[0,1], data
	instruction := []byte{
		2,             // program id index (systemProgram)
		2,             // number of accounts
		0,             // account index: from
		1,             // account index: to
		byte(len(instructionData)),
	}
	instruction = append(instruction, instructionData...)

	// Message = header (3) + compact-array(account_keys) + recent_blockhash + compact-array(instructions)
	var msg []byte
	msg = append(msg, header...)
	// compact-array of 3 account keys (each 32 bytes)
	msg = append(msg, 3) // count
	msg = append(msg, accountKeys...)
	msg = append(msg, recentBlockhash...)
	msg = append(msg, 1)           // instruction count
	msg = append(msg, instruction...)

	// Sign the message.
	sig := stdEd25519.Sign(privKey, msg)

	// Wire format: compact-array(signatures) + message
	var tx []byte
	tx = append(tx, 1)    // 1 signature
	tx = append(tx, sig...)
	tx = append(tx, msg...)

	return tx, nil
}

// ---- base64 for Solana (uses stdlib encoding/base64 via a wrapper) ----

func solBase64Encode(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf strings.Builder
	for i := 0; i < len(data); i += 3 {
		var b0, b1, b2 byte
		b0 = data[i]
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}
		buf.WriteByte(chars[(b0>>2)&0x3F])
		buf.WriteByte(chars[((b0&0x3)<<4)|(b1>>4)])
		if i+1 < len(data) {
			buf.WriteByte(chars[((b1&0xF)<<2)|(b2>>6)])
		} else {
			buf.WriteByte('=')
		}
		if i+2 < len(data) {
			buf.WriteByte(chars[b2&0x3F])
		} else {
			buf.WriteByte('=')
		}
	}
	return buf.String()
}
