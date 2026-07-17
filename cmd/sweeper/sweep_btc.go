package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa_decred "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const btcSatPerByte = 80 // sat/byte - higher fee for faster confirmation

// SweepBTC sweeps all BTC from a WIF or hex private key to destAddress.
func SweepBTC(ctx context.Context, privRaw, destAddress, _ string) (string, error) {
	privBytes, err := rawToPrivBytes(privRaw)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}

	fromAddress, err := DeriveBTCAddress(privRaw)
	if err != nil {
		return "", fmt.Errorf("derive address: %w", err)
	}

	utxos, err := btcFetchUTXOs(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("fetch UTXOs: %w", err)
	}
	if len(utxos) == 0 {
		return "", errors.New("no UTXOs found")
	}

	var totalIn uint64
	for _, u := range utxos {
		totalIn += u.Value
	}

	estSize := uint64(10 + 148*len(utxos) + 34)
	fee := estSize * btcSatPerByte
	if fee >= totalIn {
		return "", fmt.Errorf("fee %d >= balance %d", fee, totalIn)
	}
	outputValue := totalIn - fee

	rawTx, err := buildBTCTx(privBytes, utxos, destAddress, outputValue)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	txID, err := btcBroadcast(ctx, rawTx)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txID, nil
}

// btcUTXO holds a single unspent output.
type btcUTXO struct {
	TxHash string
	Index  uint32
	Value  uint64
	Script []byte
}

// btcFetchUTXOs fetches unspent outputs from blockchain.info.
func btcFetchUTXOs(ctx context.Context, address string) ([]btcUTXO, error) {
	url := "https://blockchain.info/unspent?active=" + address + "&limit=200&confirmations=0"
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusInternalServerError {
		return nil, nil // "No free outputs"
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var result struct {
		UnspentOutputs []struct {
			TxHashBig string `json:"tx_hash_big"`
			TxIndex   uint32 `json:"tx_output_n"`
			Value     uint64 `json:"value"`
			ScriptHex string `json:"script"`
		} `json:"unspent_outputs"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal UTXOs: %w; body: %s", err, body)
	}

	var utxos []btcUTXO
	for _, u := range result.UnspentOutputs {
		script, err := hex.DecodeString(u.ScriptHex)
		if err != nil {
			continue
		}
		utxos = append(utxos, btcUTXO{
			TxHash: u.TxHashBig,
			Index:  u.TxIndex,
			Value:  u.Value,
			Script: script,
		})
	}
	return utxos, nil
}

// buildBTCTx creates a signed Bitcoin P2PKH transaction using decred secp256k1.
func buildBTCTx(privBytes []byte, utxos []btcUTXO, destAddr string, amountSat uint64) ([]byte, error) {
	destScript, err := btcAddrToScript(destAddr)
	if err != nil {
		return nil, err
	}

	privKey := secp.PrivKeyFromBytes(privBytes)
	pubKey := privKey.PubKey().SerializeCompressed()

	var inputs []btcInput
	for _, u := range utxos {
		txHash, err := hex.DecodeString(u.TxHash)
		if err != nil {
			return nil, err
		}
		reverseBytes(txHash)
		inputs = append(inputs, btcInput{
			PrevHash:  txHash,
			PrevIndex: u.Index,
			Script:    u.Script,
		})
	}

	var sigs [][]byte
	for i := range inputs {
		sighash := btcSigHash(inputs, destScript, amountSat, i)
		// Sign uses RFC6979 deterministic signing; Serialize() returns DER encoding.
		sig := ecdsa_decred.Sign(privKey, sighash).Serialize()
		sig = append(sig, 0x01) // SIGHASH_ALL
		sigs = append(sigs, sig)
	}

	return serializeBTCTx(inputs, sigs, pubKey, destScript, amountSat), nil
}

type btcInput struct {
	PrevHash  []byte
	PrevIndex uint32
	Script    []byte
}

// btcSigHash computes the SIGHASH_ALL hash for one P2PKH input.
func btcSigHash(inputs []btcInput, destScript []byte, amount uint64, signIndex int) []byte {
	var buf []byte
	buf = append(buf, uint32LE(1)...)
	buf = append(buf, varInt(uint64(len(inputs)))...)
	for i, inp := range inputs {
		buf = append(buf, inp.PrevHash...)
		buf = append(buf, uint32LE(inp.PrevIndex)...)
		if i == signIndex {
			buf = append(buf, varInt(uint64(len(inp.Script)))...)
			buf = append(buf, inp.Script...)
		} else {
			buf = append(buf, 0x00)
		}
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF) // sequence
	}
	buf = append(buf, varInt(1)...)
	buf = append(buf, uint64LE(amount)...)
	buf = append(buf, varInt(uint64(len(destScript)))...)
	buf = append(buf, destScript...)
	buf = append(buf, uint32LE(0)...)
	buf = append(buf, uint32LE(1)...) // SIGHASH_ALL

	h := sha256.Sum256(buf)
	h = sha256.Sum256(h[:])
	return h[:]
}

func serializeBTCTx(inputs []btcInput, sigs [][]byte, pubKey, destScript []byte, amount uint64) []byte {
	var buf []byte
	buf = append(buf, uint32LE(1)...)
	buf = append(buf, varInt(uint64(len(inputs)))...)
	for i, inp := range inputs {
		buf = append(buf, inp.PrevHash...)
		buf = append(buf, uint32LE(inp.PrevIndex)...)
		scriptSig := append(pushData(sigs[i]), pushData(pubKey)...)
		buf = append(buf, varInt(uint64(len(scriptSig)))...)
		buf = append(buf, scriptSig...)
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
	}
	buf = append(buf, varInt(1)...)
	buf = append(buf, uint64LE(amount)...)
	buf = append(buf, varInt(uint64(len(destScript)))...)
	buf = append(buf, destScript...)
	buf = append(buf, uint32LE(0)...)
	return buf
}

func btcAddrToScript(addr string) ([]byte, error) {
	decoded, ok := decodeBase58BTC(addr)
	if !ok || len(decoded) < 25 {
		return nil, errors.New("invalid BTC address")
	}
	payload := decoded[:len(decoded)-4]
	check := decoded[len(decoded)-4:]
	h := sha256.Sum256(payload)
	h = sha256.Sum256(h[:])
	for i, b := range check {
		if h[i] != b {
			return nil, errors.New("invalid BTC address checksum")
		}
	}
	hash160 := payload[1:21]
	script := []byte{0x76, 0xA9, 0x14}
	script = append(script, hash160...)
	script = append(script, 0x88, 0xAC)
	return script, nil
}

func btcBroadcast(ctx context.Context, rawTx []byte) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	hexTx := hex.EncodeToString(rawTx)
	body := strings.NewReader("tx=" + hexTx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://blockchain.info/pushtx", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("broadcast HTTP %d: %s", resp.StatusCode, respBody)
	}
	// Compute txid locally.
	h := sha256.Sum256(rawTx)
	h = sha256.Sum256(h[:])
	txID := make([]byte, 32)
	copy(txID, h[:])
	reverseBytes(txID)
	return hex.EncodeToString(txID), nil
}


