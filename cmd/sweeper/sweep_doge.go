package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa_d "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const dogeFeeSatPerByte = 500000 // 0.005 DOGE/kB - higher fee for faster confirmation

func SweepDOGE(ctx context.Context, privRaw, destAddress string) (string, error) {
	privBytes, err := rawToPrivBytes(privRaw)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}

	fromAddress, err := DeriveDOGEAddress(privRaw)
	if err != nil {
		return "", fmt.Errorf("derive address: %w", err)
	}

	utxos, err := dogeFetchUTXOs(ctx, fromAddress)
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
	fee := estSize * dogeFeeSatPerByte / 1000
	if fee >= totalIn {
		return "", fmt.Errorf("fee %d >= balance %d", fee, totalIn)
	}
	outputValue := totalIn - fee

	rawTx, err := buildDOGETx(privBytes, utxos, destAddress, outputValue)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	txID, err := dogeBroadcast(ctx, rawTx)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	return txID, nil
}

func dogeFetchUTXOs(ctx context.Context, address string) ([]btcUTXO, error) {
	url := "https://api.blockcypher.com/v1/doge/main/addrs/" + address + "?unspentOnly=true"
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var result struct {
		TxRefs []struct {
			TxHash string `json:"tx_hash"`
			Index  uint32 `json:"tx_output_n"`
			Value  uint64 `json:"value"`
			Script string `json:"script"`
		} `json:"txrefs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}

	var utxos []btcUTXO
	for _, u := range result.TxRefs {
		script, err := hex.DecodeString(u.Script)
		if err != nil {
			continue
		}
		utxos = append(utxos, btcUTXO{
			TxHash: u.TxHash,
			Index:  u.Index,
			Value:  u.Value,
			Script: script,
		})
	}
	return utxos, nil
}

func buildDOGETx(privBytes []byte, utxos []btcUTXO, destAddr string, amount uint64) ([]byte, error) {
	destScript, err := utxoAddrToScript(destAddr, 0x1e)
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
		sighash := btcSigHash(inputs, destScript, amount, i)
		sig := ecdsa_d.Sign(privKey, sighash).Serialize()
		sig = append(sig, 0x01)
		sigs = append(sigs, sig)
	}

	return serializeBTCTx(inputs, sigs, pubKey, destScript, amount), nil
}

func dogeBroadcast(ctx context.Context, rawTx []byte) (string, error) {
	hexTx := hex.EncodeToString(rawTx)
	payload, _ := json.Marshal(map[string]string{"tx": hexTx})
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.blockcypher.com/v1/doge/main/txs/push",
		strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("broadcast HTTP %d: %s", resp.StatusCode, respBody)
	}
	var result struct {
		Tx struct {
			Hash string `json:"hash"`
		} `json:"tx"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("unmarshal response: %w; body: %s", err, respBody)
	}
	return result.Tx.Hash, nil
}
