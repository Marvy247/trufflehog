package main

import (
	"context"
	stdEd25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func SweepSui(ctx context.Context, privHex, destAddress, nodeURL string) (string, error) {
	if nodeURL == "" {
		nodeURL = "https://fullnode.mainnet.sui.io"
	}

	privBytes, err := hexToPrivBytes(privHex)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}

	privKey := stdEd25519.NewKeyFromSeed(privBytes)
	pubKey := privKey.Public().(stdEd25519.PublicKey)

	fromAddr, err := DeriveSuiAddress(privHex)
	if err != nil {
		return "", fmt.Errorf("derive address: %w", err)
	}

	gasPrice, err := suiGetGasPrice(ctx, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get gas price: %w", err)
	}

	coins, err := suiGetCoins(ctx, fromAddr, nodeURL)
	if err != nil {
		return "", fmt.Errorf("get coins: %w", err)
	}
	if len(coins) == 0 {
		return "", errors.New("no SUI coins found")
	}

	var totalBalance uint64
	for _, c := range coins {
		totalBalance += c.Balance
	}

	// Budget: use the first coin as gas, estimate ~2M MIST for budget.
	const gasBudget = 2_000_000
	if totalBalance <= gasBudget {
		return "", fmt.Errorf("total balance %d MIST too low to cover gas budget %d", totalBalance, gasBudget)
	}
	transferAmount := totalBalance - gasBudget

	destSuiAddr, err := suiParseAddress(destAddress)
	if err != nil {
		return "", fmt.Errorf("parse dest address: %w", err)
	}
	fromSuiAddr, err := suiParseAddress(fromAddr)
	if err != nil {
		return "", fmt.Errorf("parse from address: %w", err)
	}

	txData, err := buildSuiTransferTx(fromSuiAddr, destSuiAddr, coins, transferAmount, gasPrice, gasBudget)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	// Sign: Sui uses [intent(3 bytes) || txData(BCS)]
	intent := []byte{0x00, 0x00, 0x00}
	msg := append(intent, txData...)
	sigBytes := stdEd25519.Sign(privKey, msg)

	// Signature scheme: flag(0x00 for Ed25519) || sig(64) || pubkey(32)
	signature := append([]byte{0x00}, sigBytes...)
	signature = append(signature, pubKey...)

	txDigest, err := suiExecuteTx(ctx, nodeURL, txData, signature, sigBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("execute tx: %w", err)
	}
	return txDigest, nil
}

type suiCoin struct {
	CoinType      string `json:"coinType"`
	ObjectID      string `json:"coinObjectId"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	Balance       uint64 `json:"balance,string"`
	PreviousTx    string `json:"previousTransaction"`
}

func suiGetGasPrice(ctx context.Context, nodeURL string) (uint64, error) {
	payload := `{"jsonrpc":"2.0","id":1,"method":"suix_getReferenceGasPrice","params":[]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var rpc struct {
		Result string `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return 0, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpc.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpc.Error.Message)
	}
	var price uint64
	if _, err := fmt.Sscanf(rpc.Result, "%d", &price); err != nil {
		return 0, fmt.Errorf("parse gas price: %w", err)
	}
	return price, nil
}

func suiGetCoins(ctx context.Context, address, nodeURL string) ([]suiCoin, error) {
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"suix_getCoins","params":["%s","0x2::sui::SUI",null,null]}`,
		address,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var rpc struct {
		Result struct {
			Data []suiCoin `json:"data"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpc.Error.Message)
	}
	return rpc.Result.Data, nil
}

func suiParseAddress(addr string) ([32]byte, error) {
	h := strings.TrimPrefix(addr, "0x")
	h = strings.TrimPrefix(h, "0X")
	if len(h) != 64 {
		return [32]byte{}, fmt.Errorf("invalid Sui address length: %s", addr)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// ---- Minimal BCS encoding for Sui transaction ----

func bcsULEB128(n uint64) []byte {
	var buf []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if n == 0 {
			break
		}
	}
	return buf
}

func bcsU8(b byte) []byte {
	return []byte{b}
}

func bcsU64(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

func bcsU128(hi, lo uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, lo)
	binary.LittleEndian.PutUint64(b[8:], hi)
	return b
}

func bcsAddress(addr [32]byte) []byte {
	return addr[:]
}

func bcsBool(v bool) []byte {
	if v {
		return []byte{0x01}
	}
	return []byte{0x00}
}

func bcsOptionNone() []byte {
	return []byte{0x00}
}

func bcsOptionSome(data []byte) []byte {
	return append([]byte{0x01}, data...)
}

func bcsVector(items [][]byte) []byte {
	result := bcsULEB128(uint64(len(items)))
	for _, item := range items {
		result = append(result, item...)
	}
	return result
}

func bcsStruct(fields ...[]byte) []byte {
	var result []byte
	for _, f := range fields {
		result = append(result, f...)
	}
	return result
}

func bcsEnumVariant(variant byte, fields ...[]byte) []byte {
	result := []byte{variant}
	for _, f := range fields {
		result = append(result, f...)
	}
	return result
}

type suiObjRef struct {
	ObjectID [32]byte
	Version  uint64
	Digest   [32]byte
}

func bcsObjRef(ref suiObjRef) []byte {
	return bcsStruct(
		bcsAddress(ref.ObjectID),
		bcsU64(ref.Version),
		bcsAddress(ref.Digest),
	)
}

func suiParseObjID(s string) ([32]byte, error) {
	h := strings.TrimPrefix(s, "0x")
	if len(h) > 64 {
		h = h[:64]
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[32-len(b):], b)
	return out, nil
}

func suiParseDigest(s string) ([32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func buildSuiTransferTx(
	fromAddr [32]byte,
	destAddr [32]byte,
	coins []suiCoin,
	transferAmount, gasPrice, gasBudget uint64,
) ([]byte, error) {
	if len(coins) == 0 {
		return nil, errors.New("no coins to spend")
	}

	// For simplicity, use the first coin as both the gas payment and the only
	// input. In production you'd want to merge coins if needed.
	primaryCoin := coins[0]
	objID, err := suiParseObjID(primaryCoin.ObjectID)
	if err != nil {
		return nil, fmt.Errorf("parse coin object ID: %w", err)
	}
	digest, err := suiParseDigest(primaryCoin.Digest)
	if err != nil {
		return nil, fmt.Errorf("parse coin digest: %w", err)
	}
	version := primaryCoin.Version
	var verUint64 uint64
	if _, err := fmt.Sscanf(version, "%d", &verUint64); err != nil {
		return nil, fmt.Errorf("parse coin version: %w", err)
	}

	coinRef := suiObjRef{
		ObjectID: objID,
		Version:  verUint64,
		Digest:   digest,
	}

	// Build ProgrammableTransaction:
	// inputs:
	//   0: ImmOrOwnedObject(coinRef)  - the input coin
	//   1: pure(destAddress)          - destination

	// Argument::Input(0) = 0x00, 0x00
	// Argument::Input(1) = 0x00, 0x01
	argInput0 := []byte{0x00, 0x00}
	argInput1 := []byte{0x00, 0x01}

	// TransactionInput::Object(ImmOrOwnedObject)
	txInput0 := bcsEnumVariant(1, // Object
		bcsEnumVariant(0, // ImmOrOwned
			bcsObjRef(coinRef),
		),
	)

	// Pure value: destination address (32 bytes) encoded as BCS vec<u8>
	pureVal := append(bcsULEB128(32), destAddr[:]...) // vec<u8> length=32 then bytes
	txInput1 := bcsEnumVariant(0, pureVal)             // Pure(vec<u8>)

	inputs := bcsVector([][]byte{txInput0, txInput1})

	// Command::TransferObjects([Argument::Input(0)], Argument::Input(1))
	transferCmd := bcsEnumVariant(3, // TransferObjects
		bcsVector([][]byte{argInput0}), // addresses: [input 0]
		argInput1,                      // destination: input 1
	)

	commands := bcsVector([][]byte{transferCmd})

	// ProgrammableTransaction
	pt := bcsStruct(inputs, commands)

	// TransactionKind::ProgrammableTransaction
	txKind := bcsEnumVariant(2, pt)

	// GasData
	gasData := bcsStruct(
		bcsVector([][]byte{bcsObjRef(coinRef)}), // payment
		bcsAddress(fromAddr),                     // owner
		bcsU64(gasPrice),                         // price
		bcsU64(gasBudget),                        // budget
	)

	// TransactionExpiration::None
	expiration := bcsEnumVariant(0)

	// TransactionDataV1
	txDataV1 := bcsStruct(txKind, bcsAddress(fromAddr), gasData, expiration)

	// TransactionData::V1
	txData := bcsEnumVariant(0, txDataV1)

	return txData, nil
}

func suiExecuteTx(ctx context.Context, nodeURL string, txData, signature, sigBytes, pubKey []byte) (string, error) {
	txB64 := base64.StdEncoding.EncodeToString(txData)
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"sui_executeTransactionBlock","params":["%s",["%s"],{"showEffects":true}]}`,
		txB64, sigB64,
	)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeURL, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return "", fmt.Errorf("unmarshal: %w; body: %s", err, body)
	}
	if rpc.Error != nil {
		return "", fmt.Errorf("RPC error: %s", rpc.Error.Message)
	}

	// Parse digest from result
	var effects struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(rpc.Result, &effects); err != nil {
		// Try to find digest in nested structure
		var fullResult struct {
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(rpc.Result, &fullResult); err != nil {
			return "", fmt.Errorf("parse result: %w; body: %s", err, string(body))
		}
		return fullResult.Digest, nil
	}
	return effects.Digest, nil
}
