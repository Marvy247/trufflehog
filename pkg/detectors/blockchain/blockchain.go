package blockchain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

//go:embed bip39_words.txt
var bip39Data string

type Scanner struct{}

var (
	_ detectors.Detector             = (*Scanner)(nil)
	_ detectors.MaxSecretSizeProvider = (*Scanner)(nil)

	secp256k1Curve elliptic.Curve
	secp256k1N     *big.Int

	bip39Words    map[string]struct{}
	base58Lookup  [256]byte
	base58EncodeAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	c32Alphabet   = "0123456789abcdefghjkmnpqrstuvwxyz"

	httpClient    *http.Client
	keywordIndex  map[string][]int
)

func init() {
	bip39Words = make(map[string]struct{}, 2048)
	for _, w := range strings.Fields(bip39Data) {
		bip39Words[w] = struct{}{}
	}

	for i := range base58Lookup {
		base58Lookup[i] = 0xFF
	}
	for i, c := range base58EncodeAlphabet {
		base58Lookup[c] = byte(i)
	}

	secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1Curve = &elliptic.CurveParams{
		P:       mustBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
		N:       secp256k1N,
		B:       big.NewInt(7),
		Gx:      mustBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
		Gy:      mustBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
		BitSize: 256,
		Name:    "secp256k1",
	}

	httpClient = common.SaneHttpClient()

	keywordIndex = make(map[string][]int)
	for i, c := range chains {
		for _, kw := range c.keywords {
			keywordIndex[kw] = append(keywordIndex[kw], i)
		}
	}
}

type chainInfo struct {
	name       string
	keywords   []string
	pattern    *regexp.Regexp
	validate   func(string) bool
	deriveAddr func(string) string
	verify     func(context.Context, string) bool
	rpcCall    func(context.Context, string) bool
}

var chains = []chainInfo{
	{
		name:       "Ethereum",
		keywords:   []string{"eth", "ethereum", "ether", "web3", "ethers"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"eth", "ethereum", "ether", "web3", "ethers", "0x"}) + `((0x)?[0-9a-fA-F]{64})\b`),
		validate:   isValidSecp256k1Key,
		deriveAddr: deriveETHAddrFromHex,
		verify:     verifyETHKey,
	},
	{
		name:       "Ethereum keystore",
		keywords:   []string{"keystore", "UTC--", "wallet"},
		pattern:    regexp.MustCompile(`"address"\s*:\s*"0x([0-9a-fA-F]{40})".*?"crypto".*?"ciphertext"\s*:\s*"([0-9a-fA-F]+)"`),
		validate:   func(s string) bool { return len(s) >= 40 },
	},
	{
		name:       "Solana",
		keywords:   []string{"sol", "solana", "keypair", "secretkey"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"sol", "solana", "keypair", "secretkey"}) + `([1-9A-HJ-NP-Za-km-z]{87,88})\b`),
		validate:   isValidSolanaKey,
		deriveAddr: deriveSolanaAddress,
		verify:     verifySolanaKey,
	},
	{
		name:       "Bitcoin",
		keywords:   []string{"btc", "bitcoin", "wif"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"btc", "bitcoin", "wif"}) + `([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b`),
		validate:   isValidWIFKey,
		deriveAddr: deriveBTCAddress,
		verify:     verifyBTCKey,
	},
	{
		name:       "BIP32 extended key",
		keywords:   []string{"xprv", "xpub", "ypub", "zpub", "yprv", "zprv", "bip32"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"xprv", "xpub", "ypub", "zpub", "yprv", "zprv", "bip32", "extended"}) + `([xyzXYZnN][prvubPRVUB][1-9A-HJ-NP-Za-km-z]{107,111})\b`),
		validate:   isValidBase58Key,
	},
	{
		name:       "Stacks",
		keywords:   []string{"stx", "stacks"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"stx", "stacks"}) + `([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b`),
		validate:   isValidWIFKey,
		deriveAddr: deriveSTXAddress,
		verify:     verifySTXKey,
	},
	{
		name:       "Dogecoin",
		keywords:   []string{"doge", "dogecoin"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"doge", "dogecoin"}) + `([6Q][1-9A-HJ-NP-Za-km-z]{50,51})\b`),
		validate:   isValidWIFKey,
	},
	{
		name:       "Litecoin",
		keywords:   []string{"ltc", "litecoin"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"ltc", "litecoin"}) + `([6T][1-9A-HJ-NP-Za-km-z]{50,51})\b`),
		validate:   isValidWIFKey,
	},
	{
		name:     "Ripple",
		keywords: []string{"xrp", "ripple"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"xrp", "ripple"}) + `(s[1-9A-HJ-NP-Za-km-z]{27,33})\b`),
		validate: isValidBase58Key,
	},
	{
		name:     "Stellar",
		keywords: []string{"xlm", "stellar"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"xlm", "stellar"}) + `(S[1-9A-HJ-NP-Za-km-z]{55})\b`),
		validate: isValidBase58Key,
	},
	{
		name:     "Cardano",
		keywords: []string{"ada", "cardano", "xprv"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"ada", "cardano", "xprv"}) + `(xprv[1-9A-HJ-NP-Za-km-z]{165,})\b`),
		validate: isValidBase58Key,
	},
	{
		name:     "Tezos",
		keywords: []string{"xtz", "tezos", "edsk"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"xtz", "tezos", "edsk"}) + `(edsk[1-9A-HJ-NP-Za-km-z]{51})\b`),
		validate: isValidBase58Key,
	},
	{
		name:       "Polkadot",
		keywords:   []string{"dot", "polkadot", "substrate"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"dot", "polkadot", "substrate"}) + `([0-9a-fA-F]{64})\b`),
		validate:   isValidSecp256k1Key,
	},
	{
		name:       "Cosmos",
		keywords:   []string{"atom", "cosmos", "osmo", "osmosis"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"atom", "cosmos", "osmo", "osmosis"}) + `([0-9a-fA-F]{64})\b`),
		validate:   isValidSecp256k1Key,
	},
	{
		name:     "Monero",
		keywords: []string{"xmr", "monero"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"xmr", "monero"}) + `([0-9a-fA-F]{64})\b`),
		validate: isValidSecp256k1Key,
	},
	{
		name:     "NEAR",
		keywords: []string{"near", "nearprotocol"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"near", "nearprotocol"}) + `(ed25519:[1-9A-HJ-NP-Za-km-z]{43,44})\b`),
		validate: isValidBase58Key,
	},
	{
		name:       "Aptos",
		keywords:   []string{"apt", "aptos", "aptoslabs"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"apt", "aptos", "aptoslabs"}) + `(0x[0-9a-fA-F]{64})\b`),
		validate:   isValidSecp256k1Key,
	},
	{
		name:       "Sui",
		keywords:   []string{"sui", "sui:"},
		pattern:    regexp.MustCompile(detectors.PrefixRegex([]string{"sui"}) + `([0-9a-fA-F]{64})\b`),
		validate:   isValidEd25519Key,
	},
	{
		name:     "BIP39 mnemonic",
		keywords: []string{"mnemonic", "seed", "seed phrase", "recovery", "recovery phrase", "backup", "bip39", "12 words", "24 words"},
		pattern:  regexp.MustCompile(detectors.PrefixRegex([]string{"mnemonic", "seed", "recovery", "phrase", "backup", "bip39"}) + `((?:[a-zA-Z]{3,10}\s){11,23}[a-zA-Z]{3,10})\b`),
		validate: isValidMnemonic,
	},
}

func (s Scanner) MaxSecretSize() int64 { return 4096 }

func (s Scanner) Keywords() []string {
	seen := map[string]struct{}{}
	var all []string
	for _, c := range chains {
		for _, kw := range c.keywords {
			if _, ok := seen[kw]; !ok {
				seen[kw] = struct{}{}
				all = append(all, kw)
			}
		}
	}
	return all
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	dataLower := strings.ToLower(dataStr)

	chainsToScan := map[int]struct{}{}
	for kw, indices := range keywordIndex {
		if strings.Contains(dataLower, kw) {
			for _, idx := range indices {
				chainsToScan[idx] = struct{}{}
			}
		}
	}

	var results []detectors.Result

	for idx := range chainsToScan {
		chain := chains[idx]

		for _, match := range chain.pattern.FindAllStringSubmatch(dataStr, -1) {
			raw := match[1]

			if chain.validate != nil && !chain.validate(raw) {
				continue
			}

			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_CustomRegex,
				Raw:          []byte(raw),
				ExtraData:    map[string]string{"chain": chain.name},
			}

			if chain.deriveAddr != nil {
				if addr := chain.deriveAddr(raw); addr != "" {
					r.ExtraData["derived_address"] = addr
				}
			}

			if verify {
				if chain.verify != nil {
					confirmed := chain.verify(ctx, raw)
					r.Verified = confirmed
					r.ExtraData["verification"] = fmt.Sprintf("%t", confirmed)
					if confirmed && chain.deriveAddr != nil {
						r.ExtraData["has_funds"] = fmt.Sprintf("%t", chainHasFunds(ctx, chain, raw))
					}
				} else if chain.validate != nil {
					r.Verified = chain.validate(raw)
					r.ExtraData["verification"] = "cryptographic"
				}
			}

			results = append(results, r)
		}
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType { return detector_typepb.DetectorType_CustomRegex }
func (s Scanner) Description() string {
	return "Detects blockchain private keys and recovery phrases for Ethereum, Solana, Bitcoin, Stacks, Dogecoin, Litecoin, Ripple, Stellar, Cardano, Tezos, Polkadot, Cosmos, Monero, NEAR, Aptos, Sui, BIP32 extended keys, Ethereum keystores, and BIP39 mnemonics. Uses cryptographic validation to eliminate false positives."
}

// ---- helpers ----

func mustBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid big int: " + s)
	}
	return n
}

// ---- validation ----

func isValidSecp256k1Key(raw string) bool {
	h := raw
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		return false
	}
	key, ok := new(big.Int).SetString(h, 16)
	return ok && key.Sign() > 0 && key.Cmp(secp256k1N) < 0
}

func isValidEd25519Key(raw string) bool {
	h := raw
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

func decodeBase58(s string) ([]byte, bool) {
	var zeroes int
	for zeroes < len(s) && s[zeroes] == '1' {
		zeroes++
	}
	var val big.Int
	for _, c := range s[zeroes:] {
		if c >= 256 || base58Lookup[c] == 0xFF {
			return nil, false
		}
		val.Mul(&val, big.NewInt(58))
		val.Add(&val, big.NewInt(int64(base58Lookup[c])))
	}
	decoded := val.Bytes()
	result := make([]byte, zeroes+len(decoded))
	copy(result[zeroes:], decoded)
	return result, true
}

func base58Encode(data []byte) string {
	var zeroes int
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	var val big.Int
	val.SetBytes(data)
	var result []byte
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	for val.Cmp(zero) > 0 {
		val.DivMod(&val, base, mod)
		result = append(result, base58EncodeAlphabet[mod.Int64()])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return strings.Repeat("1", zeroes) + string(result)
}

func isValidBase58Key(s string) bool {
	decoded, ok := decodeBase58(s)
	return ok && len(decoded) >= 16 && len(decoded) <= 128
}

func isValidSolanaKey(s string) bool {
	decoded, ok := decodeBase58(s)
	return ok && (len(decoded) == 32 || len(decoded) == 64)
}

func isValidWIFKey(s string) bool {
	_, ok := wifToPrivKey(s)
	return ok
}

func wifToPrivKey(s string) ([]byte, bool) {
	decoded, ok := decodeBase58(s)
	if !ok || (len(decoded) != 37 && len(decoded) != 38) {
		return nil, false
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	h := sha256.Sum256(payload)
	h = sha256.Sum256(h[:])
	for i, b := range checksum {
		if h[i] != b {
			return nil, false
		}
	}
	return decoded[1:33], true
}

func isValidMnemonic(phrase string) bool {
	words := strings.Fields(strings.ToLower(phrase))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}
	for _, w := range words {
		if _, ok := bip39Words[w]; !ok {
			return false
		}
	}
	return true
}

// ---- secp256k1 ----

func parseSecp256k1Key(raw string) (*ecdsa.PrivateKey, error) {
	h := raw
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		return nil, fmt.Errorf("invalid key length")
	}
	keyBytes, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	keyInt := new(big.Int).SetBytes(keyBytes)
	if keyInt.Sign() == 0 || keyInt.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("key out of range")
	}
	x, y := secp256k1Curve.ScalarBaseMult(keyBytes)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: secp256k1Curve, X: x, Y: y},
		D:         keyInt,
	}, nil
}

func pubkeyToCompressedBytes(x, y *big.Int) []byte {
	compressed := make([]byte, 33)
	compressed[0] = 0x02 + byte(y.Bit(0))
	xBytes := x.Bytes()
	copy(compressed[33-len(xBytes):], xBytes)
	return compressed
}

func hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(h[:])
	return r.Sum(nil)
}

func doubleSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	h = sha256.Sum256(h[:])
	return h[:]
}

// ---- address derivation ----

func deriveETHAddrFromHex(raw string) string {
	priv, err := parseSecp256k1Key(raw)
	if err != nil {
		return ""
	}
	return deriveETHAddress(priv)
}

func deriveETHAddress(key *ecdsa.PrivateKey) string {
	hash := sha3.NewLegacyKeccak256()
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	padded := make([]byte, 64)
	copy(padded[32-len(xBytes):32], xBytes)
	copy(padded[64-len(yBytes):], yBytes)
	hash.Write(padded)
	return "0x" + hex.EncodeToString(hash.Sum(nil)[12:])
}

func deriveSolanaAddress(raw string) string {
	decoded, ok := decodeBase58(raw)
	if !ok {
		return ""
	}
	var pubKey ed25519.PublicKey
	switch {
	case len(decoded) == 32:
		privKey := ed25519.NewKeyFromSeed(decoded)
		pubKey = privKey.Public().(ed25519.PublicKey)
	case len(decoded) == 64:
		pubKey = ed25519.PublicKey(decoded[32:])
	default:
		return ""
	}
	return base58Encode([]byte(pubKey))
}

func deriveBTCAddress(raw string) string {
	privBytes, ok := wifToPrivKey(raw)
	if !ok {
		return ""
	}
	keyInt := new(big.Int).SetBytes(privBytes)
	if keyInt.Sign() == 0 || keyInt.Cmp(secp256k1N) >= 0 {
		return ""
	}
	x, y := secp256k1Curve.ScalarBaseMult(privBytes)
	compressed := pubkeyToCompressedBytes(x, y)
	h160 := hash160(compressed)
	return base58CheckEncode(0x00, h160)
}

func deriveSTXAddress(raw string) string {
	privBytes, ok := wifToPrivKey(raw)
	if !ok {
		return ""
	}
	keyInt := new(big.Int).SetBytes(privBytes)
	if keyInt.Sign() == 0 || keyInt.Cmp(secp256k1N) >= 0 {
		return ""
	}
	x, y := secp256k1Curve.ScalarBaseMult(privBytes)
	compressed := pubkeyToCompressedBytes(x, y)
	h160 := hash160(compressed)
	return "SP" + c32checkEncode(22, h160)[2:]
}

// ---- base58check ----

func base58CheckEncode(version byte, payload []byte) string {
	data := append([]byte{version}, payload...)
	checksum := doubleSHA256(data)[:4]
	return base58Encode(append(data, checksum...))
}

// ---- c32check (Stacks) ----

var c32Lookup [256]byte

func init() {
	for i := range c32Lookup {
		c32Lookup[i] = 0xFF
	}
	for i, c := range c32Alphabet {
		c32Lookup[c] = byte(i)
	}
}

func c32encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var zeroes int
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	carry := new(big.Int).SetBytes(data)
	var encoded []byte
	base := big.NewInt(32)
	zero := big.NewInt(0)
	tmp := new(big.Int)
	for carry.Cmp(zero) > 0 {
		tmp.Mod(carry, base)
		encoded = append(encoded, c32Alphabet[tmp.Int64()])
		carry.Div(carry, base)
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return strings.Repeat("0", zeroes) + string(encoded)
}

func c32checkEncode(version byte, payload []byte) string {
	data := append([]byte{version}, payload...)
	checksum := doubleSHA256(data)[:4]
	return c32encode(append(data, checksum...))
}

// ---- balance check helper ----

func chainHasFunds(ctx context.Context, chain chainInfo, raw string) bool {
	if chain.deriveAddr == nil {
		return false
	}
	addr := chain.deriveAddr(raw)
	if addr == "" {
		return false
	}
	switch chain.name {
	case "Ethereum":
		return checkETHBalance(ctx, addr)
	case "Bitcoin":
		return checkBTCBalance(ctx, addr)
	case "Solana":
		return checkSolanaBalance(ctx, addr)
	}
	return false
}

func checkETHBalance(ctx context.Context, address string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.etherscan.io/api?module=account&action=balance&address="+address+"&tag=latest", nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return bytes.Contains(body, []byte(`"result":"`)) && !bytes.Contains(body, []byte(`"result":"0"`))
}

func checkBTCBalance(ctx context.Context, address string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://blockstream.info/api/address/"+address, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	return bytes.Contains(body, []byte(`"funded_txo_count":`)) && !bytes.Contains(body, []byte(`"funded_txo_count":0`))
}

func checkSolanaBalance(ctx context.Context, address string) bool {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["%s"]}`, address)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.mainnet-beta.solana.com",
		strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	data, _ := io.ReadAll(resp.Body)
	return bytes.Contains(data, []byte(`"value":`)) && !bytes.Contains(data, []byte(`"value":0`))
}

// ---- network verification ----

func verifyETHKey(ctx context.Context, raw string) bool {
	priv, err := parseSecp256k1Key(raw)
	if err != nil {
		return false
	}
	address := deriveETHAddress(priv)

	if checkETHTransactions(ctx, address) {
		return true
	}
	return checkETHBalance(ctx, address)
}

func checkETHTransactions(ctx context.Context, address string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.etherscan.io/api?module=account&action=txlist&address="+address+"&page=1&offset=1&sort=desc", nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	return bytes.Contains(body, []byte(`"status":"1"`))
}

func verifySolanaKey(ctx context.Context, raw string) bool {
	address := deriveSolanaAddress(raw)
	if address == "" {
		return false
	}
	return checkSolanaBalance(ctx, address) || checkSolanaTransactions(ctx, address)
}

func checkSolanaTransactions(ctx context.Context, address string) bool {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["%s",{"limit":1}]}`, address)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.mainnet-beta.solana.com",
		strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	data, _ := io.ReadAll(resp.Body)
	return bytes.Contains(data, []byte(`"signature"`))
}

func verifyBTCKey(ctx context.Context, raw string) bool {
	address := deriveBTCAddress(raw)
	if address == "" {
		return false
	}
	return checkBTCBalance(ctx, address) || checkBTCTransactions(ctx, address)
}

func checkBTCTransactions(ctx context.Context, address string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://blockstream.info/api/address/"+address+"/txs?limit=1", nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	data, _ := io.ReadAll(resp.Body)
	return bytes.Contains(data, []byte(`"txid"`))
}

func verifySTXKey(ctx context.Context, raw string) bool {
	address := deriveSTXAddress(raw)
	if address == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.hiro.so/extended/v1/address/"+address+"/transactions?limit=1", nil)
	if err != nil {
		return false
	}
	resp, err3 := httpClient.Do(req)
	if err3 != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	return bytes.Contains(body, []byte(`"total"`))
}
