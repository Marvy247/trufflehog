package main

import (
	"crypto/sha256"
	stdEd25519 "crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// DerivedAddresses holds the addresses derived from a single private key.
type DerivedAddresses struct {
	ETH    string // "0x" + 40 hex chars
	BTC    string // P2PKH base58check
	DOGE   string // Dogecoin address
	LTC    string // Litecoin address
	STX    string // Stacks address
	Sui    string // Sui address (0x...)
	XLM    string // Stellar address (G...)
	Solana string // base58-encoded 32-byte ed25519 public key
}

// ---- ETH ----

// DeriveETHAddress returns the lowercase "0x..." Ethereum address for a secp256k1 hex key.
func DeriveETHAddress(privHex string) (string, error) {
	privBytes, err := hexToPrivBytes(privHex)
	if err != nil {
		return "", err
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pub := privKey.PubKey().SerializeUncompressed()
	return "0x" + keccakAddress(pub[1:]), nil
}

// ---- BTC ----

func DeriveBTCAddress(privRaw string) (string, error) {
	return deriveP2PKHAddress(privRaw, 0x00)
}

// ---- DOGE ----

func DeriveDOGEAddress(privRaw string) (string, error) {
	return deriveP2PKHAddress(privRaw, 0x1e)
}

// ---- LTC ----

func DeriveLTCAddress(privRaw string) (string, error) {
	return deriveP2PKHAddress(privRaw, 0x30)
}

// deriveP2PKHAddress derives a P2PKH base58check address with the given version byte.
func deriveP2PKHAddress(privRaw string, version byte) (string, error) {
	privBytes, err := rawToPrivBytes(privRaw)
	if err != nil {
		return "", err
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pub := privKey.PubKey().SerializeCompressed()
	hash160 := publicKeyHash160(pub)
	versionedPayload := append([]byte{version}, hash160...)
	return base58CheckEncode(versionedPayload), nil
}

func publicKeyHash160(pub []byte) []byte {
	h := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(h[:])
	return r.Sum(nil)
}

func base58CheckEncode(payload []byte) string {
	h := sha256.Sum256(payload)
	h = sha256.Sum256(h[:])
	full := append(payload, h[:4]...)
	return encodeBase58(full)
}

// ---- STX ----

func DeriveSTXAddress(privRaw string) (string, error) {
	privBytes, err := rawToPrivBytes(privRaw)
	if err != nil {
		return "", err
	}
	privKey := secp.PrivKeyFromBytes(privBytes)
	pub := privKey.PubKey().SerializeCompressed()
	h160 := publicKeyHash160(pub)
	// Stacks mainnet address version = 22 (0x16)
	payload := append([]byte{22}, h160...)
	checksum := doubleSHA256(payload)[:4]
	full := append(payload, checksum...)
	return "SP" + c32Encode(full), nil
}

func doubleSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	h = sha256.Sum256(h[:])
	return h[:]
}

// c32Encode encodes bytes using Stacks' c32 alphabet (RFC 4648 base32 variant).
var c32Alphabet = "0123456789abcdefghjkmnpqrstuvwxyz"

func c32Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var zeroes int
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	carry := new(big.Int).SetBytes(data)
	base := big.NewInt(32)
	zero := big.NewInt(0)
	tmp := new(big.Int)
	var encoded []byte
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

// ---- Sui ----

func DeriveSuiAddress(privHex string) (string, error) {
	privBytes, err := hexToPrivBytes(privHex)
	if err != nil {
		return "", err
	}
	privKey := stdEd25519.NewKeyFromSeed(privBytes)
	pubKey := privKey.Public().(stdEd25519.PublicKey)
	// Sui Ed25519 flag byte = 0x00, then 32-byte pubkey
	toHash := append([]byte{0x00}, pubKey...)
	hash := keccak256Hash(toHash)
	return "0x" + hex.EncodeToString(hash[:20]), nil
}

// ---- Stellar ----

func DeriveXLMAddress(privBase58 string) (string, error) {
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
		return "", fmt.Errorf("unexpected Stellar key length: %d", len(decoded))
	}
	privKey := stdEd25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(stdEd25519.PublicKey)
	return stellarStrKeyEncode(pubKey), nil
}

var stellarBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func stellarStrKeyEncode(payload []byte) string {
	// Stellar StrKey: version byte + payload + CRC-16-XModem checksum(2 bytes), then base32 encode.
	data := append([]byte{0x30}, payload...) // version byte for public key (G...)
	crc := crc16XModem(data)
	data = append(data, byte(crc>>8), byte(crc))
	return base32EncodeStellar(data)
}

func base32EncodeStellar(data []byte) string {
	var result []byte
	for i := 0; i < len(data); i += 5 {
		var b [5]byte
		for j := 0; j < 5 && i+j < len(data); j++ {
			b[j] = data[i+j]
		}
		n := 5
		if i+5 > len(data) {
			n = len(data) - i
		}
		switch n {
		case 1:
			result = append(result, stellarBase32Alphabet[b[0]>>3])
			result = append(result, stellarBase32Alphabet[(b[0]&0x07)<<2])
		case 2:
			result = append(result, stellarBase32Alphabet[b[0]>>3])
			result = append(result, stellarBase32Alphabet[(b[0]&0x07)<<2|b[1]>>6])
			result = append(result, stellarBase32Alphabet[(b[1]>>1)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[1]&0x01)<<4])
		case 3:
			result = append(result, stellarBase32Alphabet[b[0]>>3])
			result = append(result, stellarBase32Alphabet[(b[0]&0x07)<<2|b[1]>>6])
			result = append(result, stellarBase32Alphabet[(b[1]>>1)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[1]&0x01)<<4|b[2]>>4])
			result = append(result, stellarBase32Alphabet[(b[2]&0x0F)<<1])
		case 4:
			result = append(result, stellarBase32Alphabet[b[0]>>3])
			result = append(result, stellarBase32Alphabet[(b[0]&0x07)<<2|b[1]>>6])
			result = append(result, stellarBase32Alphabet[(b[1]>>1)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[1]&0x01)<<4|b[2]>>4])
			result = append(result, stellarBase32Alphabet[(b[2]&0x0F)<<1|b[3]>>7])
			result = append(result, stellarBase32Alphabet[(b[3]>>2)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[3]&0x03)<<3])
		case 5:
			result = append(result, stellarBase32Alphabet[b[0]>>3])
			result = append(result, stellarBase32Alphabet[(b[0]&0x07)<<2|b[1]>>6])
			result = append(result, stellarBase32Alphabet[(b[1]>>1)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[1]&0x01)<<4|b[2]>>4])
			result = append(result, stellarBase32Alphabet[(b[2]&0x0F)<<1|b[3]>>7])
			result = append(result, stellarBase32Alphabet[(b[3]>>2)&0x1F])
			result = append(result, stellarBase32Alphabet[(b[3]&0x03)<<3|b[4]>>5])
			result = append(result, stellarBase32Alphabet[b[4]&0x1F])
		}
	}
	return string(result)
}

func crc16XModem(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---- Solana ----

func DeriveSolanaAddress(privBase58 string) (string, error) {
	decoded, ok := decodeBase58BTC(privBase58)
	if !ok {
		return "", errors.New("invalid base58")
	}
	switch len(decoded) {
	case 32:
		pub := deriveSolanaPublicKey(decoded)
		return encodeBase58(pub), nil
	case 64:
		return encodeBase58(decoded[32:]), nil
	default:
		return "", fmt.Errorf("unexpected Solana key length: %d", len(decoded))
	}
}

// ---- Base58 helpers ----

var (
	base58AlphabetBTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	base58LookupBTC   [256]byte
)

func init() {
	for i := range base58LookupBTC {
		base58LookupBTC[i] = 0xFF
	}
	for i, c := range base58AlphabetBTC {
		base58LookupBTC[c] = byte(i)
	}
}

func decodeBase58BTC(s string) ([]byte, bool) {
	var zeroes int
	for zeroes < len(s) && s[zeroes] == '1' {
		zeroes++
	}
	val := new(big.Int)
	for _, c := range s[zeroes:] {
		if c >= 256 || base58LookupBTC[c] == 0xFF {
			return nil, false
		}
		val.Mul(val, big.NewInt(58))
		val.Add(val, big.NewInt(int64(base58LookupBTC[c])))
	}
	decoded := val.Bytes()
	result := make([]byte, zeroes+len(decoded))
	copy(result[zeroes:], decoded)
	return result, true
}

func encodeBase58(data []byte) string {
	var zeroes int
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	val := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	tmp := new(big.Int)
	var encoded []byte
	for val.Cmp(zero) > 0 {
		tmp.Mod(val, base)
		encoded = append(encoded, base58AlphabetBTC[tmp.Int64()])
		val.Div(val, base)
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return strings.Repeat("1", zeroes) + string(encoded)
}

// ---- private key parsing helpers ----

func rawToPrivBytes(privRaw string) ([]byte, error) {
	if isHexKey(privRaw) {
		return hexToPrivBytes(privRaw)
	}
	decoded, ok := decodeBase58BTC(privRaw)
	if !ok || (len(decoded) != 37 && len(decoded) != 38) {
		return nil, errors.New("invalid WIF key")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	h := sha256.Sum256(payload)
	h = sha256.Sum256(h[:])
	for i, b := range checksum {
		if h[i] != b {
			return nil, errors.New("invalid WIF checksum")
		}
	}
	return decoded[1:33], nil
}

func isHexKey(s string) bool {
	h := s
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// ---- DER encoding helpers (used by UTXO sweep) ----

func derEncodeSig(r, s *big.Int) []byte {
	return append(derEncodeInt(r), derEncodeInt(s)...)
}

func derEncodeInt(n *big.Int) []byte {
	b := n.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	encoded := []byte{0x02, byte(len(b))}
	encoded = append(encoded, b...)
	return encoded
}

// ---- Binary encoding helpers (used by sweep files) ----

func uint32LE(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

func uint64LE(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

func varInt(n uint64) []byte {
	switch {
	case n < 0xFD:
		return []byte{byte(n)}
	case n <= 0xFFFF:
		return append([]byte{0xFD}, uint16LE(uint16(n))...)
	case n <= 0xFFFFFFFF:
		return append([]byte{0xFE}, uint32LE(uint32(n))...)
	default:
		return append([]byte{0xFF}, uint64LE(n)...)
	}
}

func uint16LE(n uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)
	return b
}

func pushData(data []byte) []byte {
	if len(data) < 0x4C {
		return append([]byte{byte(len(data))}, data...)
	}
	return append([]byte{0x4C, byte(len(data))}, data...)
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// ---- UTXO address -> script helper ----

func utxoAddrToScript(addr string, verByte byte) ([]byte, error) {
	decoded, ok := decodeBase58BTC(addr)
	if !ok || len(decoded) < 25 {
		return nil, errors.New("invalid address")
	}
	payload := decoded[:len(decoded)-4]
	check := decoded[len(decoded)-4:]
	h := sha256.Sum256(payload)
	h = sha256.Sum256(h[:])
	for i, b := range check {
		if h[i] != b {
			return nil, errors.New("invalid address checksum")
		}
	}
	hash160 := payload[1:21]
	script := []byte{0x76, 0xA9, 0x14}
	script = append(script, hash160...)
	script = append(script, 0x88, 0xAC)
	return script, nil
}

// DeriveAddresses derives all applicable addresses for a FoundKey.
func DeriveAddresses(key FoundKey) (DerivedAddresses, error) {
	var addrs DerivedAddresses
	var lastErr error

	switch key.Chain {
	case "Ethereum", "Polkadot", "Cosmos", "Monero", "Aptos":
		addr, err := DeriveETHAddress(key.Raw)
		if err == nil {
			addrs.ETH = addr
		} else {
			lastErr = err
		}
		btc, err := DeriveBTCAddress(key.Raw)
		if err == nil {
			addrs.BTC = btc
		}

	case "Bitcoin":
		addr, err := DeriveBTCAddress(key.Raw)
		if err == nil {
			addrs.BTC = addr
		} else {
			lastErr = err
		}

	case "Dogecoin":
		addr, err := DeriveDOGEAddress(key.Raw)
		if err == nil {
			addrs.DOGE = addr
		} else {
			lastErr = err
		}

	case "Litecoin":
		addr, err := DeriveLTCAddress(key.Raw)
		if err == nil {
			addrs.LTC = addr
		} else {
			lastErr = err
		}

	case "Stacks":
		addr, err := DeriveSTXAddress(key.Raw)
		if err == nil {
			addrs.STX = addr
		} else {
			lastErr = err
		}

	case "Solana":
		addr, err := DeriveSolanaAddress(key.Raw)
		if err == nil {
			addrs.Solana = addr
		} else {
			lastErr = err
		}

	case "Sui":
		addr, err := DeriveSuiAddress(key.Raw)
		if err == nil {
			addrs.Sui = addr
		} else {
			lastErr = err
		}

	case "Stellar":
		addr, err := DeriveXLMAddress(key.Raw)
		if err == nil {
			addrs.XLM = addr
		} else {
			lastErr = err
		}

	case "Mnemonic":
		derived, err := deriveAddressesFromMnemonic(key.Raw)
		if err != nil {
			lastErr = err
		} else {
			addrs = derived
		}

	case "BIP39 mnemonic":
		addr, err := DeriveBIP39ETH(key.Raw)
		if err == nil {
			addrs.ETH = addr
		} else {
			lastErr = err
		}
		btc, err := DeriveBIP39BTC(key.Raw)
		if err == nil {
			addrs.BTC = btc
		}
	}

	return addrs, lastErr
}
