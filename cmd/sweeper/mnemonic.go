package main

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed bip39_words.txt
var bip39Data string

var bip39WordList []string
var bip39WordIndex map[string]int

func init() {
	fields := strings.Fields(bip39Data)
	bip39WordList = fields
	bip39WordIndex = make(map[string]int, len(fields))
	for i, w := range fields {
		bip39WordIndex[w] = i
	}
}

var validMnemonicLengths = map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}

// findMnemonics scans text for BIP39 mnemonic phrases (12, 15, 18, 21, 24 words).
func findMnemonics(text string) []string {
	normalized := strings.ToLower(strings.TrimSpace(text))
	words := strings.Fields(normalized)
	if len(words) == 0 {
		return nil
	}

	var result []string
	seen := make(map[string]bool)

	for i := 0; i < len(words); i++ {
		if _, ok := bip39WordIndex[words[i]]; !ok {
			continue
		}
		for _, length := range []int{24, 21, 18, 15, 12} {
			if i+length > len(words) {
				continue
			}
			candidate := words[i : i+length]
			allValid := true
			for _, w := range candidate {
				if _, ok := bip39WordIndex[w]; !ok {
					allValid = false
					break
				}
			}
			if !allValid {
				continue
			}
			phrase := strings.Join(candidate, " ")
			if seen[phrase] {
				continue
			}
			if validateBIP39Checksum(phrase) {
				seen[phrase] = true
				result = append(result, phrase)
				i += length - 1
				break
			}
		}
	}
	return result
}

// validateBIP39Checksum validates the BIP39 checksum for a mnemonic phrase.
func validateBIP39Checksum(phrase string) bool {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(phrase)))
	if !validMnemonicLengths[len(words)] {
		return false
	}

	// Convert words to indices
	totalBits := len(words) * 11
	entropyBits := totalBits - totalBits/33
	checkBits := totalBits / 33

	// Build bit array
	bits := make([]bool, 0, totalBits)
	for _, w := range words {
		idx, ok := bip39WordIndex[w]
		if !ok {
			return false
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, (idx>>b)&1 == 1)
		}
	}

	// Extract entropy bytes
	entropyBytes := make([]byte, entropyBits/8)
	for i := 0; i < entropyBits; i++ {
		if bits[i] {
			entropyBytes[i/8] |= 1 << (7 - i%8)
		}
	}

	// Compute SHA256 checksum
	hash := sha256.Sum256(entropyBytes)
	expectedCheck := hash[0] >> (8 - checkBits)

	// Extract actual checksum bits from the last word
	var actualCheck int
	for i := 0; i < checkBits; i++ {
		if bits[entropyBits+i] {
			actualCheck |= 1 << (checkBits - 1 - i)
		}
	}

	return byte(actualCheck) == expectedCheck
}

// deriveAddressesFromMnemonic derives addresses for all supported chains from a BIP39 mnemonic.
func deriveAddressesFromMnemonic(phrase string) (DerivedAddresses, error) {
	seed, err := mnemonicToSeed(phrase, "")
	if err != nil {
		return DerivedAddresses{}, fmt.Errorf("mnemonic to seed: %w", err)
	}

	addrs := DerivedAddresses{}

	// ETH: m/44'/60'/0'/0/0
	ethPriv, err := deriveChild(seed, []uint32{0x80000000 + 44, 0x80000000 + 60, 0x80000000, 0, 0})
	if err == nil {
		if a, e := DeriveETHAddress(fmt.Sprintf("%x", ethPriv)); e == nil {
			addrs.ETH = a
		}
	}

	// BTC: m/44'/0'/0'/0/0
	btcPriv, err := deriveChild(seed, []uint32{0x80000000 + 44, 0x80000000, 0x80000000, 0, 0})
	if err == nil {
		if a, e := DeriveBTCAddress(fmt.Sprintf("%x", btcPriv)); e == nil {
			addrs.BTC = a
		}
	}

	// DOGE: m/44'/3'/0'/0/0
	dogePriv, err := deriveChild(seed, []uint32{0x80000000 + 44, 0x80000000 + 3, 0x80000000, 0, 0})
	if err == nil {
		if a, e := DeriveDOGEAddress(fmt.Sprintf("%x", dogePriv)); e == nil {
			addrs.DOGE = a
		}
	}

	// LTC: m/44'/2'/0'/0/0
	ltcPriv, err := deriveChild(seed, []uint32{0x80000000 + 44, 0x80000000 + 2, 0x80000000, 0, 0})
	if err == nil {
		if a, e := DeriveLTCAddress(fmt.Sprintf("%x", ltcPriv)); e == nil {
			addrs.LTC = a
		}
	}

	// STX: m/44'/5757'/0'/0/0
	stxPriv, err := deriveChild(seed, []uint32{0x80000000 + 44, 0x80000000 + 5757, 0x80000000, 0, 0})
	if err == nil {
		if a, e := DeriveSTXAddress(fmt.Sprintf("%x", stxPriv)); e == nil {
			addrs.STX = a
		}
	}

	// For Ed25519 chains (Solana, Sui, Stellar), use SHA512(seed)[:32]
	edPriv := sha512Sum512(seed)[:32]
	edHex := fmt.Sprintf("%x", edPriv)
	edBase58 := encodeBase58(edPriv)

	if addrs.Solana == "" {
		if a, e := DeriveSolanaAddress(edBase58); e == nil {
			addrs.Solana = a
		}
	}
	if addrs.Sui == "" {
		if a, e := DeriveSuiAddress(edHex); e == nil {
			addrs.Sui = a
		}
	}
	if addrs.XLM == "" {
		if a, e := DeriveXLMAddress(edBase58); e == nil {
			addrs.XLM = a
		}
	}

	return addrs, nil
}

func sha512Sum512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}
