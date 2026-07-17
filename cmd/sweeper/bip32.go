package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// secp256k1N is the order of the secp256k1 curve, used for BIP32 child key derivation.
var secp256k1N, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// compressedPubKeyFromBytes derives the 33-byte compressed public key from a 32-byte private key.
func compressedPubKeyFromBytes(privBytes []byte) []byte {
	return secp.PrivKeyFromBytes(privBytes).PubKey().SerializeCompressed()
}

// DeriveBIP39ETH derives the ETH address for the first account of a mnemonic
// using the standard path m/44'/60'/0'/0/0.
func DeriveBIP39ETH(mnemonic string) (string, error) {
	seed, err := mnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", err
	}
	// m/44'/60'/0'/0/0
	privKey, err := deriveChild(seed, []uint32{
		0x80000000 + 44, // purpose
		0x80000000 + 60, // coin type ETH
		0x80000000 + 0,  // account
		0,               // change
		0,               // address index
	})
	if err != nil {
		return "", err
	}
	key, err := parseSecp256k1PrivKey(fmt.Sprintf("%x", privKey))
	if err != nil {
		return "", err
	}
	return "0x" + ethAddressFromKey(key), nil
}

// DeriveBIP39BTC derives the BTC P2PKH address for m/44'/0'/0'/0/0.
func DeriveBIP39BTC(mnemonic string) (string, error) {
	seed, err := mnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", err
	}
	// m/44'/0'/0'/0/0
	privKey, err := deriveChild(seed, []uint32{
		0x80000000 + 44,
		0x80000000 + 0, // coin type BTC
		0x80000000 + 0,
		0,
		0,
	})
	if err != nil {
		return "", err
	}
	return DeriveBTCAddress(fmt.Sprintf("%x", privKey))
}

// mnemonicToSeed converts a BIP39 mnemonic to a 512-bit seed using PBKDF2-SHA512.
// BIP39 specifies: PBKDF2(mnemonic, "mnemonic"+passphrase, 2048 iterations, 64 bytes, SHA-512).
func mnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return nil, fmt.Errorf("invalid mnemonic length: %d words", len(words))
	}
	password := []byte(strings.Join(words, " "))
	salt := []byte("mnemonic" + passphrase)
	return pbkdf2Key(password, salt, 2048, 64, sha512.New), nil
}

// pbkdf2Key is an inline PBKDF2 implementation (RFC 2898) to avoid adding a
// direct dependency on golang.org/x/crypto/pbkdf2.
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	var buf [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		U := prf.Sum(nil)
		T := make([]byte, hashLen)
		copy(T, U)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(nil)
			for i := range T {
				T[i] ^= U[i]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

// deriveChild performs BIP32 private key derivation along a path from a seed.
func deriveChild(seed []byte, path []uint32) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	kParent := I[:32]
	cParent := I[32:]

	for _, index := range path {
		var data []byte
		hardened := index >= 0x80000000
		if hardened {
			// Hardened: data = 0x00 || kParent || index (big-endian)
			data = append([]byte{0x00}, kParent...)
		} else {
			// Normal: data = compressedPubKeyFromBytes(kParent) || index
			data = compressedPubKeyFromBytes(kParent)
		}
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, index)
		data = append(data, indexBytes...)

		mac = hmac.New(sha512.New, cParent)
		mac.Write(data)
		I = mac.Sum(nil)

		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(secp256k1N) >= 0 {
			return nil, errors.New("derived key is invalid (IL >= N)")
		}
		kParentInt := new(big.Int).SetBytes(kParent)
		child := new(big.Int).Add(iL, kParentInt)
		child.Mod(child, secp256k1N)
		if child.Sign() == 0 {
			return nil, errors.New("derived key is zero")
		}
		childBytes := child.Bytes()
		// Pad to 32 bytes.
		kParent = make([]byte, 32)
		copy(kParent[32-len(childBytes):], childBytes)
		cParent = I[32:]
	}
	return kParent, nil
}
