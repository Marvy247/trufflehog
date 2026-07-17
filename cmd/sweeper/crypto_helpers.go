package main

import (
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

func keccak256Hash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func parseSecp256k1PrivKey(hexStr string) (*secp.PrivateKey, error) {
	privBytes, err := hexToPrivBytes(hexStr)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 key: %w", err)
	}
	return secp.PrivKeyFromBytes(privBytes), nil
}

func ethAddressFromKey(key *secp.PrivateKey) string {
	pub := key.PubKey().SerializeUncompressed()
	return keccakAddress(pub[1:])
}
