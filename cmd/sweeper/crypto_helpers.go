package main

import "golang.org/x/crypto/sha3"

// keccak256Hash returns the Keccak-256 hash of data.
func keccak256Hash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
