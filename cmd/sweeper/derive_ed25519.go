package main

import (
	stdEd25519 "crypto/ed25519"
)

// deriveSolanaPublicKey returns the 32-byte ed25519 public key for a 32-byte seed.
// This is used by DeriveSolanaAddress in derivation.go.
func deriveSolanaPublicKey(seed []byte) []byte {
	privKey := stdEd25519.NewKeyFromSeed(seed)
	return []byte(privKey.Public().(stdEd25519.PublicKey))
}
