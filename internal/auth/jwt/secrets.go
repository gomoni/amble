package jwt

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
)

type Secret struct {
	private ed25519.PrivateKey
}

func LoadSecret(r io.Reader) (Secret, error) {
	seed, err := io.ReadAll(r)
	if err != nil {
		return Secret{}, fmt.Errorf("read jwt ed25519 seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return Secret{}, fmt.Errorf("insufficient len of jwt ed25519 seed: got %d, expected %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return Secret{private: priv}, nil
}

func (s Secret) Private() crypto.PrivateKey {
	return s.private
}

func (s Secret) Public() crypto.PublicKey {
	return s.private.Public()
}
