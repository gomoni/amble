package jwt

import (
	"fmt"
	"io"
)

type Secret [256]byte

func LoadSecret(r io.Reader) (Secret, error) {
	var s Secret
	n, err := io.ReadFull(r, s[:])
	if err != nil {
		return s, fmt.Errorf("reading secret: %w", err)
	}
	if n != len(s) {
		return s, fmt.Errorf("read len differs, expected 256, got: %d", n)
	}
	return s, nil
}

func (s Secret) Bytes() []byte {
	return s[:]
}
