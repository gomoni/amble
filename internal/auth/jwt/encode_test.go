package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncoder_Encode(t *testing.T) {
	var buf [ed25519.SeedSize]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err)

	secret, err := LoadSecret(bytes.NewReader(buf[:]))
	require.NoError(t, err)

	encoder := NewEncoder(secret)

	token, err := encoder.Encode(map[string]any{
		"email":   "joe.doe@example.net",
		"name":    "Joe Doe",
		"picture": "https://example.net/joe.jpg",
		"iss":     "test",
		"sub":     "12345678",
	})
	require.NoError(t, err)

	claims, err := encoder.Decode(token)
	require.NoError(t, err)

	require.Equal(t, "Joe Doe", claims.Name)

	_, err = encoder.Decode(token + "-invalid")
	require.Error(t, err)
}
