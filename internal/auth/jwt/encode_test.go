package jwt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncoder_Encode(t *testing.T) {
	var buf [256]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err)

	secret, err := LoadSecret(bytes.NewReader(buf[:]))
	require.NoError(t, err)

	encoder := NewEncoder(secret)

	token, err := encoder.Encode(map[string]any{
		"email":   "joe.doe@example.net",
		"name":    "Joe Doe",
		"picture": "https://example.net/joe.jpg",
	})
	require.NoError(t, err)

	user, err := encoder.Decode(token)
	require.NoError(t, err)

	require.Equal(t, "Joe Doe", user.Name)

	_, err = encoder.Decode(token + "-invalid")
	require.Error(t, err)
}
