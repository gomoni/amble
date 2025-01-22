package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/tid"
	"github.com/stretchr/testify/require"
)

func TestEncoder_Encode(t *testing.T) {
	var buf [ed25519.SeedSize]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err)
	secret, err := LoadSecret(bytes.NewReader(buf[:]))
	require.NoError(t, err)

	uid, err := tid.NewUserID()
	require.NoError(t, err)

	encoder := NewEncoder(secret)
	decoder := NewDecoder(secret.Public())

	claims := Claims{
		jwt.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "subject",
			Audience:  []string{"audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "jti",
		},
		auth.UserInfo{
			UserID:  uid,
			Name:    "name",
			Email:   "email@example.net",
			Picture: "https://example.net/joe.png?v42",
		},
	}

	token, err := encoder.Encode(claims)
	require.NoError(t, err)

	decoded, err := decoder.Decode(token)
	require.NoError(t, err)

	require.Equal(t, "name", decoded.Name)
	require.Equal(t, decoded, claims)

	_, err = decoder.Decode(token + "-invalid")
	require.Error(t, err)
}
