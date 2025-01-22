package jwt

import (
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Decoder struct {
	publicKey crypto.PublicKey
}

func NewDecoder(publicKey crypto.PublicKey) Decoder {
	return Decoder{publicKey: publicKey}
}

func (d Decoder) Decode(tokenString string) (Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return d.publicKey, nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("parsing token: %w", err)
	}
	if !token.Valid {
		return Claims{}, fmt.Errorf("token is not valid")
	}

	return claims, nil
}
