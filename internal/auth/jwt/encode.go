package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/gomoni/amble/internal/auth"
)

type RegisteredClaims = jwt.RegisteredClaims

// Claims is a standard JWT claims with and a few stuff from OpenID Connect https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// simplifying an usage
type Claims struct {
	RegisteredClaims
	auth.UserInfo
}

type Encoder struct {
	secret Secret
}

func NewEncoder(secret Secret) Encoder {
	return Encoder{secret: secret}
}

func (e Encoder) Encode(claims Claims) (token string, err error) {
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return tokenWithClaims.SignedString(e.secret.Private())
}
