package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Encoder struct {
	secret Secret
}

// Claims is a standard JWT claims with and a few stuff from OpenID Connect https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// simplifying an usage
type Claims struct {
	jwt.RegisteredClaims
	UserID  string `json:"uid"` // this is amble's own unique userID
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

func NewEncoder(secret Secret) Encoder {
	return Encoder{secret: secret}
}

func (e Encoder) Encode(userInfo map[string]any) (token string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("can't read userInfo: %v", r)
		}
	}()

	info := Smap(userInfo)

	/*
	   https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims#registered-claims
	   * iss (issuer): Issuer of the JWT
	   * sub (subject): Subject of the JWT (the user)
	   * aud (audience): Recipient for which the JWT is intended
	   * exp (expiration time): Time after which the JWT expires
	   * nbf (not before time): Time before which the JWT must not be accepted for processing
	   * iat (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT
	   * jti (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
	*/

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "amble",
			Subject:   info.MustString("sub"),
			Audience:  []string{"amble-web"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "",
		},
		UserID:  "user_todo",
		Email:   info.MustString("email"),
		Name:    info.MustString("name"),
		Picture: info.MustString("picture"),
	}

	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return tokenWithClaims.SignedString(e.secret.Private())
}

func (e Encoder) Decode(tokenString string) (Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return e.secret.Public(), nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("parsing token: %w", err)
	}
	if !token.Valid {
		return Claims{}, fmt.Errorf("token is not valid")
	}

	return claims, nil
}
