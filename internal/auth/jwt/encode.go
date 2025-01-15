package jwt

import (
	"fmt"

	"github.com/gomoni/amble/internal/auth"

	"github.com/golang-jwt/jwt/v5"
)

type Encoder struct {
	secret Secret
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

	claims := jwt.MapClaims(userInfo)
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tokenWithClaims.SignedString(e.secret.Bytes())
}

func (e Encoder) Decode(tokenString string) (auth.User, error) {
	var zero auth.User
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return e.secret.Bytes(), nil
	})
	if err != nil {
		return zero, fmt.Errorf("parsing token: %w", err)
	}
	if !token.Valid {
		return zero, fmt.Errorf("token is not valid")
	}

	return claimsToUser(claims)
}

func claimsToUser(claims jwt.MapClaims) (user auth.User, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("can't read claims: %v", r)
		}
	}()
	info := Smap(claims)
	user = auth.User{
		ID:      "id-1",
		Name:    info.MustString("name"),
		Email:   info.MustString("email"),
		Picture: info.MustString("picture"),
		Issuer:  info.MustString("iss"),
	}
	return
}
