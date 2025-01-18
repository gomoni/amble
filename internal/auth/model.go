package auth

import (
	"context"
	"net/http"

	"github.com/gomoni/amble/internal/tid"
	"golang.org/x/oauth2"
)

type UserInfo struct {
	UserID  tid.UserID `json:"uid"`
	Name    string     `json:"name"`
	Email   string     `json:"email"`
	Picture string     `json:"picture"`
}

type OAuth2 interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Client(ctx context.Context, token *oauth2.Token) *http.Client
}

type JWTEncoder interface {
	Encode(claims map[string]any) (string, error)
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
