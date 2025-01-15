package github

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/auth/jwt"

	"github.com/justinas/nosurf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const userInfoEndpoint = "https://api.github.com/user"

type Login struct {
	conf        auth.OAuth2
	jwtEncoder  auth.JWTEncoder
	redirectURL string
}

var csrfMW = nosurf.New

func NewLogin(conf auth.OAuth2) Login {
	return Login{conf: conf}
}

func FromSecrets(secrets auth.Secrets) Login {
	return Login{
		conf: &oauth2.Config{
			ClientID:     secrets.ClientID,
			ClientSecret: secrets.ClientSecret,
			Scopes:       []string{},
			Endpoint:     github.Endpoint,
		},
	}
}

func (gh Login) WithJWTEncoder(jwtEncoder auth.JWTEncoder) Login {
	gh.jwtEncoder = jwtEncoder
	return gh
}
func (gh Login) WithRedirectURL(redirectURL string) Login {
	gh.redirectURL = redirectURL
	return gh
}

func (gh Login) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// CSRF protection - too important for authn to be left to the caller.
	h := csrfMW(http.HandlerFunc(gh.loginHandler))
	h.ServeHTTP(w, r)
}

func (gh Login) loginHandler(w http.ResponseWriter, r *http.Request) {
	token := nosurf.Token(r)
	redirectURL := gh.conf.AuthCodeURL(token)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (gh Login) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	h := csrfMW(http.HandlerFunc(gh.callbackHandler))
	h.ServeHTTP(w, r)
}

func (gh Login) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if !nosurf.VerifyToken(nosurf.Token(r), r.URL.Query().Get("state")) {
		var reason string
		nosurfErr := nosurf.Reason(r)
		if nosurfErr != nil {
			reason = ": " + nosurfErr.Error()
		}
		http.Error(w, "CSFR protection failed"+reason, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	tok, err := gh.conf.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("GitHub token: %v", tok)

	// This client will have a bearer token to access the GitHub API on
	// the user's behalf.
	client := gh.conf.Client(r.Context(), tok)
	resp, err := client.Get(userInfoEndpoint)
	if err != nil {
		http.Error(w, "get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respbody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var userInfo map[string]any
	err = json.Unmarshal(respbody, &userInfo)
	if err != nil {
		http.Error(w, "parse user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	smap := jwt.Smap(userInfo)
	user := map[string]any{
		"iss":     "github",
		"sub":     "user-1",
		"aud":     r.Host,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"nbf":     time.Now().Unix(),
		"iat":     time.Now().Unix(),
		"id":      "user-1",
		"email":   smap.Must("email"),
		"name":    smap.Must("name"),
		"picture": smap.Must("avatar_url"),
	}

	jwtToken, err := gh.jwtEncoder.Encode(user)
	if err != nil {
		http.Error(w, "encode JWT: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "Authorization",
		Value:    "Bearer " + jwtToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Use secure cookies in production
		Path:     "/",
	})

	if gh.redirectURL == "" {
		w.Header().Set("Content-type", "application/json")
		fmt.Fprint(w, string(respbody))
		return
	} else {
		http.Redirect(w, r, gh.redirectURL, http.StatusSeeOther)
	}
}
