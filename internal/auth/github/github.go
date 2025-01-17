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
	conf       auth.OAuth2
	jwtEncoder auth.JWTEncoder
}

func NewLogin(conf auth.OAuth2, encoder auth.JWTEncoder) Login {
	return Login{
		conf:       conf,
		jwtEncoder: encoder,
	}
}

func NewFromSecrets(secrets auth.Secrets, encoder auth.JWTEncoder) Login {
	return Login{
		conf: &oauth2.Config{
			ClientID:     secrets.ClientID,
			ClientSecret: secrets.ClientSecret,
			Scopes:       []string{},
			Endpoint:     github.Endpoint,
		},
		jwtEncoder: encoder,
	}
}

func (gh Login) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !nosurf.VerifyToken(nosurf.Token(r), r.Form.Get(nosurf.FormFieldName)) {
		var reason string
		nosurfErr := nosurf.Reason(r)
		if nosurfErr != nil {
			reason = ": " + nosurfErr.Error()
		}
		http.Error(w, "CSFR protection failed"+reason, http.StatusBadRequest)
		return
	}

	state := auth.State{
		CSRFToken:   nosurf.Token(r),
		RedirectURL: r.Form.Get("next_url"),
	}
	encodedState, err := state.Encode()
	if err != nil {
		http.Error(w, "preparing state parameter for authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	redirectURL := gh.conf.AuthCodeURL(encodedState)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (gh Login) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	var state auth.State
	err := state.Decode(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "decoding state parameter from authentication system: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !nosurf.VerifyToken(nosurf.Token(r), state.CSRFToken) {
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

	if state.RedirectURL == "" {
		w.Header().Set("Content-type", "application/json")
		fmt.Fprint(w, string(respbody))
		return
	} else {
		http.Redirect(w, r, state.RedirectURL, http.StatusSeeOther)
	}
}
