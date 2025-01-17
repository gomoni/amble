package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/auth/github"
	"github.com/gomoni/amble/internal/auth/jwt"
	"github.com/gomoni/amble/internal/web"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
)

const credentialsDir = `secrets/`
const servingSchema = "http://"
const servingAddress = "localhost:8000"

var csrfMW = nosurf.NewPure

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	githubSecrets, err := loadAuthSecrets(credentialsDir, "github.secrets.json")
	if err != nil {
		return fmt.Errorf("load github secrets: %w", err)
	}

	jwtSecrets, err := loadJWTSecrets(credentialsDir, "jwt.ed25519.seed")
	if err != nil {
		return fmt.Errorf("load jwt secrets: %w", err)
	}
	jwtEncoder := jwt.NewEncoder(jwtSecrets)

	githubLogin := github.NewFromSecrets(githubSecrets, jwtEncoder)

	logged := logged{jwtDecoder: jwtEncoder}

	mux := http.NewServeMux()

	loginForm := alice.New(csrfMW)
	auth := alice.New(csrfMW)

	mux.Handle("GET /{$}", loginForm.ThenFunc(handleIndex))
	mux.HandleFunc("/dashboard", logged.handleDashboard)
	mux.Handle("/auth/github/login", auth.ThenFunc(githubLogin.LoginHandler))
	mux.Handle("/auth/github/callback", auth.ThenFunc(githubLogin.CallbackHandler))

	log.Printf("Listening on: %s%s\n", servingSchema, servingAddress)
	return http.ListenAndServe(servingAddress, mux)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	index := web.Index(nosurf.FormFieldName, nosurf.Token(r))
	web.Serve(index, w, r)
}

type logged struct {
	jwtDecoder jwt.Encoder
}

func (l logged) handleDashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Error(w, "missing cookie", http.StatusUnauthorized)
		return
	}
	claims, err := l.jwtDecoder.Decode(strings.TrimPrefix(cookie.Value, "Bearer "))
	if err != nil {
		http.Error(w, "can't decode authorization cookie: "+err.Error(), http.StatusUnauthorized)
		return
	}

	const rootHTML = `
<body>
	<h1>Hello, %s</h1>
	<p>Authenticated via %s</p>
	<p>Email address: %s</p>
	<img src="%s" alt="avatar">
</body>
`
	fmt.Fprintf(w, rootHTML, claims.Name, claims.Issuer, claims.Email, claims.Picture)
}

func loadAuthSecrets(credentialsDir string, path string) (auth.Secrets, error) {
	var secrets auth.Secrets
	f, err := os.Open(filepath.Join(credentialsDir, path))
	if err != nil {
		return secrets, fmt.Errorf("open secrets file %s: %w", path, err)
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&secrets)
	if err != nil {
		return secrets, fmt.Errorf("decode secrets from json %s: %w", path, err)
	}
	if secrets.ClientID == "" {
		return secrets, fmt.Errorf("missing client id in %s", path)
	}
	if secrets.ClientSecret == "" {
		return secrets, fmt.Errorf("missing client secret in %s", path)
	}
	return secrets, nil
}

func loadJWTSecrets(credentialsDir, path string) (jwt.Secret, error) {
	f, err := os.Open(filepath.Join(credentialsDir, path))
	if err != nil {
		return jwt.Secret{}, fmt.Errorf("open secrets file %s: %w", path, err)
	}
	defer f.Close()
	ret, err := jwt.LoadSecret(f)
	if err != nil {
		return jwt.Secret{}, fmt.Errorf("read from secrets file %s: %w", path, err)
	}
	return ret, nil
}
