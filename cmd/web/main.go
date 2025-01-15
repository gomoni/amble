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
)

const credentialsDir = `secrets/`
const servingSchema = "http://"
const servingAddress = "localhost:8000"

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

	jwtSecrets, err := loadJWTSecrets(credentialsDir, "jwt.secrets.dat")
	if err != nil {
		return fmt.Errorf("load jwt secrets: %w", err)
	}
	jwtEncoder := jwt.NewEncoder(jwtSecrets)

	githubLogin := github.FromSecrets(githubSecrets).WithJWTEncoder(jwtEncoder).WithRedirectURL("/dashboard")

	logged := logged{jwtDecoder: jwtEncoder}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/dashboard", logged.handleDashboard)
	mux.HandleFunc("/auth/github/login", githubLogin.LoginHandler)
	mux.HandleFunc("/auth/github/callback", githubLogin.CallbackHandler)

	log.Printf("Listening on: %s%s\n", servingSchema, servingAddress)
	return http.ListenAndServe(servingAddress, mux)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	index := web.Index()
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
	user, err := l.jwtDecoder.Decode(strings.TrimPrefix(cookie.Value, "Bearer "))
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
	fmt.Fprintf(w, rootHTML, user.Name, user.Issuer, user.Email, user.Picture)
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
	if len(ret) < 200 {
		return jwt.Secret{}, fmt.Errorf("too small %s: expected 256, got %d", path, len(ret))
	}
	return ret, nil
}
