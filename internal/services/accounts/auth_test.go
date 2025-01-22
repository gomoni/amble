/*
End to end test for the auth service.

1. "web" creates a webClaims via auth/jwt.Encode/Decode
2. this is used as a Token for auth-callout
3. the auth callout connect (or reject) the user
4. the user profile is returned so "web" can update and encode claims again

Setup two accounts
  - PLA - aka plainsof
  - DDI - aka devdist
*/
package accounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"html/template"
	"io"
	"testing"
	"time"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/auth/jwt"
	"github.com/gomoni/amble/internal/test"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

const conf = `
jetstream: {}

accounts {
  AUTH: {
	jetstream: enabled,
    users: [
      { 
		user: auth,
		password: auth,
	  }
    ]
  }
  PLA: {}
  DDI: {}
  SYS: {}
}
system_account: SYS

authorization {
  auth_callout {
    issuer: {{.Issuer}}
    auth_users: [ auth ]
    account: AUTH
    xkey: {{.Xkey}}
  }
}
`

func TestAuthCallout(t *testing.T) {
	var buf [ed25519.SeedSize]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err)
	secret, err := jwt.LoadSecret(bytes.NewReader(buf[:]))
	require.NoError(t, err)

	encoder := jwt.NewEncoder(secret)
	//decoder := jwt.NewDecoder(secret.Public())

	calloutServer := requireServer(t)
	t.Cleanup(func() {
		err := calloutServer.natsContainer.Terminate()
		require.NoError(t, err)
	})
	endpoint := calloutServer.natsContainer.Endpoint()

	authNc, err := nats.Connect(endpoint, nats.UserInfo("auth", "auth"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	js, err := jetstream.New(authNc)
	require.NoError(t, err)
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "accounts",
	})
	require.NoError(t, err)
	// nats: API error: code=503 err_code=10039 description=jetstream not enabled for account

	// given there is an octocat user
	store := NewNats(kv)
	uid, err := store.Create(context.Background(), auth.UserInfo{
		Name:    "Octocat",
		Email:   "cat@octocat.example.net",
		Picture: "https://example.net/octocat.png",
	})
	require.NoError(t, err)
	const githubID = "543219"
	err = store.Link(ctx, "github", githubID, uid)
	require.NoError(t, err)

	// and given there are web Claims
	webToken, err := encoder.Encode(jwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "github",
			Subject:   githubID,
			Audience:  []string{},
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(10 * time.Second)),
			NotBefore: gojwt.NewNumericDate(time.Now()),
			IssuedAt:  gojwt.NewNumericDate(time.Now()),
			ID:        githubID,
		},
		UserInfo: auth.UserInfo{
			Name:    "",
			Email:   "",
			Picture: "",
		},
	})
	require.NoError(t, err)

	t.Logf("Web token: %s", webToken)
	octocatNc, err := nats.Connect(endpoint, nats.Token(webToken))
	require.NoError(t, err)
	t.Logf("octocatNc.Opts.Token: %s", octocatNc.Opts.Token)

	err = octocatNc.Publish("auth", []byte("github"))
	require.NoError(t, err)

	// TODO: once this will work, then the user data - like a octocat's user id and so shall be returned
	// TODO: more users with more accounts
	// TODO: auth user must NOT be able to create accounts! This is just a short-cut

	time.Sleep(5 * time.Second)
}

type authCalloutServer struct {
	natsContainer test.NatsContainer
	xkey          keypair
	account       keypair
}

func requireServer(t *testing.T) authCalloutServer {
	t.Helper()
	ctx := context.TODO()

	var err error
	// nsc generate nkey --account
	account, err := nscA()
	require.NoError(t, err)
	// nsc generate nkey --curve
	xkey, err := nscC()
	require.NoError(t, err)
	// nsc generate nkey --curve
	//user, err := nscU()
	//require.NoError(t, err)

	// generate config
	var conf bytes.Buffer
	err = mkconf(&conf, xkey, account)
	require.NoError(t, err)
	t.Logf("config: %s", conf.String())

	// run nats-server with a given config
	natsContainer, err := test.NewNatsContainer(ctx, test.NatsContainerOpts{
		Config: &conf,
	})
	require.NoError(t, err)

	/*
		showLogs := false
		if showLogs {
			logs, err := natsContainer.Logs(ctx)
			require.NoError(t, err)
			defer logs.Close()
			_, err = io.Copy(os.Stdout, logs)
			require.NoError(t, err)
		}
	*/
	return authCalloutServer{
		natsContainer: natsContainer,
		xkey:          xkey,
		account:       account,
	}
}

type keypair struct {
	public string
	seed   []byte
	kp     nkeys.KeyPair
}

func nscA() (keypair, error) {
	return nsc(nkeys.PrefixByteAccount)
}

func nscC() (keypair, error) {
	return nsc(nkeys.PrefixByteCurve)
}

func nscU() (keypair, error) {
	return nsc(nkeys.PrefixByteUser)
}

func nsc(prefix nkeys.PrefixByte) (keypair, error) {
	kp, err := nkeys.CreatePair(prefix)
	if err != nil {
		return keypair{}, err
	}
	public, err := kp.PublicKey()
	if err != nil {
		return keypair{}, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return keypair{}, err
	}
	return keypair{public: public, seed: seed, kp: kp}, nil
}

func mkconf(w io.Writer, xkey, account keypair) error {
	if !nkeys.IsValidPublicCurveKey(xkey.public) {
		return errors.New("Invalid curve key")
	}
	if !nkeys.IsValidPublicAccountKey(account.public) {
		return errors.New("Invalid account key")
	}
	t, err := template.New("nats.conf").Parse(conf)
	if err != nil {
		return err
	}
	return t.Execute(
		w,
		map[string]string{
			"Issuer": account.public,
			"Xkey":   xkey.public,
		},
	)
}
