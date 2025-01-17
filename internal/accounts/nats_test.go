package accounts_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gomoni/amble/internal/test"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"
)

// TODO: reuse auth.Claims here? Or split the openid-like parts of auth.Claims to smaller struct?
type Account struct {
	ID      string `json:"id"`
	Name    string `json:"n"`
	Picture string `json:"p"`
	Email   string `json:"e"`
}

type AccountService interface {
	Login(ctx context.Context, provider string, userInfo map[string]any) (Account, error)
}

func (a Account) AsJSON() ([]byte, error) {
	return json.Marshal(a)
}

func TestMe(t *testing.T) {
	server, err := test.NewNatsContainer(context.Background(), test.NatsContainerOpts{})
	require.NoError(t, err)
	t.Cleanup(func() {
		err := server.Terminate()
		require.NoError(t, err)
	})

	nc, err := nats.Connect(server.Endpoint())
	require.NoError(t, err)

	t.Run("test if it already works", func(t *testing.T) {
		pubCtx, cancel := context.WithCancel(context.Background())

		i := 0
		_, err = nc.Subscribe("hello", func(msg *nats.Msg) {
			t.Logf("Received message: %s", string(msg.Data))
			i++
			if i == 10 {
				cancel()
			}
		})
		require.NoError(t, err)

		for _, s := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
			err = nc.Publish("hello", []byte("world: "+s))
			require.NoError(t, err)
			time.Sleep(100 * time.Millisecond)
		}
		<-pubCtx.Done()
	})

	// create k/v bucket
	ctx := context.Background()
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "accounts",
	})
	require.NoError(t, err)

	// create new account
	b, err := json.Marshal(Account{
		ID:      "acc_123",
		Name:    "Octocat",
		Email:   "cat@octocat.example.net",
		Picture: "https://example.net/octocat.png",
	})
	require.NoError(t, err)
	_, err = kv.Create(ctx, "acc_123.openid", b)
	require.NoError(t, err)

	// create a link from user to github login
	const githubID = "583231"
	_, err = kv.Create(ctx, "github."+githubID+".link", []byte("acc_123"))
	require.NoError(t, err)

	// store a github user info
	_, err = kv.Create(ctx, "github."+githubID+".user_info", []byte(`{"login": "octocat", "id": 583231}`))
	require.NoError(t, err)

	// login via github is then -> get a link for a github ID
	ret, err := kv.Get(ctx, "github."+githubID+".link")
	require.NoError(t, err)
	accountID := string(ret.Value())
	require.Equal(t, "acc_123", accountID)

	// read account info
	ret, err = kv.Get(ctx, accountID+".openid")
	require.NoError(t, err)

	var acc Account
	err = json.Unmarshal(ret.Value(), &acc)
	require.NoError(t, err)

	t.Logf("Account: %+v", acc)
	require.Equal(t, "Octocat", acc.Name)
}
