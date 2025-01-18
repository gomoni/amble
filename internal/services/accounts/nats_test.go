package accounts_test

import (
	"context"
	"testing"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/services/accounts"
	"github.com/gomoni/amble/internal/test"
	"github.com/gomoni/amble/internal/tid"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"
)

func TestMe(t *testing.T) {
	server, err := test.NewNatsContainer(context.Background(), test.NatsContainerOpts{})
	require.NoError(t, err)
	t.Cleanup(func() {
		err := server.Terminate()
		require.NoError(t, err)
	})

	nc, err := nats.Connect(server.Endpoint())
	require.NoError(t, err)

	// create k/v bucket
	ctx := context.Background()
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "accounts",
	})
	require.NoError(t, err)

	store := accounts.NewNats(kv)
	uid, err := store.Create(context.Background(), auth.UserInfo{
		Name:    "Octocat",
		Email:   "cat@octocat.example.net",
		Picture: "https://example.net/octocat.png",
	})
	require.NoError(t, err)

	account, err := store.Get(context.Background(), uid)
	require.NoError(t, err)
	t.Logf("User info: %#v", account)

	fakeUid, err := tid.NewUserID()
	require.NoError(t, err)

	_, err = store.Get(context.Background(), fakeUid)
	require.Error(t, err)
	t.Logf("Error: %v", err)

	kl, err := kv.ListKeys(ctx, jetstream.MetaOnly(), jetstream.IgnoreDeletes())
	require.NoError(t, err)
	for key := range kl.Keys() {
		t.Logf("Key: %s", key)
	}

	s, err := store.List(ctx, "amble.*.user_info")
	require.NoError(t, err)
	for user := range s {
		t.Logf("User: %v", user)
	}

	return

	/*
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
	*/
}
