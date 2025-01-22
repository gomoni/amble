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
	t.Logf("User info: %T %#v", account, account)

	fakeUid, err := tid.NewUserID()
	require.NoError(t, err)

	_, err = store.Get(context.Background(), fakeUid)
	require.Error(t, err)
	t.Logf("Error: %T %v", err, err)

	kl, err := kv.ListKeys(ctx, jetstream.MetaOnly(), jetstream.IgnoreDeletes())
	require.NoError(t, err)
	for key := range kl.Keys() {
		t.Logf("Key: %s", key)
	}

	s, err := store.Lister().WithPattern("amble.*.user_info").Iter(ctx)
	require.NoError(t, err)
	var user auth.UserInfo
	for u := range s {
		user = u
	}

	t.Logf("User info: %#v", user)

	const githubID = "583231"
	_, err = kv.Create(ctx, "auth_link.github."+githubID, []byte(uid.String()))
	require.NoError(t, err)

	// ensure there is a linked user
	uid2, err := store.Linked(ctx, "github", githubID)
	require.NoError(t, err)
	require.Equal(t, uid, uid2)

	err = store.UpdateUserInfo(ctx, "github", uid, map[string]any{
		"sub":   githubID,
		"login": "octocat",
	})
	require.NoError(t, err)
}

func TestMatchSubjects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		subject string
		match   bool
	}{
		{"a", "", false},
		{"a", "a", true},
		{"a", "b", false},
		{"a.b", "a", false},
		{"a.b", "a.b", true},
		{"a.b", "a.c", false},
		{"a.b.c", "", false},
		{"a.b.c", "a", false},
		{"a.b.c", "a.b", false},
		{"a.b.c", "a.b.", false},
		{"a.b.c", "a.b.d", false},
		{"a.b.c", "a.b.c", true},
		{"a.*", "", false},
		{"a.*", "a", false},
		{"a.*", "a.b.c", false},
		{"a.*", "a.b", true},
		{"a.*", "a.xyz", true},
		{"*.a", "", false},
		{"*.a", "a", false},
		{"*.a", "a.b.c", false},
		{"*.a", "a.a", true},
		{"*.a", "xyz.a", true},
		{"*.a", "x.a", true},
		{"a.>", "", false},
		{"a.>", "a", false},
		{"a.>", "a.b", true},
		{"a.>", "a.xyz", true},
		{"a.>", "a.b.c", true},
		{"a.>", "a.b.xyz", true},
		{"*.>", "", false},
		{"*.>", "a", false},
		{"*.>", "a.b", true},
		{"*.>", "xyz.b", true},
		{"*.>", "c.b.d.e", true},
		{"*.>", "x.y.z", true},
	}

	for _, test := range tests {
		t.Run(test.pattern+"-"+test.subject, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.match, accounts.MatchSubject(test.pattern, test.subject))
		})
	}
}
