package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/tid"
	"github.com/nats-io/nats.go/jetstream"
)

type Nats struct {
	kv jetstream.KeyValue
}

func NewNats(kv jetstream.KeyValue) Nats {
	return Nats{kv: kv}
}

// Create creates a new account based on user info. Store to `amble.$user_id.user_info` key
func (n Nats) Create(ctx context.Context, userInfo auth.UserInfo) (tid.UserID, error) {
	uid, err := tid.NewUserID()
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: generate user id: %w", err)
	}
	userInfo.UserID = uid
	b, err := json.Marshal(userInfo)
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: marshal user data: %w", err)
	}
	_, err = n.kv.Create(ctx, "amble."+uid.String()+".user_info", b)
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: marshal user data: %w", err)
	}
	return uid, nil
}

func (n Nats) Get(ctx context.Context, uid tid.UserID) (auth.UserInfo, error) {
	b, err := n.kv.Get(ctx, "amble."+uid.String()+".user_info")
	if err != nil {
		return auth.UserInfo{}, fmt.Errorf("account get: %w", err)
	}
	var userInfo auth.UserInfo
	err = json.Unmarshal(b.Value(), &userInfo)
	if err != nil {
		return auth.UserInfo{}, fmt.Errorf("account get: unmarshal user data: %w", err)
	}
	return userInfo, nil
}

// TODO: List method
// List(ctx, "amble.*.user_info") (iter.Seq, error)
// Usage
// for _, user_info := range store.List(ctx, "amble.*.user_info") {
//   fmt.Printf("User info: %v", user_info)
// }

// The lister will always close the channel when done (either all keys have
// been read or an error occurred) and therefore can be used in range loops.
// Stop can be used to stop the lister when not all keys have been read.

// TODO: figure out how to return an errors - log them, store them in map/array?

func (n Nats) List(ctx context.Context, pattern string) (iter.Seq[auth.UserInfo], error) {
	kl, err := n.kv.ListKeys(ctx, jetstream.MetaOnly(), jetstream.IgnoreDeletes())
	if err != nil {
		return nil, fmt.Errorf("account list: create key lister: %w", err)
	}

	s := func(yield func(auth.UserInfo) bool) {
		for key := range kl.Keys() {
			// TODO: figure this out
			//if !jetstream.Match(key, pattern) {
			//	continue
			//}
			x := key[len("amble.") : len(key)-len(".user_info")]
			uid, err := tid.ParseUserID(x)
			if err != nil {
				log.Printf("account list: parse user id %q: %v", x, err)
				continue
			}
			account, err := n.Get(ctx, uid)
			if err != nil {
				log.Printf("account list: get user id %q: %v", x, err)
				continue
			}
			if !yield(account) {
				_ = kl.Stop()
				break
			}
		}
	}
	return s, nil
}
