/*
Package nats provide a NATS based implementation of accounts store

Expected usage if from login subsystem

  - user logs via github
  - github returns user info including "sub"
  - `auth_link.$github_sub.github` is then queried to get a linked user id
  - `user_info.$uid.app` contains relevant user data
*/
package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"

	"github.com/gomoni/amble/internal/auth"
	"github.com/gomoni/amble/internal/tid"
	"github.com/nats-io/nats.go/jetstream"
)

type Accounts struct {
	kv jetstream.KeyValue
}

func NewNats(kv jetstream.KeyValue) Accounts {
	return Accounts{kv: kv}
}

// Create creates a new account based on user info. Store to `amble.$user_id.user_info` key
func (n Accounts) Create(ctx context.Context, userInfo auth.UserInfo) (tid.UserID, error) {
	uid, err := tid.NewUserID()
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: generate user id: %w", err)
	}
	userInfo.UserID = uid
	b, err := json.Marshal(userInfo)
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: marshal user data: %w", err)
	}
	_, err = n.kv.Create(ctx, "user_info."+uid.String()+".app", b)
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account create: marshal user data: %w", err)
	}
	return uid, nil
}

func (n Accounts) Get(ctx context.Context, uid tid.UserID) (auth.UserInfo, error) {
	b, err := n.kv.Get(ctx, "user_info."+uid.String()+".app")
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

func (n Accounts) Link(ctx context.Context, provider, id string, uid tid.UserID) error {
	key := strings.Join([]string{"auth_link", provider, id}, ".")
	_, err := n.kv.Create(ctx, key, []byte(uid.String()))
	return err
}

// Linked returns the user id for given provider/provider id pair
func (n Accounts) Linked(ctx context.Context, provider, id string) (tid.UserID, error) {
	key := strings.Join([]string{"auth_link", provider, id}, ".")
	b, err := n.kv.Get(ctx, key)
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account get linked: %w", err)
	}
	uid, err := tid.ParseUserID(string(b.Value()))
	if err != nil {
		return tid.UserID{}, fmt.Errorf("account get linked: parse user id: %w", err)
	}
	return uid, nil
}

func (n Accounts) UpdateUserInfo(ctx context.Context, provider string, uid tid.UserID, userInfo map[string]any) error {
	b, err := json.Marshal(userInfo)
	if err != nil {
		return fmt.Errorf("account update user info: marshal %s user data: %w", provider, err)
	}
	_, err = n.kv.Put(ctx, "user_info."+uid.String()+"."+provider, b)
	if err != nil {
		return fmt.Errorf("account update user info: %w", err)
	}
	return nil
}

// The nats docu says:
// > lister will always close the channel when done (either all keys have
// > been read or an error occurred) and therefore can be used in range loops.
// > Stop can be used to stop the lister when not all keys have been read.
// Does that really work?

func (n Accounts) Lister() Lister {
	return Lister{
		kv: n.kv,
		n:  n,
	}
}

type Lister struct {
	kv         jetstream.KeyValue
	n          Accounts
	keyMatcher func(string) bool
	errs       []error
}

func (l Lister) WithKeyMatcher(f func(string) bool) Lister {
	return Lister{
		kv:         l.kv,
		n:          l.n,
		keyMatcher: f,
	}
}

func (l Lister) WithPattern(pattern string) Lister {
	return Lister{
		kv:         l.kv,
		n:          l.n,
		keyMatcher: func(subject string) bool { return MatchSubject(pattern, subject) },
	}
}

func (l Lister) Iter(ctx context.Context) (iter.Seq[auth.UserInfo], error) {
	l.errs = make([]error, 0)
	kl, err := l.kv.ListKeys(ctx, jetstream.MetaOnly(), jetstream.IgnoreDeletes())
	if err != nil {
		return nil, fmt.Errorf("account list: create key lister: %w", err)
	}

	s := func(yield func(auth.UserInfo) bool) {
		for key := range kl.Keys() {
			if !l.keyMatcher(key) {
				continue
			}
			x := key[len("amble.") : len(key)-len(".user_info")]
			uid, err := tid.ParseUserID(x)
			if err != nil {
				l.errs = append(l.errs, fmt.Errorf("account list: parse user id %q: %w", x, err))
				continue
			}
			account, err := l.n.Get(ctx, uid)
			if err != nil {
				l.errs = append(l.errs, fmt.Errorf("account list: get id %s: %w", uid.String(), err))
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

func (l Lister) Errors() []error {
	return l.errs
}

// FIXME: seems implemented by https://pkg.go.dev/github.com/nats-io/jwt/v2#Subject.IsContainedIn
// MatchSubject implements a wildcard matching of NATS
// foo.*.bar matches foo.1.bar, foo.2.bar, etc., but not foo.1.bar.baz
// foo.bar.> matches foo.bar.baz, foo.bar.baz.1, but not foo.bar
func MatchSubject(pattern, subject string) bool {
	// reject invalid characters
	if strings.ContainsAny(pattern, "\x00 ") || strings.ContainsAny(subject, "\x00 >*") {
		return false
	}
	if idx := strings.Index(pattern, ">"); idx != -1 {
		if idx != len(pattern)-1 {
			return false
		}
	}
	patternParts := strings.Split(pattern, ".")
	subjectParts := strings.Split(subject, ".")
	greedy := patternParts[len(patternParts)-1] == ">"
	if greedy {
		if len(patternParts) > len(subjectParts) {
			return false
		}
		patternParts = patternParts[:len(patternParts)-1]
		for i, part := range patternParts {
			if part != "*" && part != subjectParts[i] {
				return false
			}
		}
		return true
	}
	if len(patternParts) != len(subjectParts) {
		return false
	}
	for i, part := range patternParts {
		if part != "*" && part != subjectParts[i] {
			return false
		}
	}
	return true
}
