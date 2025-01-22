# accounts

Manages account information and an auth-callback for NATS.

The schema is as follows:
 * `user_info.$uid.app` - user info for the app itself
 * `user_info.$uid.github` - user info for the github
 * `auth_link.$github_sub.github` -> $uid links github login with user id

User oauth2 login is the

1. User logins through IDP, so gets provider name and provider ID (`github` and `sub`ject in case of Github)
2. Store checks the `auth_link` key and return user ID of an user if found.
3. Store can update the `user_info` and return the `auth.UserInfo` from appropriate key
4. TODO: it will apply the needed scopes for NATS auth-callback to work

# auth-callout setup

See https://pkg.go.dev/github.com/nats-io/jwt/v2#ExternalAuthorization on how
to allow specific connections to bypass the callout and be used for
authorization service itself.

Atm web implements the github login flow - would be this done by auth-callout itself?

```go
	code := r.URL.Query().Get("code")
	tok, err := gh.conf.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("GitHub token: %v", tok)

    nc, err := natsAuth(ctx, "github/" + token)
    // nc is now authenticated via github
```

The major question is - would be nat's auth-callout token returned to user? If
xkey - this encryption will be deployed, then it shall work, right?

And ofc - the refresh token shall be stored too. In the future.
