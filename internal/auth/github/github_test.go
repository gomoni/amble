package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gomoni/amble/internal/auth/github"
	"github.com/gomoni/amble/internal/test"
	"github.com/justinas/nosurf"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const githubUserInfo = `{
  "login": "octocat",
  "id": 583231,
  "node_id": "MDQ6VXNlcjg4MzA2NzY=",
  "avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4",
  "gravatar_id": "",
  "url": "https://api.github.com/users/octocat",
  "html_url": "https://github.com/octocat",
  "followers_url": "https://api.github.com/users/octocat/followers",
  "following_url": "https://api.github.com/users/octocat/following{/other_user}",
  "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
  "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
  "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
  "organizations_url": "https://api.github.com/users/octocat/orgs",
  "repos_url": "https://api.github.com/users/octocat/repos",
  "events_url": "https://api.github.com/users/octocat/events{/privacy}",
  "received_events_url": "https://api.github.com/users/octocat/received_events",
  "type": "User",
  "user_view_type": "public",
  "site_admin": false,
  "name": "The Octocat",
  "company": null,
  "blog": "https://octocat.example.net",
  "location": "Octocity",
  "email": "cat@octocat.example.net",
  "hireable": true,
  "bio": "Homepage: https://octocat.example.net",
  "twitter_username": null,
  "notification_email": "github@octocat.example.net",
  "public_repos": 142,
  "public_gists": 42,
  "followers": 242,
  "following": 4,
  "created_at": "2006-01-02T06:02:12Z",
  "updated_at": "2025-01-15T09:43:23Z"
	}`

type oauth2Mock struct {
	mock.Mock
}

func (o *oauth2Mock) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	args := o.Called(state, opts)
	return args.String(0)
}

func (o *oauth2Mock) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	args := o.Called(ctx, code, opts)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (o *oauth2Mock) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	args := o.Called(ctx, token)
	return args.Get(0).(*http.Client)
}

func TestGithubLogin(t *testing.T) {
	const authURL = "https://github.example.net/auth"

	oauth2Mock := &oauth2Mock{}
	//t.Cleanup(func() { oauth2Mock.AssertExpectations(t) })
	// given a github login handlers
	login := github.NewLogin(oauth2Mock)

	oauth2Mock.On(
		"AuthCodeURL",
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(authURL + "?state=csrf_token")

	// when login handler is called
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	login.LoginHandler(w, r)
	cookies := w.Result().Cookies()

	// then it should redirect
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, authURL+"?state=csrf_token", w.Header().Get("Location"))

	// and a CSRF protection cookie should be set
	token := csrfToken(w.Result().Cookies())
	require.NotEmpty(t, token)
	require.True(t, len(token) >= 16)

	// given guthub user API provides a mocked response
	githubInfoHandlerFunc :=
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(githubUserInfo))
			require.NoError(t, err)
		}
	infoServer := httptest.NewServer(http.HandlerFunc(githubInfoHandlerFunc))
	t.Cleanup(infoServer.Close)
	u, err := url.Parse(infoServer.URL)
	require.NoError(t, err)

	// and given used client calls httptest server instead of api.github.com here
	infoClient := infoServer.Client()
	infoClient.Transport = test.RewriteTransport{Transport: infoClient.Transport, URL: u}

	oauth2Token := oauth2.Token{
		AccessToken: "access_token",
		TokenType:   "Bearer",
		ExpiresIn:   time.Now().Add(time.Hour).Unix(),
	}
	oauth2Mock.On(
		"Exchange",
		mock.Anything,
		"code",
		mock.Anything,
	).Return(&oauth2Token, nil)
	oauth2Mock.On(
		"Client",
		mock.Anything,
		&oauth2Token,
		mock.Anything,
	).Return(infoClient)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/?state="+url.QueryEscape(token)+"&code=code", nil)
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	login.CallbackHandler(w, r)

	//require.Equal(t, http.StatusOK, w.Code)
	//require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Equal(t, githubUserInfo, w.Body.String())
}

func csrfToken(cookies []*http.Cookie) string {
	for _, cookie := range cookies {
		if cookie.Name == nosurf.CookieName {
			return cookie.Value
		}
	}
	return ""
}
