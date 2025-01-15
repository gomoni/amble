package web

import (
	"net/http"

	. "maragu.dev/gomponents"
	. "maragu.dev/gomponents/components"
	. "maragu.dev/gomponents/http"
)

func Serve(node Node, w http.ResponseWriter, r *http.Request) {
	h := Adapt(func(w http.ResponseWriter, r *http.Request) (Node, error) {
		return node, nil
	})
	h(w, r)
}

func Index() Node {
	const rootHTML = `
<h1>My web app</h1>
<p>Using the x/oauth2 package</p>
<p>You can log into this app with your GitHub credentials:</p>
<p><a href="/auth/github/login">Log in with GitHub</a></p>
<p>You can log into this app with your Google credentials:</p>
<p><a href="/auth/google/login">Log in with Google</a></p>
`
	return HTML5(HTML5Props{
		Title:       "Amble.app",
		Description: "Amble.app is a management ui for Sunshine screen sharing application.",
		Body: []Node{
			Raw(rootHTML),
		},
	})
}
