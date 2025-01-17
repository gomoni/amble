package web

import (
	"net/http"

	. "maragu.dev/gomponents"
	. "maragu.dev/gomponents/components"
	. "maragu.dev/gomponents/html"
	. "maragu.dev/gomponents/http"
)

const githubLogo = `
  <svg width="19" height="19" viewBox="0 0 16 16" version="1.1">
	<path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
</svg>`

func Serve(node Node, w http.ResponseWriter, r *http.Request) {
	h := Adapt(func(w http.ResponseWriter, r *http.Request) (Node, error) {
		return node, nil
	})
	h(w, r)
}

func Index(csfrName, csfrValue string) Node {
	return HTML5(HTML5Props{
		Title:       "Amble.app",
		Description: "Amble.app is a management ui for Sunshine screen sharing application.",
		Body: []Node{
			H1(Text("Amble.app")),
			P(Text("Please login in")),
			Form(
				Method("POST"),
				ID("loginGitHub"),
				Action("/auth/github/login"),
				Input(Type("hidden"), Name("next_url"), Value("/dashboard")),
				Input(Type("hidden"), Name(csfrName), Value(csfrValue)),
				Button(Type("submit"), Raw(githubLogo), Text("Sign in with GitHub")),
			),
		},
	})
}
