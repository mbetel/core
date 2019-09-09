// Package xsrf is a container for the gorilla csrf package
package xsrf

import (
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/mbetel/core/view"
)

// Info holds the config.
type Info struct {
	AuthKey string
	Secure  bool
}

// Token sets token in the template to the CSRF token.
func Token(w http.ResponseWriter, r *http.Request, v *view.Info) {
	v.Vars["token"] = csrf.Token(r)
}
