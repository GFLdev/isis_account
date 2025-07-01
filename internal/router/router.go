package router

import (
	"net/http"

	"github.com/gorilla/mux"
)

// NewRouter build and configure the ISIS account service router.
func NewRouter() *mux.Router {
	r := mux.NewRouter()

	// Defining subroutes
	auth := r.PathPrefix("/auth").Subrouter()
	acc := r.PathPrefix("/account").Subrouter()
	role := r.PathPrefix("/role").Subrouter()
	log := r.PathPrefix("/log").Subrouter()

	// Defining routes
	auth.HandleFunc("/login", AuthLoginHandler).
		Methods(http.MethodPost)
	auth.HandleFunc("/refresh", AuthRefreshHandler).
		Methods(http.MethodPost)
	auth.HandleFunc("/logout", AuthLogoutHandler).
		Methods(http.MethodPost)

	acc.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)
	acc.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)
	acc.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodPost)
	acc.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodPatch)
	acc.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodDelete)
	acc.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodDelete)

	role.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)
	role.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)
	role.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodPost)
	role.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodPatch)
	role.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodDelete)
	role.HandleFunc("/{id}", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodDelete)

	log.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)
	log.HandleFunc("/login", func(_ http.ResponseWriter, _ *http.Request) {}).
		Methods(http.MethodGet)

	// Returning router
	return r
}
