package main

import (
	"isis_account/internal/router"
	"net/http"

	"github.com/gorilla/mux"
)

func serve(r *mux.Router) {
	http.ListenAndServe(":8080", r)
}

func main() {
	// New router
	r := router.NewRouter()

	// Start server
	serve(r)
}
