package router

import "net/http"

// AuthLoginHandler handles login via username and password.
func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	println("POST /auth/login reached")
	w.Write([]byte("/auth/login reached"))
}

// AuthRefreshHandler handles session via access and/or refresh token.
func AuthRefreshHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	println("POST /auth/refresh reached")
	w.Write([]byte("/auth/refresh reached"))
}

// AuthLogoutHandler handles session logout.
func AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	println("POST /auth/logout reached")
	w.Write([]byte("/auth/logout reached"))
}
