package router

import (
	"isis_account/internal/utils"
	"net/http"

	"go.uber.org/zap"
)

// AuthLoginHandler handles login via username and password.
func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Read and parse body
	body, err := utils.ParseHTTPBody[AuthLogin](nil) // TODO: r.Body to io.Reader
	if err != nil {
		zap.L().Error(string(CannotReadBodyError),
			zap.Error(err),
		)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(CannotReadBodyError))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body.Username))
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
