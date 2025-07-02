package router

import (
	"isis_account/internal/utils"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the total iterations for bcrypt's algorithm.
const BcryptCost = 5

// AuthLoginHandler handles login via username and password.
func AuthLoginHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Read and parse body
	body, err := utils.ParseHTTPBody[AuthLogin](&c.Request().Body)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			MessageResponse{Message: string(ParsingError)},
		)
		return err
	}

	// Validate body
	err = utils.ValidateStruct(body)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			MessageResponse{Message: string(InvalidAuthForm)},
		)
		return err
	}

	// Get password hash from database
	hash := []byte("") // TODO: Get hash from database

	// Compare
	err = bcrypt.CompareHashAndPassword(hash, []byte(body.Password))
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			MessageResponse{Message: string(IncorrectCredentials)},
		)
		return err
	}

	// Response
	return c.JSON(
		http.StatusOK,
		MessageResponse{Message: body.Username},
	)
}

// AuthRefreshHandler handles session via access and/or refresh token.
func AuthRefreshHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Response
	return c.JSON(
		http.StatusOK,
		MessageResponse{Message: "/auth/refresh reached"},
	)
}

// AuthLogoutHandler handles session logout.
func AuthLogoutHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Response
	return c.JSON(
		http.StatusOK,
		MessageResponse{Message: "/auth/logout reached"},
	)
}
