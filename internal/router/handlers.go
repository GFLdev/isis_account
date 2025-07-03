package router

import (
	"isis_account/internal/router/queries"
	"isis_account/internal/types"
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
	body, err := utils.ParseHTTPBody[types.HTTPAuthLogin](&c.Request().Body)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: string(types.ParsingError)},
		)
		return err
	}

	// Validate body
	err = utils.ValidateStruct(body)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: string(types.InvalidAuthForm)},
		)
		return err
	}

	// Get password hash from database
	acc, err := queries.GetAccountByUsername(body.Username)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: string(types.InternalError)},
		)
		return err
	} else if acc == nil {
		return c.JSON(
			http.StatusNotFound,
			types.HTTPMessageResponse{Message: string(types.AccountNotFound)},
		)
	}

	// Compare
	err = bcrypt.CompareHashAndPassword(acc.Password, []byte(body.Password))
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: string(types.IncorrectCredentials)},
		)
		return err
	}

	// Response
	return c.JSON(
		http.StatusOK,
		types.HTTPMessageResponse{Message: body.Username},
	)
}

// AuthRefreshHandler handles session via access and/or refresh token.
func AuthRefreshHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Response
	return c.JSON(
		http.StatusOK,
		types.HTTPMessageResponse{Message: "/auth/refresh reached"},
	)
}

// AuthLogoutHandler handles session logout.
func AuthLogoutHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Response
	return c.JSON(
		http.StatusOK,
		types.HTTPMessageResponse{Message: "/auth/logout reached"},
	)
}
