package router

import (
	"isis_account/internal/router/queries"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the total iterations for bcrypt's algorithm.
const BcryptCost = 12

// AuthLoginHandler handles login via username and password.
func AuthLoginHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Read and parse body
	body, err := utils.ParseHTTPBody[types.HTTPAuthLoginReq](&c.Request().Body)
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

	// Generate access token
	// TODO: Configurable JWT expire duration
	// TODO: Configurable token sign key
	duration := time.Duration(30) * time.Minute
	expiresAt := time.Now().Add(duration)
	claims := GenerateClaims(acc.AccountID, acc.RoleID, acc.Username, expiresAt)
	accessToken, err := GenerateToken(claims, []byte("secret"))
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: string(types.ParsingError)},
		)
		return err
	}

	// Response
	res := types.HTTPAuthLoginRes{
		AccountID: acc.AccountID,
		RoleId:    acc.RoleID,
	}
	err = utils.ValidateStruct(res)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: string(types.ParsingError)},
		)
		return err
	}

	// Set cookie and return
	c.SetCookie(&http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: expiresAt,
	})
	return c.JSON(http.StatusOK, res)
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
