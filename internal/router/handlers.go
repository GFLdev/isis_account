package router

import (
	"database/sql"
	"errors"
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
	body, err := utils.JSONToStruct[types.HTTPAuthLoginReq](c.Request().Body)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Validate body
	err = utils.ValidateStruct(body)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: types.InvalidAuthForm.Error()},
		)
		return err
	}

	// Get password hash from database
	acc, err := queries.GetAccountByUsername(body.Username)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.InternalError.Error()},
		)
		return err
	} else if acc == nil {
		return c.JSON(
			http.StatusNotFound,
			types.HTTPMessageResponse{Message: types.AccountNotFound.Error()},
		)
	}

	// Compare
	err = bcrypt.CompareHashAndPassword(acc.Password, []byte(body.Password))
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: types.IncorrectCredentials.Error()},
		)
		return err
	}

	// Generate access token
	// TODO: Configurable JWT expire duration
	accessDuration := time.Duration(30) * time.Minute
	accessExpiration := time.Now().Add(accessDuration)
	claims := GenerateClaims(
		acc.AccountID,
		acc.RoleID,
		acc.Username,
		accessExpiration,
	)
	accessToken, err := GenerateToken(claims)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Generate refresh token
	// TODO: Configurable JWT expire duration
	refreshDuration := time.Duration(48) * time.Hour
	refreshExpiration := time.Now().Add(refreshDuration)
	refreshToken, err := queries.CreateRefreshToken(
		acc.AccountID,
		refreshExpiration,
	)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.InternalError.Error()},
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
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Set cookies and return
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.RefreshTokenID.String(),
		Expires:  refreshExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  accessExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return c.JSON(http.StatusOK, res)
}

// AuthRefreshHandler handles session via access and/or refresh token.
func AuthRefreshHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Get token
	token, err := GetToken(c)
	if errors.As(err, &types.TokenError) {
		// mask endpoint with 404 if there is no token
		c.JSON(
			http.StatusNotFound,
			types.HTTPMessageResponse{Message: types.NotFound.Error()},
		)
		return err
	} else if errors.As(err, &types.ParseTokenError) {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Get claims from token
	claims, err := GetClaims(c, token)
	if errors.As(err, &types.ClaimsError) {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Check if token is expired
	now := time.Now()
	if claims.ExpiresAt.Compare(now) < 1 {
		// Refresh token provided by the user
		reqToken, err := c.Cookie("refresh_token")
		if err != nil || reqToken.Expires.Compare(now) < 1 {
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		}

		// Get account's refresh token
		refreshToken, err := queries.GetRefreshTokenByAccount(claims.AccountID)
		if err == sql.ErrNoRows || refreshToken.ExpirationDate.Compare(now) < 1 {
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		} else if err != nil {
			c.JSON(
				http.StatusInternalServerError,
				types.HTTPMessageResponse{Message: types.InternalError.Error()},
			)
			return err
		}

		// Check if the refresh tokens are the same
		// TODO: Encrypt refresh token
		if reqToken.Value != refreshToken.RefreshTokenID.String() {
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		}
	}

	// Generate access token
	// TODO: Configurable JWT expire duration
	accessDuration := time.Duration(30) * time.Minute
	accessExpiration := time.Now().Add(accessDuration)
	newClaims := GenerateClaims(
		claims.AccountID,
		claims.RoleID,
		claims.Username,
		accessExpiration,
	)
	accessToken, err := GenerateToken(newClaims)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Generate refresh token
	// TODO: Configurable JWT expire duration
	refreshDuration := time.Duration(48) * time.Hour
	refreshExpiration := time.Now().Add(refreshDuration)
	refreshToken, err := queries.CreateRefreshToken(
		newClaims.AccountID,
		refreshExpiration,
	)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.InternalError.Error()},
		)
		return err
	}

	// Response
	res := types.HTTPAuthLoginRes{
		AccountID: newClaims.AccountID,
		RoleId:    newClaims.RoleID,
	}
	err = utils.ValidateStruct(res)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Set cookies and return
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.RefreshTokenID.String(),
		Expires:  refreshExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  accessExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return c.JSON(http.StatusOK, res)
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
