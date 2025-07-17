package router

import (
	"database/sql"
	"errors"
	"isis_account/internal/config"
	"isis_account/internal/router/queries"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// AuthLoginHandler handles login via username and password.
func AuthLoginHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Read and parse body
	body, err := utils.JSONToStruct[types.HTTPAuthLoginReq](c.Request().Body, false)
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
	ts := time.Now()
	err = bcrypt.CompareHashAndPassword(acc.Password, []byte(body.Password))
	if err != nil {
		newLoginAttempt(
			acc.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: types.IncorrectCredentials.Error()},
		)
		return err
	}

	// Generate access token
	cfg := config.GetConfig() // get config
	accessDuration := time.Duration(cfg.JWT.AccessTokenMinutes) * time.Minute
	accessExpiration := ts.Add(accessDuration)
	claims := GenerateClaims(
		acc.AccountID,
		acc.RoleID,
		acc.Username,
		accessExpiration,
	)
	accessToken, err := GenerateToken(claims)
	if err != nil {
		newLoginAttempt(
			acc.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Generate refresh token
	refreshDuration := time.Duration(cfg.JWT.RefreshTokenHours) * time.Hour
	refreshExpiration := ts.Add(refreshDuration)
	refreshToken, err := queries.CreateRefreshToken(
		acc.AccountID,
		refreshExpiration,
	)
	if err != nil {
		newLoginAttempt(
			acc.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
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
		newLoginAttempt(
			acc.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Update last login
	err = queries.UpdateLogin(acc.AccountID, ts)
	if err != nil {
		zap.L().Warn("Could not update last login for "+acc.AccountID.String(),
			zap.Error(err),
		)
	}

	// Set cookies and return
	newLoginAttempt(
		acc.AccountID,
		ts,
		true,
		net.ParseIP(c.RealIP()),
		c.Request().UserAgent(),
	)
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
	ts := time.Now()
	if claims.ExpiresAt.Compare(ts) < 1 {
		// Refresh token provided by the user
		reqToken, err := c.Cookie("refresh_token")
		if err != nil || reqToken.Expires.Compare(ts) < 1 {
			newLoginAttempt(
				claims.AccountID,
				ts,
				false,
				net.ParseIP(c.RealIP()),
				c.Request().UserAgent(),
			)
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		}

		// Get account's refresh token
		refreshToken, err := queries.GetRefreshTokenByAccount(claims.AccountID)
		if err == sql.ErrNoRows || refreshToken.ExpirationDate.Compare(ts) < 1 {
			newLoginAttempt(
				claims.AccountID,
				ts,
				false,
				net.ParseIP(c.RealIP()),
				c.Request().UserAgent(),
			)
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		} else if err != nil {
			newLoginAttempt(
				claims.AccountID,
				ts,
				false,
				net.ParseIP(c.RealIP()),
				c.Request().UserAgent(),
			)
			c.JSON(
				http.StatusInternalServerError,
				types.HTTPMessageResponse{Message: types.InternalError.Error()},
			)
			return err
		}

		// Check if the refresh tokens are the same
		hashedToken := []byte(refreshToken.RefreshTokenID.String())
		err = bcrypt.CompareHashAndPassword(hashedToken, []byte(reqToken.Value))
		if err != nil {
			newLoginAttempt(
				claims.AccountID,
				ts,
				false,
				net.ParseIP(c.RealIP()),
				c.Request().UserAgent(),
			)
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		}
	}

	// Generate access token
	cfg := config.GetConfig() // get config
	accessDuration := time.Duration(cfg.JWT.AccessTokenMinutes) * time.Minute
	accessExpiration := ts.Add(accessDuration)
	newClaims := GenerateClaims(
		claims.AccountID,
		claims.RoleID,
		claims.Username,
		accessExpiration,
	)
	accessToken, err := GenerateToken(newClaims)
	if err != nil {
		newLoginAttempt(
			claims.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Generate refresh token
	refreshDuration := time.Duration(cfg.JWT.RefreshTokenHours) * time.Hour
	refreshExpiration := ts.Add(refreshDuration)
	refreshToken, err := queries.CreateRefreshToken(
		newClaims.AccountID,
		refreshExpiration,
	)
	if err != nil {
		newLoginAttempt(
			claims.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
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
		newLoginAttempt(
			claims.AccountID,
			ts,
			false,
			net.ParseIP(c.RealIP()),
			c.Request().UserAgent(),
		)
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.ParsingError.Error()},
		)
		return err
	}

	// Update last login
	err = queries.UpdateLogin(newClaims.AccountID, ts)
	if err != nil {
		zap.L().Warn("Could not update last login for "+newClaims.AccountID.String(),
			zap.Error(err),
		)
	}

	// Set cookies and return
	newLoginAttempt(
		claims.AccountID,
		ts,
		true,
		net.ParseIP(c.RealIP()),
		c.Request().UserAgent(),
	)
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
