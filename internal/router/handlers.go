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
	"strconv"
	"time"

	"github.com/google/uuid"
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

	// New login attempt
	ts := time.Now()
	loginAttemptConfig := types.LoginAttemptConfig{
		AccountID:   acc.AccountID,
		AttemptedAt: ts,
		Success:     false,
		IPAddress:   net.ParseIP(c.RealIP()),
		UserAgent:   c.Request().UserAgent(),
	}

	// Compare
	err = bcrypt.CompareHashAndPassword(acc.Password, []byte(body.Password))
	if err != nil {
		newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
	loginAttemptConfig.Success = true
	newLoginAttempt(loginAttemptConfig)
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.RefreshTokenID,
		Path:     "/",
		Expires:  refreshExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
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

	// New login attempt
	ts := time.Now()
	loginAttemptConfig := types.LoginAttemptConfig{
		AccountID:   claims.AccountID,
		AttemptedAt: ts,
		Success:     false,
		IPAddress:   net.ParseIP(c.RealIP()),
		UserAgent:   c.Request().UserAgent(),
	}

	// Check if token is expired
	if claims.ExpiresAt.Compare(ts) < 1 {
		// Refresh token provided by the user
		reqToken, err := c.Cookie("refresh_token")
		if err != nil || reqToken.Expires.Compare(ts) < 1 {
			newLoginAttempt(loginAttemptConfig)
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		}

		// Get account's refresh token
		refreshToken, err := queries.GetRefreshTokenByAccount(claims.AccountID)
		if err == sql.ErrNoRows || refreshToken.ExpirationDate.Compare(ts) < 1 {
			newLoginAttempt(loginAttemptConfig)
			return c.JSON(
				http.StatusUnauthorized,
				types.HTTPMessageResponse{Message: types.SessionExpired.Error()},
			)
		} else if err != nil {
			newLoginAttempt(loginAttemptConfig)
			c.JSON(
				http.StatusInternalServerError,
				types.HTTPMessageResponse{Message: types.InternalError.Error()},
			)
			return err
		}

		// Check if the refresh tokens are the same
		hashedToken := []byte(refreshToken.RefreshTokenID)
		err = bcrypt.CompareHashAndPassword(hashedToken, []byte(reqToken.Value))
		if err != nil {
			newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
		newLoginAttempt(loginAttemptConfig)
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
	loginAttemptConfig.Success = true
	newLoginAttempt(loginAttemptConfig)
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.RefreshTokenID,
		Path:     "/",
		Expires:  refreshExpiration,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
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

	// Get token
	token, err := GetToken(c)
	if err != nil {
		return c.JSON(
			http.StatusOK,
			types.HTTPMessageResponse{Message: string(types.AlreadyLoggedOut)},
		)
	}

	// Get claims from token
	claims, err := GetClaims(c, token)
	if err != nil {
		return c.JSON(
			http.StatusOK,
			types.HTTPMessageResponse{Message: string(types.AlreadyLoggedOut)},
		)
	}

	// Check if token is expired
	if claims.ExpiresAt.Compare(time.Now()) < 1 {
		return c.JSON(
			http.StatusOK,
			types.HTTPMessageResponse{Message: string(types.AlreadyLoggedOut)},
		)
	}

	// Reset cookies
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Response
	return c.JSON(
		http.StatusOK,
		types.HTTPMessageResponse{Message: string(types.LoggedOut)},
	)
}

// GetAccountsHandler handles all accounts fetching.
func GetAccountsHandler(c echo.Context) error {
	// Headers
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// TODO: Check elevation

	// Get query params and validate them
	var err error
	filters := types.GetAccountsFilters{}
	qLimit := c.QueryParam("limit")
	if qLimit != "" {
		filters.Limit, err = strconv.Atoi(qLimit)
		if err != nil {
			c.JSON(
				http.StatusBadRequest,
				types.HTTPMessageResponse{Message: types.InvalidParameters.Error()},
			)
			return err
		}
	} else {
		filters.Limit = 0 // default to all
	}
	qOffset := c.QueryParam("offset")
	if qOffset != "" {
		filters.Offset, err = strconv.Atoi(qOffset)
		if err != nil {
			c.JSON(
				http.StatusBadRequest,
				types.HTTPMessageResponse{Message: types.InvalidParameters.Error()},
			)
			return err
		}
	} else {
		filters.Offset = 0 // default to 0 offset
	}
	qRoleID := c.QueryParam("role_id")
	if qRoleID != "" {
		filters.RoleID, err = uuid.Parse(qRoleID)
		if err != nil {
			c.JSON(
				http.StatusBadRequest,
				types.HTTPMessageResponse{Message: types.InvalidParameters.Error()},
			)
			return err
		}
	} else {
		filters.RoleID = uuid.Nil // default to a null role
	}
	qIsActive := c.QueryParam("is_active")
	if qIsActive == string(types.ActiveAccountFilter) ||
		qIsActive == string(types.InactiveAccountFilter) {
		filters.IsActive = types.AccountActivityFilter(qIsActive)
	} else {
		filters.IsActive = types.NoActivityAccountFilter // default to no filter
	}

	// Validate filters
	err = utils.ValidateStruct(filters)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			types.HTTPMessageResponse{Message: types.InvalidParameters.Error()},
		)
		return err
	}

	// Query all accounts
	accs, err := queries.GetAllAcounts(filters)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			types.HTTPMessageResponse{Message: types.NoAccountsFound.Error()},
		)
		return err
	} else if len(accs) == 0 {
		return c.JSON(
			http.StatusNoContent,
			types.HTTPMessageResponse{Message: types.NoAccountsFound.Error()},
		)
	}
	return c.JSON(http.StatusOK, accs)
}

// GetAccountHandler handles one account fetching.
func GetAccountHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// CreateAccountHandler handles the creation of an account.
func CreateAccountHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// UpdateAccountHandler handles one account update.
func UpdateAccountHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// DeleteAccountsHandler handles the deletion of all accounts.
func DeleteAccountsHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// DeleteAccountHandler handles the deletion of one account.
func DeleteAccountHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// GetRolesHandler handles all roles fetching.
func GetRolesHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// GetRoleHandler handles one role fetching.
func GetRoleHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// CreateRoleHandler handles the creation of a role.
func CreateRoleHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// UpdateRoleHandler handles one role update.
func UpdateRoleHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// DeleteRolesHandler handles the deletion of all roles.
func DeleteRolesHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// DeleteRoleHandler handles the deletion of one role.
func DeleteRoleHandler(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// GetLogs handles all logs fetching.
func GetLogs(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}

// GetLoginLogs handles all login attempt logs fetching.
func GetLoginLogs(c echo.Context) error {
	return c.JSON(
		http.StatusNotImplemented,
		types.HTTPMessageResponse{Message: types.NotImplemented.Error()},
	)
}
