package router

import (
	"isis_account/internal/router/queries"
	"isis_account/internal/types"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// newLoginAttempt is a wrapper to create a new login attempt. Logs the attempt.
func newLoginAttempt(loginAttemptConfig types.LoginAttemptConfig) {
	loginAttempt, err := queries.CreateLoginAttempt(
		loginAttemptConfig.AccountID,
		loginAttemptConfig.AttemptedAt,
		loginAttemptConfig.Success,
		loginAttemptConfig.IPAddress,
		loginAttemptConfig.UserAgent,
	)
	if err != nil {
		zap.L().Warn("Could not create a login attempt in database",
			zap.Error(err),
		)
		return
	}
	zap.L().Info("New login attempt from "+loginAttemptConfig.IPAddress.String(),
		zap.String("login_attempt_id", loginAttempt.LoginAttemptID.String()),
		zap.String("account_id", loginAttempt.AccountID.String()),
		zap.Bool("success", loginAttempt.Success),
		zap.Time("attempted_at", loginAttempt.AttemptedAt),
		zap.String("ip_address", loginAttempt.IPAddress.String()),
		zap.String("user_agent", loginAttempt.UserAgent),
	)
}

// GetElevation is a wrapper to get role module elevation data from
// echo.Context JWT.
func GetElevation(
	c echo.Context,
	claimsData *ClaimsData,
	module types.ModuleName,
) (bool, error) {
	// Check elevation
	roleModule, err := queries.GetRoleModuleByRole(claimsData.RoleID, module)
	if err != nil {
		return false, err
	} else if roleModule == nil {
		return false, nil
	}
	return roleModule.Elevated, nil
}

// ElevationErrorHandler handles the error returned from elevationFromJWT,
// sending a coherent JSON response for each possible error.
func ElevationErrorHandler(
	c echo.Context,
	elevated bool,
	err error,
) error {
	err = TokenErrorHandler(c, err)
	if err != nil {
		return err
	} else if !elevated {
		c.JSON(
			http.StatusUnauthorized,
			types.HTTPMessageResponse{Message: types.RoleNotElevated.Error()},
		)
	}
	return err
}
