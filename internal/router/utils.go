package router

import (
	"isis_account/internal/router/queries"
	"isis_account/internal/types"

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

// getClaimsDataWrapper is a wrapper to get JWT claims data from echo.Context.
func getClaimsDataWrapper(c echo.Context) (*ClaimsData, error) {
	// Get token
	token, err := GetToken(c)
	if err != nil {
		return nil, err
	}

	// Get claims from token
	claims, err := GetClaims(c, token)
	if err != nil {
		return nil, err
	}
	return &claims.ClaimsData, nil
}

// elevationFromJWT is a wrapper to get role module elevation data from
// echo.Context JWT.
func elevationFromJWT(c echo.Context) (bool, error) {
	// Get claims data from JWT
	claimsData, err := getClaimsDataWrapper(c)
	if err != nil {
		return false, err
	}

	// Check elevation
	roleModule, err := queries.GetRoleModuleByRole(
		claimsData.RoleID,
		types.AccountModule,
	)
	if err != nil {
		return false, err
	}
	return roleModule.Elevated, nil
}
