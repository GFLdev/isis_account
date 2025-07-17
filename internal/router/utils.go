package router

import (
	"isis_account/internal/router/queries"
	"net"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// newLoginAttempt is a wrapper to create a new login attempt. Logs the attempt.
func newLoginAttempt(
	accountID uuid.UUID,
	ts time.Time,
	success bool,
	addr net.IP,
	userAgent string,
) {
	loginAttempt, err := queries.CreateLoginAttempt(
		accountID,
		ts,
		success,
		addr,
		userAgent,
	)
	if err != nil {
		zap.L().Warn("Could not create a login attempt in database",
			zap.Error(err),
		)
		return
	}
	zap.L().Info("New login attempt from "+addr.String(),
		zap.String("login_attempt_id", loginAttempt.LoginAttemptID.String()),
		zap.String("account_id", loginAttempt.AccountID.String()),
		zap.Bool("success", loginAttempt.Success),
		zap.Time("attempted_at", loginAttempt.AttemptedAt),
		zap.String("ip_address", loginAttempt.IPAddress.String()),
		zap.String("user_agent", loginAttempt.UserAgent),
	)
}
