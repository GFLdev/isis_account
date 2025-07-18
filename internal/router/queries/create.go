package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// CreateRefreshToken inserts a new refresh token for an account.
func CreateRefreshToken(
	accountID uuid.UUID,
	expirationDate time.Time,
) (*types.RefreshToken, error) {
	// Build data and validates
	refreshToken := types.RefreshToken{
		RefreshTokenID: uuid.New().String(),
		AccountID:      accountID,
		ExpirationDate: expirationDate,
	}
	err := utils.ValidateStruct(refreshToken)
	if err != nil {
		return nil, err
	}

	// Hash refresh token
	hashedToken, err := bcrypt.GenerateFromPassword(
		[]byte(refreshToken.RefreshTokenID),
		BcryptCost,
	)
	if err != nil {
		return nil, err
	}

	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer utils.Rollback(tx)

	// Insert data
	_, err = tx.Exec(
		`INSERT INTO account.refresh_token
		VALUES ($1, $2, $3);`,
		hashedToken,
		refreshToken.AccountID,
		refreshToken.ExpirationDate,
	)
	if err != nil {
		utils.Rollback(tx)
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return &refreshToken, nil
}

// CreateLoginAttempt inserts a new login attempt for an account.
func CreateLoginAttempt(
	accountID uuid.UUID,
	ts time.Time,
	success bool,
	addr net.IP,
	userAgent string,
) (*types.LoginAttempt, error) {
	// Build data and validates
	loginAttempt := types.LoginAttempt{
		LoginAttemptID: uuid.New(),
		AccountID:      accountID,
		AttemptedAt:    ts,
		Success:        success,
		IPAddress:      addr,
		UserAgent:      userAgent,
	}
	err := utils.ValidateStruct(loginAttempt)
	if err != nil {
		return nil, err
	}

	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer utils.Rollback(tx)

	// Insert data
	_, err = tx.Exec(
		`INSERT INTO account.login_attempt
    VALUES ($1, $2, $3, $4, $5, $6);`,
		loginAttempt.LoginAttemptID,
		loginAttempt.AccountID,
		loginAttempt.AttemptedAt,
		loginAttempt.Success,
		loginAttempt.IPAddress.String(),
		loginAttempt.UserAgent,
	)
	if err != nil {
		utils.Rollback(tx)
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return &loginAttempt, nil
}
