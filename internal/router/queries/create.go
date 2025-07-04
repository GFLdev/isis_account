package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"time"

	"github.com/google/uuid"
)

// CreateRefreshToken inserts a new refresh token for an account.
func CreateRefreshToken(
	accountID uuid.UUID,
	expirationDate time.Time,
) (*types.RefreshToken, error) {
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

	// Build data and validates
	refreshToken := types.RefreshToken{
		RefreshTokenID: uuid.New(),
		AccountID:      accountID,
		ExpirationDate: expirationDate,
	}
	err = utils.ValidateStruct(refreshToken)
	if err != nil {
		utils.Rollback(tx)
		return nil, err
	}

	// Insert data
	_, err = tx.Exec(
		`INSERT INTO account.refresh_token
		VALUES ($1, $2, $3);`,
		refreshToken.RefreshTokenID,
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
