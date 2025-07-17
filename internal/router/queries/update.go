package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/utils"
	"time"

	"github.com/google/uuid"
)

// UpdateLogin updates the last login timestamp and login counter for a given
// account.
func UpdateLogin(accountID uuid.UUID, ts time.Time) error {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return err
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer utils.Rollback(tx)

	// Update last login from account
	_, err = tx.Exec(
		`UPDATE account.account
    SET last_login_at = $1
      , login_count = login_count + 1
    WHERE account.account_id = $2;`,
		ts,
		accountID,
	)
	if err != nil {
		utils.Rollback(tx)
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
