package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/utils"

	"github.com/google/uuid"
)

// DeleteAccount deletes one account by its ID.
func DeleteAccountByID(accID uuid.UUID) error {
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

	// Delete account
	_, err = tx.Exec(
		`DELETE account.account
    WHERE account.account_id = $1;`,
		accID,
	)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
