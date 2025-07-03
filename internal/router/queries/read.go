package queries

import (
	"database/sql"
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"

	"github.com/google/uuid"
)

// GetAccountByID gets only one account from database, by ID.
func GetAccountByID(accountID uuid.UUID) (*types.Account, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	acc := new(types.Account)
	err = db.QueryRow(
		`SELECT *
    FROM account.account
    WHERE account.account_id = $1;`,
		accountID.String(),
	).Scan(
		&acc.AccountID,
		&acc.RoleID,
		&acc.Username,
		&acc.Name,
		&acc.Surname,
		&acc.Email,
		&acc.Password,
		&acc.IsActive,
		&acc.LoginCount,
		&acc.LastLoginAt,
		&acc.CreatedAt,
		&acc.ModifiedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate the account structure and return, if it passes
	err = utils.ValidateStruct(acc)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

// GetAccountByUsername gets only one account from database, by username.
func GetAccountByUsername(username string) (*types.Account, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	acc := new(types.Account)
	err = db.QueryRow(
		`SELECT *
    FROM account.account
    WHERE account.username = $1;`,
		username,
	).Scan(
		&acc.AccountID,
		&acc.RoleID,
		&acc.Username,
		&acc.Name,
		&acc.Surname,
		&acc.Email,
		&acc.Password,
		&acc.IsActive,
		&acc.LoginCount,
		&acc.LastLoginAt,
		&acc.CreatedAt,
		&acc.ModifiedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate the account structure and return, if it passes
	err = utils.ValidateStruct(acc)
	if err != nil {
		return nil, err
	}
	return acc, nil
}
