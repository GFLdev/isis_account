package queries

import (
	"database/sql"
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"strconv"

	"github.com/google/uuid"
)

// GetAllAcounts gets all accounts, with filters.
func GetAllAcounts(filters types.GetAccountsFilters) ([]*types.Account, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Validate filters
	err = utils.ValidateStruct(filters)
	if err != nil {
		return nil, err
	}

	// Build query
	query := `
    SELECT *
    FROM account.account
    WHERE 0 = 0`
	args := []any{}
	idx := 1
	if filters.RoleID != uuid.Nil { // Role
		query += "\nAND account.role_id = $" + strconv.Itoa(idx)
		args = append(args, filters.RoleID)
		idx++
	}
	if filters.IsActive != types.NoActivityAccountFilter { // Account activity
		query += "\nAND account.is_active = $" + strconv.Itoa(idx)
		if filters.IsActive == types.ActiveAccountFilter {
			args = append(args, true)
		} else {
			args = append(args, false)
		}
		idx++
	}

	// Limit and offset
	if filters.Limit > 0 {
		query += "\nLIMIT $" + strconv.Itoa(idx)
		args = append(args, filters.Limit)
		idx++
	}
	query += "\nOFFSET $" + strconv.Itoa(idx) + ";"
	args = append(args, filters.Offset)

	// Query all rows and copy data
	accs := []*types.Account{}
	rows, err := db.Query(query, args...)
	if err != nil {
		println("\n" + err.Error() + "\n")
		return nil, err
	}
	for rows.Next() {
		acc := new(types.Account)
		err = rows.Scan(
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
		if err != nil {
			return nil, err
		}

		// Validate account and append
		err = utils.ValidateStruct(acc)
		if err != nil {
			return nil, err
		}
		acc.Password = []byte{} // omit for security
		accs = append(accs, acc)
	}
	return accs, nil
}

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

func GetRefreshTokenByAccount(accoundID uuid.UUID) (*types.RefreshToken, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	refreshToken := new(types.RefreshToken)
	err = db.QueryRow(
		`SELECT *
    FROM account.refresh_token
    WHERE refresh_token.account_id = $1;`,
		accoundID,
	).Scan(
		&refreshToken.RefreshTokenID,
		&refreshToken.AccountID,
		&refreshToken.ExpirationDate,
	)
	if err == sql.ErrNoRows {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate the account structure and return, if it passes
	err = utils.ValidateStruct(refreshToken)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}
