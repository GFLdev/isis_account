package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/utils"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// DeleteAccountByID deletes one account by its ID.
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
		`DELETE FROM account.account
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

// DeleteAccountsByID deletes multiple accounts by each ID.
func DeleteAccountsByID(accsID []uuid.UUID) error {
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
		`DELETE FROM account.account
    WHERE account.account_id = ANY($1);`,
		pq.Array(accsID),
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

// DeleteRoleByID deletes one role by its ID.
func DeleteRoleByID(roleID uuid.UUID) error {
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
		`DELETE FROM account.role
    WHERE role.role_id = $1;`,
		roleID,
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

// DeleteRolesByID deletes multiple roles by each ID.
func DeleteRolesByID(rolesID []uuid.UUID) error {
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
		`DELETE FROM account.role
    WHERE role.role_id = ANY($1);`,
		pq.Array(rolesID),
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
