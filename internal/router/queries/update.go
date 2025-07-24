package queries

import (
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// UpdateLogin updates the last login timestamp and login counter for a given
// account.
func UpdateLogin(accID uuid.UUID, ts time.Time) error {
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

// UpdateAccount updates any non-null values from the types.HTTPPatchAccountForm
// for a given account.
func UpdateAccount(accID uuid.UUID, form *types.HTTPPatchAccountForm) error {
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

	// Build query
	query := "UPDATE account.account\nSET "
	set := []string{}
	args := []any{}
	idx := 1
	if form.RoleID != uuid.Nil { // Update role
		set = append(set, "role_id = $"+strconv.Itoa(idx))
		args = append(args, form.RoleID)
		idx++
	}
	if form.Username != "" { // Update username
		set = append(set, "username = $"+strconv.Itoa(idx))
		args = append(args, form.Username)
		idx++
	}
	if form.Name != "" { // Update name
		set = append(set, "name = $"+strconv.Itoa(idx))
		args = append(args, form.Name)
		idx++
	}
	if form.Surname != "" { // Update surname
		set = append(set, "surname = $"+strconv.Itoa(idx))
		args = append(args, form.Surname)
		idx++
	}
	if form.Email != "" { // Update email
		set = append(set, "email = $"+strconv.Itoa(idx))
		args = append(args, form.Email)
		idx++
	}
	if form.Password != "" { // Update password
		hash, err := bcrypt.GenerateFromPassword([]byte(form.Password), BcryptCost)
		if err != nil {
			return err
		}
		set = append(set, "password = $"+strconv.Itoa(idx))
		args = append(args, hash)
		idx++
	}
	if form.IsActive != types.NilActivity { // Update activity
		set = append(set, "is_active = $"+strconv.Itoa(idx))
		args = append(args, form.IsActive == types.ActiveAccount)
		idx++
	}
	set = append(set, "modified_at = $"+strconv.Itoa(idx))
	query += strings.Join(set, "\n, ") +
		"\nWHERE account.account_id = $" + strconv.Itoa(idx+1) + ";"
	args = append(args, time.Now(), accID)

	// Update account
	_, err = tx.Exec(query, args...)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

// UpdateRole updates any non-null values from the types.HTTPPatchRoleForm
// for a given role.
func UpdateRole(roleID uuid.UUID, form *types.HTTPPatchRoleForm) error {
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

	// Build query
	query := "UPDATE account.role\nSET "
	set := []string{}
	args := []any{}
	idx := 1
	if form.Name != "" { // Update name
		set = append(set, "name = $"+strconv.Itoa(idx))
		args = append(args, form.Name)
		idx++
	}
	if form.Description != "" { // Update description
		set = append(set, "description = $"+strconv.Itoa(idx))
		args = append(args, form.Description)
		idx++
	}
	set = append(set, "modified_at = $"+strconv.Itoa(idx))
	query += strings.Join(set, "\n, ") +
		"\nWHERE role.role_id = $" + strconv.Itoa(idx+1) + ";"
	args = append(args, time.Now(), roleID)

	// Update account
	_, err = tx.Exec(query, args...)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
