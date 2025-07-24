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

// CreateAccount inserts a new account.
func CreateAccount(form *types.HTTPNewAccountForm) (*types.Account, error) {
	// Hashed password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(form.Password),
		BcryptCost,
	)
	if err != nil {
		return nil, err
	}

	// Build data and validates
	acc := types.Account{
		AccountID:  uuid.New(),
		RoleID:     form.RoleID,
		Username:   form.Username,
		Name:       form.Name,
		Surname:    form.Surname,
		Email:      form.Email,
		Password:   hashedPassword,
		IsActive:   true,
		LoginCount: 0,
		CreatedAt:  time.Now(),
	}
	err = utils.ValidateStruct(acc)
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
		`INSERT INTO account.account
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, null, $10, null);`,
		acc.AccountID,
		acc.RoleID,
		acc.Username,
		acc.Name,
		acc.Surname,
		acc.Email,
		acc.Password,
		acc.IsActive,
		acc.LoginCount,
		acc.CreatedAt,
	)
	if err != nil {
		utils.Rollback(tx)
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return &acc, nil
}

// CreateRefreshToken inserts a new refresh token for an account.
func CreateRefreshToken(
	accID uuid.UUID,
	expDate time.Time,
) (*types.RefreshToken, error) {
	// New hashed refresh token ID
	token := uuid.New().String()
	hash, err := bcrypt.GenerateFromPassword([]byte(token), BcryptCost)
	if err != nil {
		return nil, err
	}

	// Build data and validates
	refreshToken := types.RefreshToken{
		RefreshTokenID: string(hash),
		AccountID:      accID,
		ExpirationDate: expDate,
	}
	err = utils.ValidateStruct(refreshToken)
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

// CreateRole inserts a new role.
func CreateRole(form *types.HTTPNewRoleForm) (*types.Role, error) {
	// Build data and validates
	role := types.Role{
		RoleID:      uuid.New(),
		Name:        form.Name,
		Description: form.Description,
		CreatedAt:   time.Now(),
	}
	err := utils.ValidateStruct(role)
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
		`INSERT INTO account.role
		VALUES ($1, $2, $3, $4, null);`,
		role.RoleID,
		role.Name,
		role.Description,
		role.CreatedAt,
	)
	if err != nil {
		utils.Rollback(tx)
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// CreateLoginAttempt inserts a new login attempt for an account.
func CreateLoginAttempt(
	accID uuid.UUID,
	ts time.Time,
	success bool,
	addr net.IP,
	userAgent string,
) (*types.LoginAttempt, error) {
	// Build data and validates
	loginAttempt := types.LoginAttempt{
		LoginAttemptID: uuid.New(),
		AccountID:      accID,
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
