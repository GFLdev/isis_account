package queries

import (
	"database/sql"
	"errors"
	"isis_account/internal/database"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"strconv"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// closeRows close *sql.Rows to prevent further enumeration. Used in defer.
func closeRows(rows *sql.Rows) {
	err := rows.Close()
	if err != nil {
		zap.L().Warn("Could not close query rows",
			zap.Error(err),
		)
	}
}

// CheckAccountWithRole check if the account, with given role, exists and is
// active.
func CheckAccountWithRole(accID, roleID uuid.UUID) (bool, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return false, err
	}

	// Query one row and copy the data
	var exists bool
	err = db.QueryRow(
		`SELECT EXISTS (
      SELECT 1
      FROM account.account
      WHERE account.account_id = $1
        AND account.role_id = $2
        AND account.is_active = TRUE
    );`,
		accID,
		roleID,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// CheckAccountByID check if an account, with the given ID, exists.
func CheckAccountByID(accID uuid.UUID) (bool, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return false, err
	}

	// Query one row and copy the data
	var exists bool
	err = db.QueryRow(
		`SELECT EXISTS (
      SELECT 1
      FROM account.account
      WHERE account.account_id = $1
    );`,
		accID,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// CheckAccountByUsername check if an account, with the given username, exists.
func CheckAccountByUsername(username string) (bool, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return false, err
	}

	// Query one row and copy the data
	var exists bool
	err = db.QueryRow(
		`SELECT EXISTS (
      SELECT 1
      FROM account.account
      WHERE account.username = $1
        AND account.is_active = TRUE
    );`,
		username,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// CheckNonExistantAccounts check accounts that does not exist.
func CheckNonExistantAccounts(accsID []uuid.UUID) ([]uuid.UUID, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	nonExistantAccsID := []uuid.UUID{}
	rows, err := db.Query(
		`SELECT id
    FROM UNNEST($1::uuid[]) AS id
    WHERE NOT EXISTS (
      SELECT 1
      FROM account.account
      WHERE account.account_id = id
    );`,
		pq.Array(accsID),
	)
	if err != nil {
		return nil, nil
	}
	defer closeRows(rows)
	for rows.Next() {
		var nonExistantAccID uuid.UUID
		err = rows.Scan(&nonExistantAccID)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}
		nonExistantAccsID = append(nonExistantAccsID, nonExistantAccID)
	}
	return nonExistantAccsID, nil
}

// CheckNonExistantRoles check roles that does not exist.
func CheckNonExistantRoles(rolesID []uuid.UUID) ([]uuid.UUID, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	nonExistantRolesID := []uuid.UUID{}
	rows, err := db.Query(
		`SELECT id
    FROM UNNEST($1::uuid[]) AS id
    WHERE NOT EXISTS (
      SELECT 1
      FROM account.role
      WHERE role.role_id = id
    );`,
		pq.Array(rolesID),
	)
	defer closeRows(rows)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var nonExistantRoleID uuid.UUID
		err = rows.Scan(&nonExistantRoleID)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}
		nonExistantRolesID = append(nonExistantRolesID, nonExistantRoleID)
	}
	return nonExistantRolesID, nil
}

// CheckRoleByID check if a role, with the given ID, exists.
func CheckRoleByID(roleID uuid.UUID) (bool, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return false, err
	}

	// Query one row and copy the data
	var exists bool
	err = db.QueryRow(
		`SELECT EXISTS (
      SELECT 1
      FROM account.role
      WHERE role.role_id = $1
    );`,
		roleID,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

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
	query := "SELECT *\nFROM account.account\nWHERE 0 = 0"
	args := []any{}
	idx := 1
	if filters.RoleID != uuid.Nil { // Role
		query += "\nAND account.role_id = $" + strconv.Itoa(idx)
		args = append(args, filters.RoleID)
		idx++
	}
	if filters.IsActive != types.NilActivity { // Account activity
		query += "\nAND account.is_active = $" + strconv.Itoa(idx)
		args = append(args, filters.IsActive == types.ActiveAccount)
		idx++
	}
	if filters.Limit > 0 { // Limit
		query += "\nLIMIT $" + strconv.Itoa(idx)
		args = append(args, filters.Limit)
		idx++
	}
	if filters.Offset > 0 { // Offset
		query += "\nOFFSET $" + strconv.Itoa(idx)
		args = append(args, filters.Offset)
		idx++
	}
	query += ";"

	// Query all rows and copy data
	var lastLoginAt, modifiedAt sql.NullTime
	accs := []*types.Account{}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
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
			&lastLoginAt,
			&acc.CreatedAt,
			&modifiedAt,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Nullable dates
		acc.LastLoginAt = lastLoginAt.Time
		acc.ModifiedAt = modifiedAt.Time

		// Validate account structure and append it, if it passes
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
func GetAccountByID(accID uuid.UUID) (*types.Account, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query one row and copy the data
	var lastLoginAt, modifiedAt sql.NullTime
	acc := new(types.Account)
	err = db.QueryRow(
		`SELECT *
    FROM account.account
    WHERE account.account_id = $1;`,
		accID,
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
		&lastLoginAt,
		&acc.CreatedAt,
		&modifiedAt,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Nullable dates
	acc.LastLoginAt = lastLoginAt.Time
	acc.ModifiedAt = modifiedAt.Time

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
	var lastLoginAt, modifiedAt sql.NullTime
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
		&lastLoginAt,
		&acc.CreatedAt,
		&modifiedAt,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Nullable dates
	acc.LastLoginAt = lastLoginAt.Time
	acc.ModifiedAt = modifiedAt.Time

	// Validate the account structure and return, if it passes
	err = utils.ValidateStruct(acc)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func GetRefreshTokenByAccount(accID uuid.UUID) (*types.RefreshToken, error) {
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
		accID,
	).Scan(
		&refreshToken.RefreshTokenID,
		&refreshToken.AccountID,
		&refreshToken.ExpirationDate,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate the refresh token structure and return, if it passes
	err = utils.ValidateStruct(refreshToken)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}

// GetAllRoles gets all roles from database.
func GetAllRoles() ([]*types.Role, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query all roles and copy data
	var modifiedAt sql.NullTime
	roles := []*types.Role{}
	rows, err := db.Query(
		`SELECT *
    FROM account.role;`,
	)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	for rows.Next() {
		role := new(types.Role)
		err = rows.Scan(
			&role.RoleID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&modifiedAt,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Nullable date
		role.ModifiedAt = modifiedAt.Time

		// Validate role structure and append it, if it passes
		err = utils.ValidateStruct(role)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// GetRoleByID gets one role by its ID.
func GetRoleByID(roleID uuid.UUID) (*types.Role, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get role by ID and copy its data
	var modifiedAt sql.NullTime
	role := new(types.Role)
	err = db.QueryRow(
		`SELECT *
    FROM account.role
    WHERE role.role_id = $1;`,
		roleID,
	).Scan(
		&role.RoleID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&modifiedAt,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Nullable date
	role.ModifiedAt = modifiedAt.Time

	// Validate role structure and return it, if it passes
	err = utils.ValidateStruct(role)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// GetRolesInUse get all roles currently in use by accounts.
func GetRolesInUse() ([]*types.Role, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query all roles in use and copy data
	var modifiedAt sql.NullTime
	roles := []*types.Role{}
	rows, err := db.Query(
		`SELECT *
    FROM account.role
    WHERE role.role_id IN (
      SELECT DISTINCT account.role_id
      FROM account.account
    );`,
	)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	for rows.Next() {
		role := new(types.Role)
		err = rows.Scan(
			&role.RoleID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&modifiedAt,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Nullable date
		role.ModifiedAt = modifiedAt.Time

		// Validate role structure and append it, if it passes
		err = utils.ValidateStruct(role)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// GetModulesName gets all module_name enum values from database.
func GetModulesName() ([]types.ModuleName, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Query all module_name enum values in database
	modulesName := []types.ModuleName{}
	rows, err := db.Query(
		`SELECT UNNEST(enum_range(NULL::account.module_name));`,
	)
	defer closeRows(rows)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var moduleName string
		err = rows.Scan(&moduleName)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}
		modulesName = append(modulesName, types.ModuleName(moduleName))
	}
	return modulesName, nil
}

// GetAllModules gets all modules from database;
func GetAllModules() ([]*types.Module, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get all modules and copy its data
	modules := []*types.Module{}
	rows, err := db.Query(
		`SELECT *
    FROM account.module;`,
	)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	for rows.Next() {
		module := new(types.Module)
		err = rows.Scan(
			&module.ModuleName,
			&module.Description,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Validate module structure and append it, if it passes
		err = utils.ValidateStruct(module)
		if err != nil {
			return nil, err
		}
		modules = append(modules, module)
	}
	return modules, nil
}

// GetModuleByName gets one module by its name.
func GetModuleByName(name types.ModuleName) (*types.Module, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get module from database and copy its data
	module := new(types.Module)
	err = db.QueryRow(
		`SELECT *
    FROM account.module
    WHERE module.module_name = $1;`,
		name,
	).Scan(
		&module.ModuleName,
		&module.Description,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate module structure and return it, if it passes
	err = utils.ValidateStruct(module)
	if err != nil {
		return nil, err
	}
	return module, nil
}

// GetAllRoleModuleByRole gets all role module permissions by role ID.
func GetAllRoleModuleByRole(roleID uuid.UUID) ([]*types.RoleModule, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get role module from database and copy its data
	roleModules := []*types.RoleModule{}
	rows, err := db.Query(
		`SELECT *
    FROM account.role_module
    WHERE role_module.rode_id = $1;`,
		roleID,
	)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	for rows.Next() {
		roleModule := new(types.RoleModule)
		err = rows.Scan(
			&roleModule.RoleID,
			&roleModule.ModuleName,
			&roleModule.Elevated,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Validate role_module structure and append it, if it passes
		err = utils.ValidateStruct(roleModule)
		if err != nil {
			return nil, err
		}
		roleModules = append(roleModules, roleModule)
	}
	return roleModules, nil
}

// GetRoleModuleByRole gets the role module permission by role ID and
// module name.
func GetRoleModuleByRole(
	roleID uuid.UUID,
	moduleName types.ModuleName,
) (*types.RoleModule, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get role module from database and copy its data
	roleModule := new(types.RoleModule)
	err = db.QueryRow(
		`SELECT *
    FROM account.role_module
    WHERE role_module.role_id = $1
    AND role_module.module_name = $2;`,
		roleID,
		moduleName,
	).Scan(
		&roleModule.RoleID,
		&roleModule.ModuleName,
		&roleModule.Elevated,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate role_module structure and return it, if it passes
	err = utils.ValidateStruct(roleModule)
	if err != nil {
		return nil, err
	}
	return roleModule, nil
}

// GetAllRoleModuleByAccount gets all role module permissions by account ID.
func GetAllRoleModuleByAccount(accID uuid.UUID) ([]*types.RoleModule, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get role module from database and copy its data
	roleModules := []*types.RoleModule{}
	rows, err := db.Query(
		`SELECT role_module.role_id
          , role_module.module_name
          , role_module.elevated
    FROM account.role_module
    INNER JOIN account.account
      ON account.account_id = $1
      AND account.role_id = role_module.role_id;`,
		accID,
	)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	for rows.Next() {
		roleModule := new(types.RoleModule)
		err = rows.Scan(
			&roleModule.RoleID,
			&roleModule.ModuleName,
			&roleModule.Elevated,
		)
		if errors.As(err, &sql.ErrNoRows) {
			return nil, nil // returns no data and no error, if it does not exist
		} else if err != nil {
			return nil, err
		}

		// Validate role_module structure and append it, if it passes
		err = utils.ValidateStruct(roleModule)
		if err != nil {
			return nil, err
		}
		roleModules = append(roleModules, roleModule)
	}
	return roleModules, nil
}

// GetRoleModuleByAccount gets the role module permission by account ID and
// module name.
func GetRoleModuleByAccount(
	accID uuid.UUID,
	moduleName types.ModuleName,
) (*types.RoleModule, error) {
	// Get database instance
	db, err := database.GetInstance()
	if err != nil {
		return nil, err
	}

	// Get role module from database and copy its data
	roleModule := new(types.RoleModule)
	err = db.QueryRow(
		`SELECT role_module.role_id
          , role_module.module_name
          , role_module.elevated
    FROM account.role_module
    INNER JOIN account.account
      ON account.account_id = $1
      AND account.role_id = role_module.role_id
    WHERE role_module.module_name = $2;`,
		accID,
		moduleName,
	).Scan(
		&roleModule.RoleID,
		&roleModule.ModuleName,
		&roleModule.Elevated,
	)
	if errors.As(err, &sql.ErrNoRows) {
		return nil, nil // returns no data and no error, if it does not exist
	} else if err != nil {
		return nil, err
	}

	// Validate role_module structure and return it, if it passes
	err = utils.ValidateStruct(roleModule)
	if err != nil {
		return nil, err
	}
	return roleModule, nil
}
