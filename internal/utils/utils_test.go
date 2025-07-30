package utils_test

import (
	"errors"
	"isis_account/internal/database"
	"isis_account/internal/utils"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

type UserTest struct {
	Name  string `json:"name" validate:"required"`
	Email string `json:"email" validate:"required,email"`
}

type IPTest struct {
	IP net.IP `validate:"required,ip_with_localhost"`
}

// TestReadFile is the ReadFile unit tests function.
func TestReadFile(t *testing.T) {
	t.Run("ShouldReadFileSuccessfully", func(t *testing.T) {
		t.Parallel()
		content := "hello world"
		tmpFile, err := os.CreateTemp("", "readfile_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		_, err = tmpFile.Seek(0, 0) // to beginning
		assert.NoError(t, err)

		data, err := utils.ReadFile(tmpFile)
		assert.NoError(t, err)
		assert.Equal(t, content, string(*data))
		_ = tmpFile.Close()
	})

	t.Run("ShouldReturnErrorWhenFileIsClosed", func(t *testing.T) {
		t.Parallel()
		tmpFile, err := os.CreateTemp("", "readfile_test_*.txt")
		assert.NoError(t, err)
		tmpFile.Close()

		_, err = utils.ReadFile(tmpFile)
		assert.Error(t, err)
	})
}

// TestCloseFiles is the CloseFiles unit tests function.
func TestCloseFiles(t *testing.T) {
	t.Run("ShouldCloseFilesWithoutError", func(t *testing.T) {
		t.Parallel()
		tmpFile1, err := os.CreateTemp("", "closefile_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile1.Name())

		tmpFile2, err := os.CreateTemp("", "closefile_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile2.Name())
		utils.CloseFiles(tmpFile1, tmpFile2)
	})

	t.Run("ShouldHandleErrorWhenFileAlreadyClosed", func(t *testing.T) {
		t.Parallel()
		tmpFile, err := os.CreateTemp("", "closefile_test_*.txt")
		assert.NoError(t, err)
		tmpFile.Close()
		utils.CloseFiles(tmpFile) // should not panic
	})
}

// TestValidateStruct is the ValidateStruct unit tests function.
func TestValidateStruct(t *testing.T) {
	t.Run("ShouldPassBasicValidation", func(t *testing.T) {
		t.Parallel()
		val := UserTest{Name: "John", Email: "john@example.com"}
		err := utils.ValidateStruct(val)
		assert.NoError(t, err)
	})

	t.Run("ShouldFailBasicValidation", func(t *testing.T) {
		t.Parallel()
		val := UserTest{Name: "", Email: "invalid-email"}
		err := utils.ValidateStruct(val)
		assert.Error(t, err)

		var vErr validator.ValidationErrors
		assert.True(t, errors.As(err, &vErr))
	})

	t.Run("ShouldPassIPWithLocalhostValidation", func(t *testing.T) {
		t.Parallel()
		validIPs := []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("192.168.0.1"),
			net.ParseIP("2001:db8::1"),
		}

		for _, ip := range validIPs {
			err := utils.ValidateStruct(IPTest{IP: ip})
			assert.NoError(t, err)
		}
	})

	t.Run("ShouldFailIPWithLocalhostValidation", func(t *testing.T) {
		t.Parallel()
		invalidIPs := []net.IP{
			nil,
			net.IP{},              // empty
			net.ParseIP(""),       // unparsable
			net.ParseIP("banana"), // not IP (returns nil)
		}

		for _, ip := range invalidIPs {
			err := utils.ValidateStruct(IPTest{IP: ip})
			assert.Error(t, err)
		}
	})
}

// TestJSONToStruct is the JSONToStruct unit tests function.
func TestJSONToStruct(t *testing.T) {
	t.Run("ShouldParseValidJSON", func(t *testing.T) {
		t.Parallel()
		jsonData := `{"name":"Alice","email":"alice@example.com"}`
		reader := strings.NewReader(jsonData)
		user, err := utils.JSONToStruct[UserTest](reader, false)
		assert.NoError(t, err)
		assert.Equal(t, "Alice", user.Name)
		assert.Equal(t, "alice@example.com", user.Email)
	})

	t.Run("ShouldFailOnUnknownField", func(t *testing.T) {
		t.Parallel()
		jsonData := `{"name":"Bob","unknown":123}`
		reader := strings.NewReader(jsonData)
		_, err := utils.JSONToStruct[UserTest](reader, false)
		assert.Error(t, err)
	})

	t.Run("ShouldAllowUnknownFieldWhenFlagSet", func(t *testing.T) {
		t.Parallel()
		jsonData := `{"name":"Carol","extra":true}`
		reader := strings.NewReader(jsonData)
		user, err := utils.JSONToStruct[UserTest](reader, true)
		assert.NoError(t, err)
		assert.Equal(t, "Carol", user.Name)
	})
}

// TestRollback is the Rollback unit tests function.
func TestRollback(t *testing.T) {
	t.Run("ShouldRollbackTransactionSuccessfully", func(t *testing.T) {
		t.Parallel()
		db, err := database.GetInstance()
		assert.NoError(t, err)

		tx, err := db.Begin()
		assert.NoError(t, err)

		utils.Rollback(tx)
		err = tx.Commit() // should return error if rollbacked
		assert.Error(t, err)
	})

	t.Run("ShouldHandleErrTxDoneWithoutLoggingError", func(t *testing.T) {
		t.Parallel()
		db, err := database.GetInstance()
		assert.NoError(t, err)

		tx, err := db.Begin()
		assert.NoError(t, err)

		err = tx.Commit()
		assert.NoError(t, err)
		utils.Rollback(tx) // error should be handled after commit
	})
}
