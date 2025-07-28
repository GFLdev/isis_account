package utils_test

import (
	"isis_account/internal/utils"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReadFile is the ReadFile unit tests function.
func TestReadFile(t *testing.T) {
	t.Run("ShouldReadFileSuccessfully", func(t *testing.T) {
		content := "hello world"
		tmpFile, err := os.CreateTemp("", "readfile_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		_, err = tmpFile.Seek(0, 0) // To beginning
		assert.NoError(t, err)

		data, err := utils.ReadFile(tmpFile)
		assert.NoError(t, err)
		assert.Equal(t, content, string(*data))
		_ = tmpFile.Close()
	})

	t.Run("ShouldReturnErrorWhenFileIsClosed", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "readfile_test_*.txt")
		assert.NoError(t, err)
		tmpFile.Close()

		_, err = utils.ReadFile(tmpFile)
		assert.Error(t, err)
	})
}

// TestCloseFiles is the CloseFiles unit tests function.
func TestCloseFiles(t *testing.T) {
	t.Run("ShouldCloseFileWithoutError", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "closefile_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		utils.CloseFiles(tmpFile)
	})

	t.Run("ShouldHandleErrorWhenFileAlreadyClosed", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "closefile_test_*.txt")
		assert.NoError(t, err)
		tmpFile.Close()

		utils.CloseFiles(tmpFile) // Should not panic
	})
}
