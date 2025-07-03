package router

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ClaimsData struct {
	AccountID uuid.UUID
	RoleID    uuid.UUID
	Username  string
}

type JWTClaims struct {
	ClaimsData
	jwt.RegisteredClaims
}

func GenerateClaims(
	accoutID uuid.UUID,
	roleID uuid.UUID,
	username string,
	expiresAt time.Time,
) JWTClaims {
	return JWTClaims{
		ClaimsData: ClaimsData{
			AccountID: accoutID,
			RoleID:    roleID,
			Username:  username,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
}

func GenerateToken(claims JWTClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return t, nil
}

// NewClaims generates a new JWTClaims.
func NewClaims(c echo.Context) jwt.Claims {
	return new(JWTClaims) // TODO: Create a claims builder function
}
