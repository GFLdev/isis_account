package router

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type JWTClaims struct {
	AccountID uuid.UUID
	RoleID    uuid.UUID
	Username  string
	jwt.RegisteredClaims
}

// NewClaims generates a new JWTClaims.
func NewClaims(c echo.Context) jwt.Claims {
	return new(JWTClaims) // TODO: Create a claims builder function
}
