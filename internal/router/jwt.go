package router

import (
	"errors"
	"isis_account/internal/config"
	"isis_account/internal/router/queries"
	"isis_account/internal/types"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	echojwt "github.com/labstack/echo-jwt/v4"
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
	accountID uuid.UUID,
	roleID uuid.UUID,
	username string,
	expiresAt time.Time,
) JWTClaims {
	return JWTClaims{
		ClaimsData: ClaimsData{
			AccountID: accountID,
			RoleID:    roleID,
			Username:  username,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
}

func GetToken(c echo.Context) (*jwt.Token, error) {
	// Get config
	cfg := config.GetConfig()

	// Get cookie
	cookie, err := c.Cookie("access_token")
	if err != nil {
		return nil, types.TokenError.Err()
	}

	// Parse token
	tokenString := cookie.Value
	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, types.ParseTokenError.Err()
			}
			return []byte(cfg.JWT.Secret), nil
		},
		jwt.WithoutClaimsValidation(), // get claims from expired tokens (refresh)
	)
	if err != nil {
		return nil, types.TokenError.Err()
	}
	return token, nil
}

func GetClaims(c echo.Context, token *jwt.Token) (*JWTClaims, error) {
	// Parse token claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, types.ClaimsError.Err()
	}

	// Validate data
	ok, err := queries.CheckAccountWithRole(
		claims.ClaimsData.AccountID,
		claims.ClaimsData.RoleID,
	)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, types.InvalidClaimsData.Err()
	}
	return claims, nil
}

// GetClaimsData is a wrapper to get JWT claims data from echo.Context.
func GetClaimsData(c echo.Context) (*ClaimsData, error) {
	// Get token
	token, err := GetToken(c)
	if err != nil {
		return nil, err
	}

	// Get claims from token
	claims, err := GetClaims(c, token)
	if err != nil {
		return nil, err
	}
	return &claims.ClaimsData, nil
}

func GenerateToken(claims JWTClaims) (string, error) {
	cfg := config.GetConfig()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		return "", err
	}
	return t, nil
}

func AuthErrorHandler(c echo.Context, err error) error {
	switch {
	case errors.As(err, &echojwt.ErrJWTMissing):
		c.JSON(http.StatusUnauthorized, types.TokenError)
	case errors.As(err, &echojwt.ErrJWTInvalid):
		c.JSON(http.StatusUnauthorized, types.ParseTokenError.Message())
	default:
		c.JSON(http.StatusInternalServerError, types.AuthFailedError.Message())
	}
	return err
}

// TokenErrorHandler handles the error returned from token related getter
// functions, sending a coherent JSON response for each possible error.
func TokenErrorHandler(c echo.Context, err error) error {
	switch {
	case errors.Is(err, types.TokenError.Err()):
		c.JSON(http.StatusUnauthorized, types.TokenError.Message())
	case errors.Is(err, types.ClaimsError.Err()):
	case errors.Is(err, types.ParseTokenError.Err()):
		c.JSON(http.StatusInternalServerError, types.ParsingError.Message())
	case errors.Is(err, types.InvalidClaimsData.Err()):
		c.JSON(http.StatusUnauthorized, types.InvalidClaimsData.Message())
	default:
		c.JSON(http.StatusInternalServerError, types.AuthFailedError.Message())
	}
	return err
}
