package router

import (
	"encoding/json"
	"isis_account/internal/utils"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// httpErrorHandlerWithLogs handles the errors, returned from the routes'
// handlers, and logs them.
func httpErrorHandlerWithLogs(err error, c echo.Context) {
	// Log error with HTTP information, if it is a Internal Server Error
	if c.Response().Status == http.StatusInternalServerError {
		utils.LogWithHTTPInfo(
			c,
			zap.L().Error,
			"HTTP request-response error",
			zap.Int("status", c.Response().Status),
			zap.Error(err),
		)
	}
}

// logHTTPInfo logs each request-response, filtering sensible data in the bodies.
func logHTTPInfo(c echo.Context, reqBody, resBody []byte) {
	// Filter sensible data to not show in logs
	filtered := make([][]byte, 2)
	bodies := [][]byte{reqBody, resBody}
	for j, body := range bodies {
		// Parse each body
		var i interface{}
		err := json.Unmarshal(body, &i)
		if err != nil {
			filtered[j] = []byte("")
			continue
		}

		// Filter sensible fields
		m, ok := i.(map[string]interface{})
		if ok {
			sensibleFields := []string{"password"}
			for _, field := range sensibleFields {
				delete(m, field)
			}
		} else {
			filtered[j] = []byte("")
			continue
		}

		payload, err := json.Marshal(i)
		if err == nil {
			filtered[j] = payload
		} else {
			filtered[j] = []byte("")
		}
	}

	// Log with HTTP information
	utils.LogWithHTTPInfo(
		c,
		zap.L().Info,
		"HTTP request-response",
		zap.Int("status", c.Response().Status),
		zap.String("request_body", string(filtered[0])),
		zap.String("response_body", string(filtered[1])),
	)
}

// configMiddlewares configure the middlewares for the echo router.
func configMiddlewares(e *echo.Echo) *echo.Echo {
	// Redirect to HTTPS
	// FIXME: Commented for testing purposes
	// e.Pre(middleware.HTTPSRedirect())

	// CORS config
	corsConfig := middleware.CORSConfig{
		AllowCredentials: true,
		AllowOrigins:     []string{"*"}, // TODO: Change to configurable origins
		AllowMethods: []string{
			echo.GET,
			echo.POST,
			echo.PATCH,
			echo.DELETE,
			echo.HEAD,
			echo.OPTIONS,
		},
		AllowHeaders: []string{
			echo.HeaderAuthorization,
			echo.HeaderOrigin,
			echo.HeaderContentType,
			echo.HeaderAccept,
		},
	}

	// Implement middlewares
	e.Use(
		middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
			logHTTPInfo(c, reqBody, resBody) // log HTTP req/res info
		}), // dump request/response bodies, for pre/post-processing
		middleware.Decompress(), // decompress request with gzip
		middleware.GzipWithConfig(
			middleware.GzipConfig{Level: 5},
		), // compress response with gzip, 5x
		middleware.RateLimiter(
			middleware.NewRateLimiterMemoryStore(rate.Limit(40)),
		), // limit 40 req/sec
		middleware.Recover(), // recover from panics
		middleware.SecureWithConfig(middleware.SecureConfig{
			XSSProtection:         "1; mode=block",
			ContentTypeNosniff:    "nosniff",
			XFrameOptions:         "DENY",
			HSTSMaxAge:            31536000, // 1 year
			HSTSPreloadEnabled:    true,
			ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self'",
		}), // rules against XSS scripting, sniffing, injections, etc.
		middleware.CORSWithConfig(corsConfig), // CORS
	)
	return e
}

// NewRouter build and configure the ISIS account service router.
func NewRouter() *echo.Echo {
	// New echo router with middlewares
	e := echo.New()
	e.HideBanner = true                           // hide start banner
	e.HidePort = true                             // hide started port
	e.IPExtractor = echo.ExtractIPFromXFFHeader() // extract IP
	e.HTTPErrorHandler = httpErrorHandlerWithLogs // HTTP error with logging
	configMiddlewares(e)

	// Defining subroutes
	auth := e.Group("/auth")

	restricted := e.Group("/")
	acc := restricted.Group("/account")
	role := restricted.Group("/role")
	log := restricted.Group("/log")

	// JWT
	jwtSecret := os.Getenv("JWT_SECRET") // TODO: Create config struct
	if jwtSecret == "" {
		zap.L().Warn("JWT secret not defined, defaulting to \"secret\"")
		jwtSecret = "secret"
	}
	jwtConfig := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JWTClaims)
		},
		SigningKey:    []byte(jwtSecret),
		SigningMethod: "HS256", // HMAC with SHA-256
		TokenLookup:   "cookie:access_token",
	}
	restricted.Use(echojwt.WithConfig(jwtConfig))

	// Defining routes
	auth.POST("/login", AuthLoginHandler)
	auth.POST("/refresh", AuthRefreshHandler)
	auth.POST("/logout", AuthLogoutHandler)

	acc.GET("/", func(c echo.Context) error { return nil })
	acc.GET("/:id", func(c echo.Context) error { return nil })
	acc.POST("/", func(c echo.Context) error { return nil })
	acc.PATCH("/:id", func(c echo.Context) error { return nil })
	acc.DELETE("/", func(c echo.Context) error { return nil })
	acc.DELETE("/:id", func(c echo.Context) error { return nil })

	role.GET("/", func(c echo.Context) error { return nil })
	role.GET("/:id", func(c echo.Context) error { return nil })
	role.POST("/", func(c echo.Context) error { return nil })
	role.PATCH("/:id", func(c echo.Context) error { return nil })
	role.DELETE("/", func(c echo.Context) error { return nil })
	role.DELETE("/:id", func(c echo.Context) error { return nil })

	log.GET("/", func(c echo.Context) error { return nil })
	log.GET("/login", func(c echo.Context) error { return nil })

	// Preflight
	e.OPTIONS("/*", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	// Returning router
	return e
}
