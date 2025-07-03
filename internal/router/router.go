package router

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

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
	configMiddlewares(e)

	// Defining subroutes
	auth := e.Group("/auth")
	acc := e.Group("/account")
	role := e.Group("/role")
	log := e.Group("/log")

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
