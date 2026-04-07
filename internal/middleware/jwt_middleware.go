package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"menii-auth/config"
	"menii-auth/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func JWTMiddleware(cfg *config.JWTConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "missing authorization header",
				})
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "invalid authorization header format",
				})
			}

			tokenString := parts[1]
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(cfg.Secret), nil
			})

			if err != nil || !token.Valid {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "invalid or expired token",
				})
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "invalid token claims",
				})
			}

			// Extract sub (UserID) and session_id
			sub, _ := claims["sub"].(string)
			sessionID, _ := claims["session_id"].(string)

			userID, err := uuid.Parse(sub)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "invalid user id in token",
				})
			}

			sessID, err := uuid.Parse(sessionID)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Code:    "UNAUTHORIZED",
					Message: "invalid session id in token",
				})
			}

			// Set to context
			c.Set("user_id", userID)
			c.Set("session_id", sessID)

			return next(c)
		}
	}
}
