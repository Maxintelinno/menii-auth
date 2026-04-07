package main

import (
	"fmt"
	"log"

	"menii-auth/config"
	"menii-auth/internal/handler"
	appMiddleware "menii-auth/internal/middleware"
	"menii-auth/internal/models"
	"menii-auth/internal/repository"
	"menii-auth/internal/service"
	"menii-auth/pkg/db"
	"menii-auth/pkg/logger"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	logger.InitLogger(cfg.App.Env)
	log := logger.GetLogger()
	defer log.Sync()

	// Initialize database
	db.InitDB(&cfg.Database)
	database := db.GetDB()

	// Auto-migrate models
	if err := database.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.ClientProfile{},
		&models.ConsentLog{},
		&models.OtpRequest{},
		&models.UserSession{},
	); err != nil {
		log.Fatal("Failed to auto-migrate database")
	}

	// Initialize components
	userRepo := repository.NewUserRepository(database)
	authSvc := service.NewAuthService(database, userRepo, &cfg.JWT)
	authHandler := handler.NewAuthHandler(authSvc)

	// Initialize Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Routes
	e.GET("/health", handler.HealthCheck)

	api := e.Group("/api/v1")
	auth := api.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout, appMiddleware.JWTMiddleware(&cfg.JWT))
	}

	// Start server
	addr := fmt.Sprintf(":%d", cfg.App.Port)
	fmt.Println("Starting server on " + addr)
	if err := e.Start(addr); err != nil {
		log.Fatal("Server failed to start")
	}
}
