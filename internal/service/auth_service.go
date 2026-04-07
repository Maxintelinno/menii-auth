package service

import (
	"errors"
	"time"

	"menii-auth/config"
	"menii-auth/internal/models"
	"menii-auth/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(req *models.RegisterRequest) error
	Login(req *models.LoginRequest) (*models.TokenResponse, error)
}

type authService struct {
	repo   repository.UserRepository
	config *config.JWTConfig
}

func NewAuthService(repo repository.UserRepository, config *config.JWTConfig) AuthService {
	return &authService{repo: repo, config: config}
}

func (s *authService) Register(req *models.RegisterRequest) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	return s.repo.Create(user)
}

func (s *authService) Login(req *models.LoginRequest) (*models.TokenResponse, error) {
	user, err := s.repo.FindByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	token, err := s.generateToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		Token: token,
	}, nil
}

func (s *authService) generateToken(userID uint) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * time.Duration(s.config.ExpiryHours)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.Secret))
}
