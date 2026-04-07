package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"menii-auth/config"
	"menii-auth/internal/models"
	"menii-auth/internal/repository"
	"menii-auth/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService interface {
	Register(req *models.RegisterRequest) (*models.RegisterResponseData, error)
	Login(req *models.LoginRequest) (*models.LoginResponseData, error)
}

type authService struct {
	db     *gorm.DB
	repo   repository.UserRepository
	config *config.JWTConfig
}

func NewAuthService(db *gorm.DB, repo repository.UserRepository, config *config.JWTConfig) AuthService {
	return &authService{db: db, repo: repo, config: config}
}

func (s *authService) Register(req *models.RegisterRequest) (*models.RegisterResponseData, error) {
	// 1. Password validation
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}

	// 2. Check phone/email uniqueness
	if _, err := s.repo.FindByPhone(req.Phone); err == nil {
		return nil, errors.New("phone already exists")
	}
	if req.Email != "" {
		if _, err := s.repo.FindByEmail(req.Email); err == nil {
			return nil, errors.New("email already exists")
		}
	}

	// 3. Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var responseData models.RegisterResponseData

	// 4. Transaction
	err = s.db.Transaction(func(tx *gorm.DB) error {
		txRepo := s.repo.WithTx(tx)

		// Create user
		user := &models.User{
			Phone:        &req.Phone,
			PasswordHash: string(hashedPassword),
			Status:       "PENDING_VERIFY",
			IsActive:     true,
		}
		if req.Email != "" {
			user.Email = &req.Email
		}

		if err := tx.Create(user).Error; err != nil {
			return err
		}

		// Create ClientProfile
		profile := &models.ClientProfile{
			UserID:    user.ID,
			FirstName: req.FirstName,
			LastName:  req.LastName,
		}
		if err := tx.Create(profile).Error; err != nil {
			return err
		}

		// Get Role
		role, err := txRepo.GetRoleByCode("CLIENT")
		if err != nil {
			// Fallback if role doesn't exist (should ideally exist)
			role = &models.Role{Code: "CLIENT", Name: "Client"}
			if err := tx.FirstOrCreate(role, models.Role{Code: "CLIENT"}).Error; err != nil {
				return err
			}
		}

		// Assign Role
		userRole := &models.UserRole{
			UserID: user.ID,
			RoleID: role.ID,
		}
		if err := tx.Create(userRole).Error; err != nil {
			return err
		}

		// Consent Logs
		consents := []models.ConsentLog{
			{UserID: user.ID, ConsentType: "TERMS", ConsentVersion: "1.0", Accepted: true, Source: "REGISTER"},
			{UserID: user.ID, ConsentType: "PRIVACY", ConsentVersion: "1.0", Accepted: true, Source: "REGISTER"},
		}
		if err := tx.Create(&consents).Error; err != nil {
			return err
		}

		// Generate OTP
		otpCode := generateOTP()
		refCode := generateRefCode()
		otpHash, _ := bcrypt.GenerateFromPassword([]byte(otpCode), bcrypt.DefaultCost)

		otpReq := &models.OtpRequest{
			Phone:         &req.Phone,
			OtpCodeHash:   string(otpHash),
			ReferenceCode: refCode,
			Purpose:       "REGISTER",
			TargetUserID:  user.ID,
			ExpiredAt:     time.Now().Add(5 * time.Minute),
			RequestStatus: "PENDING",
		}
		if err := tx.Create(otpReq).Error; err != nil {
			return err
		}

		// Mock SMS Send
		logger.GetLogger().Info(fmt.Sprintf("Sending OTP: %s to %s (Ref: %s)", otpCode, req.Phone, refCode))

		responseData = models.RegisterResponseData{
			UserID:           user.ID,
			Status:           user.Status,
			OTPReferenceCode: refCode,
			OTPExpiresInSec:  300,
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &responseData, nil
}

func (s *authService) Login(req *models.LoginRequest) (*models.LoginResponseData, error) {
	// 1. Find user by phone or email
	user, err := s.repo.FindByUsername(req.Username)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	// 2. Check credentials
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid username or password")
	}

	// 3. Check status & is_active
	if !user.IsActive {
		return nil, errors.New("user account is inactive")
	}
	if user.Status == "PENDING_VERIFY" {
		return nil, errors.New("user account is pending verification")
	}

	// 4. Prepare Roles
	roleCodes := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roleCodes[i] = r.Code
	}

	// 5. Generate Session ID
	sessionID := uuid.New()

	// 6. Generate Tokens
	accessToken, err := s.generateToken(user.ID, sessionID, "access", roleCodes, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.generateToken(user.ID, sessionID, "refresh", nil, 30*24*time.Hour)
	if err != nil {
		return nil, err
	}

	// 7. Store Refresh Token in Session
	rfHash := hashRefreshToken(refreshToken)
	session := &models.UserSession{
		ID:               sessionID,
		UserID:           user.ID,
		RefreshTokenHash: rfHash,
		DeviceID:         req.DeviceID,
		DeviceName:       req.DeviceName,
		Platform:         req.Platform,
		ExpiredAt:        time.Now().Add(30 * 24 * time.Hour),
	}

	if err := s.repo.CreateSession(session); err != nil {
		return nil, err
	}

	// 8. Update Last Login
	_ = s.repo.UpdateLastLogin(user.ID)

	// 9. Prepare Response
	res := &models.LoginResponseData{
		User: models.UserInfoResponse{
			UserID: user.ID,
			Phone:  *user.Phone,
			Status: user.Status,
			Roles:  roleCodes,
		},
		Tokens: models.TokensResponse{
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			TokenType:        "Bearer",
			ExpiresIn:        900,
			RefreshExpiresIn: 2592000,
		},
	}
	if user.Email != nil {
		res.User.Email = *user.Email
	}

	return res, nil
}

func (s *authService) generateToken(userID, sessionID uuid.UUID, tokenType string, roles []string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub":        userID.String(),
		"session_id": sessionID.String(),
		"token_type": tokenType,
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(duration).Unix(),
	}

	if roles != nil {
		claims["roles"] = roles
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.Secret))
}

// Helpers
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasUpper || !hasLower || !hasNumber {
		return errors.New("password must contain uppercase, lowercase, and numbers")
	}
	return nil
}

func generateOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func generateRefCode() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("OTP-%s", hex.EncodeToString(b))
}

func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
