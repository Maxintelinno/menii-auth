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

type OtpRateLimitError struct {
	RetryAfterSec int
}

func (e *OtpRateLimitError) Error() string {
	return fmt.Sprintf("OTP_RATE_LIMITED: please wait %d seconds", e.RetryAfterSec)
}

var (
	ErrInvalidCredentials  = errors.New("INVALID_CREDENTIALS")
	ErrAccountNotVerified  = errors.New("ACCOUNT_NOT_VERIFIED")
	ErrAccountSuspended    = errors.New("ACCOUNT_SUSPENDED")
	ErrInvalidRefreshToken   = errors.New("INVALID_REFRESH_TOKEN")
	ErrSessionExpired        = errors.New("SESSION_EXPIRED")
	ErrUserNotFound          = errors.New("USER_NOT_FOUND")
	ErrOtpExpired            = errors.New("OTP_EXPIRED")
	ErrOtpInvalid            = errors.New("OTP_INVALID")
	ErrOtpMaxAttemptsExceeded = errors.New("OTP_MAX_ATTEMPTS_EXCEEDED")
)

type AuthService interface {
	Register(req *models.RegisterRequest) (*models.RegisterResponseData, error)
	Login(req *models.LoginRequest) (*models.LoginResponseData, error)
	Logout(sessionID uuid.UUID) error
	RefreshToken(req *models.RefreshRequest) (*models.LoginResponseData, error)
	RequestOTP(req *models.OtpRequestPayload) (*models.OtpResponseData, error)
	VerifyOTP(req *models.VerifyOtpRequest) (*models.VerifyOtpResponseData, error)
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
		return nil, ErrInvalidCredentials
	}

	// 2. Check credentials
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// 3. Check status & is_active
	if !user.IsActive {
		return nil, ErrAccountSuspended
	}
	if user.Status == "PENDING_VERIFY" {
		return nil, ErrAccountNotVerified
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

func (s *authService) Logout(sessionID uuid.UUID) error {
	return s.repo.RevokeSession(sessionID, "USER_LOGOUT")
}

func (s *authService) RefreshToken(req *models.RefreshRequest) (*models.LoginResponseData, error) {
	// 1. Parse Token
	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidRefreshToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidRefreshToken
	}

	// 2. Check Type & Session
	tokenType, _ := claims["token_type"].(string)
	if tokenType != "refresh" {
		return nil, ErrInvalidRefreshToken
	}

	sessionIDStr, _ := claims["session_id"].(string)
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	session, err := s.repo.FindSessionByID(sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	// 3. Guards
	if session.RevokedAt != nil {
		return nil, ErrInvalidRefreshToken
	}
	if time.Now().After(session.ExpiredAt) {
		return nil, ErrSessionExpired
	}

	// 4. Verify Hash
	providedHash := hashRefreshToken(req.RefreshToken)
	if session.RefreshTokenHash != providedHash {
		// Possibly token theft (reuse of old token)
		_ = s.repo.RevokeSession(sessionID, "TOKEN_REUSE_DETECTED")
		return nil, ErrInvalidRefreshToken
	}

	// 5. Rotate & Issue New Tokens
	roleCodes := make([]string, len(session.User.Roles))
	for i, r := range session.User.Roles {
		roleCodes[i] = r.Code
	}

	newAccessToken, err := s.generateToken(session.UserID, session.ID, "access", roleCodes, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := s.generateToken(session.UserID, session.ID, "refresh", nil, 30*24*time.Hour)
	if err != nil {
		return nil, err
	}

	// 6. Update Session in DB (Rotate Hash)
	session.RefreshTokenHash = hashRefreshToken(newRefreshToken)
	session.LastUsedAt = time.Now()
	// Optionally update ExpiredAt? User suggested 30 days.
	// session.ExpiredAt = time.Now().Add(30 * 24 * time.Hour)

	if err := s.repo.UpdateSession(session); err != nil {
		return nil, err
	}

	// 7. Response
	res := &models.LoginResponseData{
		User: models.UserInfoResponse{
			UserID: session.UserID,
			Phone:  *session.User.Phone,
			Status: session.User.Status,
			Roles:  roleCodes,
		},
		Tokens: models.TokensResponse{
			AccessToken:      newAccessToken,
			RefreshToken:     newRefreshToken,
			TokenType:        "Bearer",
			ExpiresIn:        900,
			RefreshExpiresIn: 2592000,
		},
	}
	if session.User.Email != nil {
		res.User.Email = *session.User.Email
	}

	return res, nil
}

func (s *authService) RequestOTP(req *models.OtpRequestPayload) (*models.OtpResponseData, error) {
	// 1. Validate User based on Purpose
	user, err := s.repo.FindByPhone(req.Phone)
	if req.Purpose == "REGISTER" {
		if err != nil || user.Status != "PENDING_VERIFY" {
			return nil, errors.New("invalid registration status")
		}
	} else if req.Purpose == "FORGOT_PASSWORD" {
		if err != nil {
			return nil, ErrUserNotFound
		}
	} else {
		// PHONE_VERIFY
		if err != nil {
			return nil, ErrUserNotFound
		}
	}

	// 2. Daily Limit Check (e.g., max 10 per day)
	dailyCount, _ := s.repo.CountOtpRequestsToday(req.Phone)
	if dailyCount >= 10 {
		return nil, errors.New("daily otp limit exceeded")
	}

	// 3. Rate Limit Check (60 seconds cooldown)
	latest, err := s.repo.GetLatestOtpRequest(req.Phone, req.Purpose)
	if err == nil {
		elapsed := time.Since(latest.CreatedAt)
		if elapsed < 60*time.Second {
			return nil, &OtpRateLimitError{RetryAfterSec: int(60 - elapsed.Seconds())}
		}
	}

	// 4. Generate & Save OTP
	otpCode := generateOTP()
	refCode := generateRefCode()
	otpHash, _ := bcrypt.GenerateFromPassword([]byte(otpCode), bcrypt.DefaultCost)

	otpReq := &models.OtpRequest{
		Phone:         &req.Phone,
		OtpCodeHash:   string(otpHash),
		ReferenceCode: refCode,
		Purpose:       req.Purpose,
		TargetUserID:  user.ID,
		ExpiredAt:     time.Now().Add(5 * time.Minute),
		RequestStatus: "PENDING",
	}

	if err := s.db.Create(otpReq).Error; err != nil {
		return nil, err
	}

	// 5. Mock SMS Send
	logger.GetLogger().Info(fmt.Sprintf("Sending OTP: %s to %s (Purpose: %s, Ref: %s)", otpCode, req.Phone, req.Purpose, refCode))

	return &models.OtpResponseData{
		ReferenceCode: refCode,
		ExpiresInSec:  300,
		RetryAfterSec: 60,
	}, nil
}

func (s *authService) VerifyOTP(req *models.VerifyOtpRequest) (*models.VerifyOtpResponseData, error) {
	// 1. Find OTP Request
	otp, err := s.repo.FindByReferenceCode(req.ReferenceCode)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOtpInvalid
		}
		return nil, err
	}

	// 2. Initial Checks
	if otp.RequestStatus != "PENDING" {
		return nil, ErrOtpInvalid
	}
	if time.Now().After(otp.ExpiredAt) {
		otp.RequestStatus = "EXPIRED"
		_ = s.repo.UpdateOtpRequest(otp)
		return nil, ErrOtpExpired
	}
	if otp.AttemptCount >= otp.MaxAttempt {
		return nil, ErrOtpMaxAttemptsExceeded
	}

	// 3. Compare OTP Code
	if err := bcrypt.CompareHashAndPassword([]byte(otp.OtpCodeHash), []byte(req.OtpCode)); err != nil {
		otp.AttemptCount++
		if otp.AttemptCount >= otp.MaxAttempt {
			otp.RequestStatus = "FAILED"
		}
		_ = s.repo.UpdateOtpRequest(otp)
		return nil, ErrOtpInvalid
	}

	// 4. Verification Success
	now := time.Now()
	otp.VerifiedAt = &now
	otp.RequestStatus = "VERIFIED"
	if err := s.repo.UpdateOtpRequest(otp); err != nil {
		return nil, err
	}

	res := &models.VerifyOtpResponseData{
		Verified: true,
		Purpose:  otp.Purpose,
		UserID:   otp.TargetUserID,
	}

	// 5. Purpose-based logic
	switch otp.Purpose {
	case "REGISTER":
		// Update user status
		if err := s.repo.UpdateUserStatus(otp.TargetUserID, "ACTIVE"); err != nil {
			return nil, err
		}
		res.AccountStatus = "ACTIVE"
	case "FORGOT_PASSWORD":
		// Generate temporary reset token (no session_id)
		resetToken, err := s.generateToken(otp.TargetUserID, uuid.Nil, "reset", nil, 15*time.Minute)
		if err != nil {
			return nil, err
		}
		res.ResetToken = resetToken
		res.ResetTokenExpiresIn = 900
	case "PHONE_VERIFY":
		// Possibly mark phone as verified in profile
		// (Assume logic done for now)
	}

	return res, nil
}

func (s *authService) generateToken(userID, sessionID uuid.UUID, tokenType string, roles []string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub":        userID.String(),
		"token_type": tokenType,
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(duration).Unix(),
	}

	if sessionID != uuid.Nil {
		claims["session_id"] = sessionID.String()
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
