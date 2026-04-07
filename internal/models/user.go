package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Phone        *string        `gorm:"uniqueIndex" json:"phone"`
	Email        *string        `gorm:"uniqueIndex" json:"email"`
	PasswordHash string         `gorm:"not null" json:"-"`
	Status       string         `gorm:"not null;default:'PENDING_VERIFY'" json:"status"`
	IsActive     bool           `gorm:"not null;default:true" json:"is_active"`
	LastLoginAt  *time.Time     `json:"last_login_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	ClientProfile *ClientProfile `json:"client_profile,omitempty"`
	Roles         []Role         `gorm:"many2many:user_roles;" json:"roles,omitempty"`
}

type LoginRequest struct {
	Username   string `json:"username" validate:"required"`
	Password   string `json:"password" validate:"required"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RegisterRequest struct {
	Phone           string `json:"phone" validate:"required"`
	Email           string `json:"email" validate:"omitempty,email"`
	Password        string `json:"password" validate:"required,min=8"`
	FirstName       string `json:"first_name" validate:"required"`
	LastName        string `json:"last_name" validate:"required"`
	AcceptedTerms   bool   `json:"accepted_terms" validate:"required,oneof=true"`
	AcceptedPrivacy bool   `json:"accepted_privacy" validate:"required,oneof=true"`
}

type RegisterResponseData struct {
	UserID           uuid.UUID `json:"user_id"`
	Status           string    `json:"status"`
	OTPReferenceCode string    `json:"otp_reference_code"`
	OTPExpiresInSec  int       `json:"otp_expires_in_sec"`
}

type LoginResponseData struct {
	User   UserInfoResponse `json:"user"`
	Tokens TokensResponse   `json:"tokens"`
}

type UserInfoResponse struct {
	UserID uuid.UUID `json:"user_id"`
	Phone  string    `json:"phone"`
	Email  string    `json:"email"`
	Status string    `json:"status"`
	Roles  []string  `json:"roles"`
}

type TokensResponse struct {
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         int    `json:"expires_in"`
	RefreshExpiresIn  int    `json:"refresh_expires_in"`
}

type TokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type APIResponse struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
