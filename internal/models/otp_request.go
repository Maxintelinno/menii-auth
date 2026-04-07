package models

import (
	"time"

	"github.com/google/uuid"
)

type OtpRequest struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Phone         *string    `json:"phone,omitempty"`
	Email         *string    `json:"email,omitempty"`
	OtpCodeHash   string     `gorm:"not null" json:"-"`
	ReferenceCode string     `gorm:"uniqueIndex;not null" json:"reference_code"`
	Purpose       string     `gorm:"not null" json:"purpose"`
	TargetUserID  uuid.UUID  `gorm:"type:uuid;column:target_user_id" json:"target_user_id"`
	ExpiredAt     time.Time  `gorm:"not null" json:"expired_at"`
	VerifiedAt    *time.Time `json:"verified_at"`
	AttemptCount  int        `gorm:"not null;default:0" json:"attempt_count"`
	MaxAttempt    int        `gorm:"not null;default:5" json:"max_attempt"`
	RequestStatus string     `gorm:"not null;default:'PENDING'" json:"request_status"`
	CreatedAt     time.Time  `gorm:"not null;default:NOW()" json:"created_at"`
}
