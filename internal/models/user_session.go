package models

import (
	"time"

	"github.com/google/uuid"
)

type UserSession struct {
	ID                uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID            uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	RefreshTokenHash  string     `gorm:"not null" json:"-"`
	DeviceID          string     `gorm:"column:device_id" json:"device_id"`
	DeviceName        string     `gorm:"column:device_name" json:"device_name"`
	Platform          string     `gorm:"column:platform" json:"platform"`
	IPAddress         string     `gorm:"column:ip_address" json:"ip_address"`
	UserAgent         string     `gorm:"column:user_agent" json:"user_agent"`
	LastUsedAt        time.Time  `gorm:"not null;default:NOW()" json:"last_used_at"`
	ExpiredAt         time.Time  `gorm:"not null" json:"expired_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevokeReason      string     `json:"revoke_reason"`
	CreatedAt         time.Time  `gorm:"not null;default:NOW()" json:"created_at"`

	// Link back to user
	User User `gorm:"foreignKey:UserID" json:"-"`
}
