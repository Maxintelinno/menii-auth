package models

import (
	"time"

	"github.com/google/uuid"
)

type ConsentLog struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID         uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
	ConsentType    string    `gorm:"not null" json:"consent_type"`
	ConsentVersion string    `gorm:"not null" json:"consent_version"`
	Accepted       bool      `gorm:"not null" json:"accepted"`
	AcceptedAt     time.Time `gorm:"not null;default:NOW()" json:"accepted_at"`
	Source         string    `json:"source"`
}
