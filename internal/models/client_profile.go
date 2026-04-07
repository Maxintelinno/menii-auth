package models

import (
	"time"

	"github.com/google/uuid"
)

type ClientProfile struct {
	UserID    uuid.UUID `gorm:"type:uuid;primaryKey" json:"user_id"`
	FirstName string    `gorm:"not null" json:"first_name"`
	LastName  string    `gorm:"not null" json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Link back to user
	User User `gorm:"foreignKey:UserID" json:"-"`
}
