package repository

import (
	"time"

	"menii-auth/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(user *models.User) error
	FindByEmail(email string) (*models.User, error)
	FindByPhone(phone string) (*models.User, error)
	FindByUsername(username string) (*models.User, error)
	FindByID(id uuid.UUID) (*models.User, error)
	GetRoleByCode(code string) (*models.Role, error)
	UpdateLastLogin(userID uuid.UUID) error
	CreateSession(session *models.UserSession) error
	RevokeSession(sessionID uuid.UUID, reason string) error
	WithTx(tx *gorm.DB) UserRepository
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) WithTx(tx *gorm.DB) UserRepository {
	return &userRepository{db: tx}
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles").Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByPhone(phone string) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles").Where("phone = ?", phone).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles").Where("phone = ? OR email = ?", username, username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles").First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetRoleByCode(code string) (*models.Role, error) {
	var role models.Role
	if err := r.db.Where("code = ?", code).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *userRepository) UpdateLastLogin(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("last_login_at", &now).Error
}

func (r *userRepository) CreateSession(session *models.UserSession) error {
	return r.db.Create(session).Error
}

func (r *userRepository) RevokeSession(sessionID uuid.UUID, reason string) error {
	return r.db.Model(&models.UserSession{}).
		Where("id = ?", sessionID).
		Updates(map[string]interface{}{
			"revoked_at":    time.Now(),
			"revoke_reason": reason,
		}).Error
}
