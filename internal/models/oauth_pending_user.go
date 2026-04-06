package models

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"

	"github.com/gofrs/uuid"
)

// OAuthPendingUser stores OAuth user data before phone binding
type OAuthPendingUser struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	Platform   string                 `json:"platform" db:"platform"`
	ProviderID string                 `json:"provider_id" db:"provider_id"`
	UserMeta   JSONMap `json:"user_meta" db:"user_meta"`
	PendingToken string               `json:"pending_token" db:"pending_token"`
	ExpiresAt  time.Time             `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time             `json:"created_at" db:"created_at"`
}

// TableName is "oauth_pending_users"
func (OAuthPendingUser) TableName() string {
	return "oauth_pending_users"
}

// NewOAuthPendingUser creates a new pending OAuth user record
func NewOAuthPendingUser(platform, providerID string, userMeta map[string]interface{}) (*OAuthPendingUser, error) {
	id := uuid.Must(uuid.NewV4())

	// Generate a random pending token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, errors.Wrap(err, "failed to generate pending token")
	}
	pendingToken := hex.EncodeToString(tokenBytes)

	// Token expires in 30 minutes
	expiresAt := time.Now().Add(30 * time.Minute)

	return &OAuthPendingUser{
		ID:          id,
		Platform:    platform,
		ProviderID:  providerID,
		UserMeta:    userMeta,
		PendingToken: pendingToken,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}, nil
}

// IsExpired checks if the pending user record has expired
func (p *OAuthPendingUser) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// FindOAuthPendingUserByToken finds a pending user by pending token
func FindOAuthPendingUserByToken(tx *storage.Connection, pendingToken string) (*OAuthPendingUser, error) {
	obj := &OAuthPendingUser{}
	if err := tx.Q().Where("pending_token = ?", pendingToken).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthPendingUserNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding oauth pending user")
	}
	if obj.IsExpired() {
		// Clean up expired record
		if err := tx.Destroy(obj); err != nil {
			errors.Wrap(err, "error deleting expired oauth pending user")
		}
		return nil, OAuthPendingUserNotFoundError{}
	}
	return obj, nil
}

// OAuthPendingUserNotFoundError indicates the pending user record was not found
type OAuthPendingUserNotFoundError struct{}

func (OAuthPendingUserNotFoundError) Error() string   { return "oauth pending user not found" }
func (OAuthPendingUserNotFoundError) NotFoundError() {}

func IsOAuthPendingUserNotFoundError(err error) bool {
	_, ok := errors.Cause(err).(OAuthPendingUserNotFoundError)
	return ok
}
