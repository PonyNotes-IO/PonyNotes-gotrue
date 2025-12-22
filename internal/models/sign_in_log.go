package models

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

// SignInLog represents a structured record of a user sign-in attempt.
type SignInLog struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserUUID    uuid.UUID `json:"user_uuid" db:"user_uuid"`
	UserUID     *int64    `json:"user_uid,omitempty" db:"user_uid"`
	Provider    *string   `json:"provider,omitempty" db:"provider"`
	ThirdPartyID *string  `json:"third_party_id,omitempty" db:"third_party_id"`
	IPAddress   *string   `json:"ip_address,omitempty" db:"ip_address"`
	Country     *string   `json:"country,omitempty" db:"country"`
	Region      *string   `json:"region,omitempty" db:"region"`
	City        *string   `json:"city,omitempty" db:"city"`
	UserAgent   *string   `json:"user_agent,omitempty" db:"user_agent"`
	Success     bool      `json:"success" db:"success"`
	ErrorReason *string   `json:"error_reason,omitempty" db:"error_reason"`
	Metadata    JSONMap   `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

func (SignInLog) TableName() string {
	return "sign_in_logs"
}

// CreateSignInLog persists a sign-in log record in the database using the provided transaction.
func CreateSignInLog(tx *storage.Connection, l *SignInLog) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.Must(uuid.NewV4())
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}

	if err := tx.Create(l); err != nil {
		return errors.Wrap(err, "Database error creating sign in log")
	}
	return nil
}

// FindSignInLogsByUser returns sign-in logs for a given user UUID, ordered by created_at desc.
func FindSignInLogsByUser(tx *storage.Connection, userUUID uuid.UUID, pageParams *Pagination) ([]*SignInLog, error) {
	q := tx.Q().Order("created_at desc").Where("user_uuid = ?", userUUID)

	logs := []*SignInLog{}
	var err error
	if pageParams != nil {
		err = q.Paginate(int(pageParams.Page), int(pageParams.PerPage)).All(&logs)
		pageParams.Count = uint64(q.Paginator.TotalEntriesSize)
	} else {
		err = q.All(&logs)
	}
	return logs, err
}


