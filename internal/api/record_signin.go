package api

import (
	"context"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// recordSignInEvent writes a SignInLog record to the database. This function
// should not block or fail the main authentication flow; callers are advised
// to run it in a goroutine if they don't want to wait for completion.
func (a *API) recordSignInEvent(ctx context.Context, r *http.Request, userID uuid.UUID, loginType metering.LoginType, data *metering.LoginData, success bool, errorReason string) error {
	db := a.db.WithContext(ctx)

	provider := ""
	if data != nil && data.Provider != "" {
		provider = data.Provider
	}

	ip := ""
	if r != nil {
		ip = r.RemoteAddr
	}
	ua := ""
	if r != nil {
		ua = r.Header.Get("User-Agent")
	}

	var providerPtr *string
	var uaPtr *string
	var ipPtr *string
	if provider != "" {
		providerPtr = &provider
	}
	if ua != "" {
		uaPtr = &ua
	}
	if ip != "" {
		ipPtr = &ip
	}

	log := &models.SignInLog{
		UserUUID:    userID,
		Provider:    providerPtr,
		UserAgent:   uaPtr,
		IPAddress:   ipPtr,
		Success:     success,
	}

	// Attempt to persist in a transaction but do not surface errors to callers.
	err := db.Transaction(func(tx *storage.Connection) error {
		// use models.CreateSignInLog which accepts tx
		return models.CreateSignInLog(tx, log)
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"user_id": userID.String(),
			"error":   err.Error(),
		}).Warn("failed to persist sign in log")
	}
	return err
}


