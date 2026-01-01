package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// SignInLogRequest represents the request body for creating a sign-in log from client
type SignInLogRequest struct {
	UserUID      *int64         `json:"user_uid,omitempty"`
	Provider     *string        `json:"provider,omitempty"`
	ThirdPartyID *string        `json:"third_party_id,omitempty"`
	Country      *string        `json:"country,omitempty"`
	Region       *string        `json:"region,omitempty"`
	City         *string        `json:"city,omitempty"`
	Success      bool           `json:"success"`
	ErrorReason  *string        `json:"error_reason,omitempty"`
	Metadata     models.JSONMap `json:"metadata,omitempty"`
}

// ClientSignInLog handles POST /user/sign_in_log
// This endpoint allows authenticated clients to record their sign-in events
func (a *API) ClientSignInLog(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	// Get user from context (set by requireAuthentication middleware)
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "User not found in context")
	}

	// Parse request body
	var params SignInLogRequest
	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		return apierrors.NewInternalServerError("Could not read body into byte slice").WithInternalError(err)
	}
	if err := json.Unmarshal(body, &params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Could not parse request body as JSON: %v", err)
	}

	// Extract IP address from request
	ipAddress := getClientIPAddress(r)

	// Extract User-Agent from request headers
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = ""
	}

	// Build SignInLog from request params
	log := &models.SignInLog{
		UserUUID:     user.ID,
		UserUID:      params.UserUID,
		Provider:     params.Provider,
		ThirdPartyID: params.ThirdPartyID,
		IPAddress:    &ipAddress,
		Country:      params.Country,
		Region:       params.Region,
		City:         params.City,
		UserAgent:    &userAgent,
		Success:      params.Success,
		ErrorReason:  params.ErrorReason,
		Metadata:     params.Metadata,
	}

	// If metadata is nil, initialize it as empty map
	if log.Metadata == nil {
		log.Metadata = make(models.JSONMap)
	}

	// Persist sign-in log in a transaction
	err = db.Transaction(func(tx *storage.Connection) error {
		return models.CreateSignInLog(tx, log)
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"user_id": user.ID.String(),
			"error":   err.Error(),
		}).Warn("failed to persist client sign in log")
		return apierrors.NewInternalServerError("Failed to create sign-in log").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"id":        log.ID.String(),
		"user_uuid": log.UserUUID.String(),
		"success":   true,
	})
}

// getClientIPAddress extracts the client IP address from the request
// It checks X-Forwarded-For header first, then X-Real-IP, and finally RemoteAddr
func getClientIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies/load balancers)
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present (e.g., "192.168.1.1:12345" -> "192.168.1.1")
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

