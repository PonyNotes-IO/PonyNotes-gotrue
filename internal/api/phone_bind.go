package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// SendPhoneBindCodeParams 是绑定手机号发送验证码的参数
type SendPhoneBindCodeParams struct {
	Phone       string `json:"phone"`
	PendingToken string `json:"pending_token"` // OAuth 流程中的临时 token（可选）
}

// SendPhoneBindCodeResponse 是绑定手机号发送验证码的响应
type SendPhoneBindCodeResponse struct {
	CodeSent    bool   `json:"code_sent"`
	PhoneExists bool   `json:"phone_exists"` // 手机号已被其他账号注册
	IsOwnPhone  bool   `json:"is_own_phone"` // 手机号是当前用户的
	ExistingUID string `json:"existing_uid,omitempty"` // 已存在账号的 UID
	Message     string `json:"message,omitempty"`
}

// SendPhoneBindCode 发送绑定手机号的验证码
// - 有 pending_token：OAuth pending 流程，pending_token 识别待绑定用户
// - 无 pending_token：已登录用户换绑手机号流程
func (a *API) SendPhoneBindCode(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	params := &SendPhoneBindCodeParams{}
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body: "+err.Error())
	}

	phone, err := validatePhone(params.Phone)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"phone": phone,
		"aud":   aud,
	}).Info("[SendPhoneBindCode] Processing phone bind code request")

	// 有 pending_token → OAuth pending 流程
	if params.PendingToken != "" {
		return a.sendPhoneBindCodeWithPendingToken(ctx, db, w, r, phone, params.PendingToken, logEntry)
	}

	// 无 pending_token → 已登录用户换绑手机号流程
	return a.sendPhoneBindCodeAuthenticated(ctx, db, w, r, phone, logEntry)
}

// sendPhoneBindCodeWithPendingToken OAuth pending 流程的发送验证码
func (a *API) sendPhoneBindCodeWithPendingToken(ctx context.Context, db *storage.Connection, w http.ResponseWriter, r *http.Request, phone, pendingToken string, logEntry *logrus.Entry) error {
	pendingUser, err := models.FindOAuthPendingUserByToken(db, pendingToken)
	if err != nil {
		if models.IsOAuthPendingUserNotFoundError(err) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Pending token expired or invalid. Please re-authenticate.")
		}
		logEntry.WithError(err).Error("[SendPhoneBindCode] Database error finding pending user")
		return apierrors.NewInternalServerError("Database error").WithInternalError(err)
	}

	logEntry = logEntry.WithFields(logrus.Fields{
		"pending_user_id": pendingUser.ID,
		"platform":        pendingUser.Platform,
	})

	// 检查手机号是否已被其他用户注册
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, a.requestAud(ctx, r))
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Database error checking phone")
			return apierrors.NewInternalServerError("Database error checking phone").WithInternalError(err)
		}
		// 手机号未被占用，OTP 发送到该手机（将绑定到新建账号）
		logEntry.Info("[SendPhoneBindCode] Phone not registered, sending OTP")

		tmpUser := &models.User{Aud: a.requestAud(ctx, r)}
		tmpUser.Phone = storage.NullString(phone)

		if _, err := a.sendPhoneConfirmation(r, db, tmpUser, phone, phoneConfirmationOtp, sms_provider.SMSProvider); err != nil {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Failed to send OTP")
			return err
		}

		return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
			CodeSent:    true,
			PhoneExists: false,
			IsOwnPhone:  false,
		})
	}

	// 手机号已被其他账号注册 → OTP 发送到已注册用户
	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Info("[SendPhoneBindCode] Phone already registered, sending OTP to existing user")

	if _, err := a.sendPhoneConfirmation(r, db, existingUser, phone, phoneConfirmationOtp, sms_provider.SMSProvider); err != nil {
		logEntry.WithError(err).Error("[SendPhoneBindCode] Failed to send OTP to existing user")
		return err
	}

	return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
		CodeSent:    true,
		PhoneExists: true,
		IsOwnPhone:  false,
		ExistingUID: existingUser.ID.String(),
		Message:     "This phone number is already registered. Please verify ownership to bind.",
	})
}

// sendPhoneBindCodeAuthenticated 已登录用户换绑手机号流程的发送验证码
func (a *API) sendPhoneBindCodeAuthenticated(ctx context.Context, db *storage.Connection, w http.ResponseWriter, r *http.Request, phone string, logEntry *logrus.Entry) error {
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not authenticated")
	}

	logEntry = logEntry.WithFields(logrus.Fields{
		"user_id": user.ID,
	})

	// 检查手机号是否属于当前用户
	if user.GetPhone() == phone {
		return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
			CodeSent:    false,
			IsOwnPhone:  true,
			PhoneExists: false,
			Message:     "This phone number is already bound to your account",
		})
	}

	// 检查手机号是否已被其他用户注册
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, a.requestAud(ctx, r))
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Database error checking phone")
			return apierrors.NewInternalServerError("Database error checking phone").WithInternalError(err)
		}
		// 手机号未被占用，OTP 发送到当前用户
		logEntry.Info("[SendPhoneBindCode] Phone not registered, sending OTP to current user")

		if _, err := a.sendPhoneConfirmation(r, db, user, phone, phoneConfirmationOtp, sms_provider.SMSProvider); err != nil {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Failed to send OTP")
			return err
		}

		return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
			CodeSent:    true,
			PhoneExists: false,
			IsOwnPhone:  false,
		})
	}

	// 手机号已被其他用户注册 → 直接拒绝，不允许绑定他人手机号
	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Warn("[SendPhoneBindCode] Attempted to bind phone registered by another user - rejected")
	return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "This phone number is already registered by another account and cannot be bound")
}

// ConfirmPhoneBindParams 是确认手机号绑定的参数
type ConfirmPhoneBindParams struct {
	Phone        string `json:"phone"`
	Token        string `json:"token"`         // 手机验证码
	PendingToken string `json:"pending_token"` // OAuth 流程中的临时 token（可选）
	Merge        bool   `json:"merge"`         // 是否绑定到已注册账号
}

// ConfirmPhoneBindResponse 是确认手机号绑定的响应
type ConfirmPhoneBindResponse struct {
	BindToExisting bool   `json:"bind_to_existing"`
	UserID         string `json:"user_id"`
	Message        string `json:"message,omitempty"`
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	ExpiresIn     int    `json:"expires_in,omitempty"`
	TokenType     string `json:"token_type,omitempty"`
}

// ConfirmPhoneBind 确认手机号绑定
// - 有 pending_token：OAuth pending 流程，无需登录态
// - 无 pending_token：已登录用户换绑手机号流程
func (a *API) ConfirmPhoneBind(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	params := &ConfirmPhoneBindParams{}
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body: "+err.Error())
	}

	phone, err := validatePhone(params.Phone)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"phone":        phone,
		"pending_token": params.PendingToken,
		"merge":        params.Merge,
		"aud":          aud,
	}).Info("[ConfirmPhoneBind] Processing phone bind confirmation")

	// 有 pending_token → OAuth pending 流程
	if params.PendingToken != "" {
		return a.confirmPhoneBindWithPendingToken(ctx, db, w, r, phone, params, logEntry)
	}

	// 无 pending_token → 已登录用户换绑手机号流程
	return a.confirmPhoneBindAuthenticated(ctx, db, w, r, phone, params, logEntry)
}

// confirmPhoneBindWithPendingToken OAuth pending 流程的确认绑定
func (a *API) confirmPhoneBindWithPendingToken(ctx context.Context, db *storage.Connection, w http.ResponseWriter, r *http.Request, phone string, params *ConfirmPhoneBindParams, logEntry *logrus.Entry) error {
	pendingUser, err := models.FindOAuthPendingUserByToken(db, params.PendingToken)
	if err != nil {
		if models.IsOAuthPendingUserNotFoundError(err) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Pending token expired or invalid. Please re-authenticate.")
		}
		logEntry.WithError(err).Error("[ConfirmPhoneBind] Database error finding pending user")
		return apierrors.NewInternalServerError("Database error").WithInternalError(err)
	}

	logEntry = logEntry.WithFields(logrus.Fields{
		"pending_user_id": pendingUser.ID,
		"platform":        pendingUser.Platform,
	})

	// 查找是否已有账号使用该手机号
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, a.requestAud(ctx, r))
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[ConfirmPhoneBind] Database error finding existing user")
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}
		// 手机号未注册 → 创建新用户并绑定
		logEntry.Info("[ConfirmPhoneBind] No existing user, creating new user with OAuth identity")

		var newUser *models.User
		err = db.Transaction(func(tx *storage.Connection) error {
			var terr error

			newUser, terr = models.NewUser(phone, "", "", a.requestAud(ctx, r), pendingUser.UserMeta)
			if terr != nil {
				return apierrors.NewInternalServerError("Error creating user").WithInternalError(terr)
			}
			newUser.IsSSOUser = true

			if terr = tx.Create(newUser); terr != nil {
				return apierrors.NewInternalServerError("Database error saving new user").WithInternalError(terr)
			}
			if terr = newUser.SetRole(tx, a.config.JWT.DefaultGroupName); terr != nil {
				return apierrors.NewInternalServerError("Database error updating user role").WithInternalError(terr)
			}

			identity, terr := models.NewIdentity(newUser, pendingUser.Platform, pendingUser.UserMeta)
			if terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}
			if terr = tx.Create(identity); terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}

			if err := a.verifyPhoneOTPForBind(tx, newUser, phone, params.Token, a.requestAud(ctx, r)); err != nil {
				return err
			}

			if terr = tx.Destroy(pendingUser); terr != nil {
				return apierrors.NewInternalServerError("Error deleting pending user").WithInternalError(terr)
			}

			if terr = models.NewAuditLogEntry(a.config.AuditLog, nil, tx, newUser, models.UserSignedUpAction, "", map[string]interface{}{
				"action":   "oauth_pending_bind_new_user",
				"platform": pendingUser.Platform,
			}); terr != nil {
				return terr
			}

			return nil
		})
		if err != nil {
			return err
		}

		logEntry.WithField("new_user_id", newUser.ID).Info("[ConfirmPhoneBind] New user created with OAuth identity")

		var grantParams models.GrantParams
		grantParams.FillGrantParams(r)
		token, terr := a.issueRefreshToken(r, db, newUser, models.PasswordGrant, grantParams)
		if terr != nil {
			logEntry.WithError(terr).Error("[ConfirmPhoneBind] Failed to issue token")
			return apierrors.NewInternalServerError("Failed to issue token").WithInternalError(terr)
		}

		return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
			BindToExisting: false,
			UserID:         newUser.ID.String(),
			Message:        "Account created successfully.",
			AccessToken:   token.Token,
			RefreshToken:  token.RefreshToken,
			ExpiresIn:     token.ExpiresIn,
			TokenType:     token.TokenType,
		})
	}

	// 找到了已注册账号
	if !params.Merge {
		return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
			BindToExisting: false,
			UserID:         "",
			Message:        "Binding to existing account was not confirmed by user",
		})
	}

	// 执行绑定到已注册账号
	logEntry.WithFields(logrus.Fields{
		"pending_user_id":  pendingUser.ID,
		"existing_user_id": existingUser.ID,
	}).Info("[ConfirmPhoneBind] Binding OAuth identity to existing account")

	tokenHash := crypto.GenerateTokenHash(phone, params.Token)
	if !isOtpValid(tokenHash, existingUser.ConfirmationToken, existingUser.ConfirmationSentAt, a.config.Sms.OtpExp) {
		logEntry.Error("[ConfirmPhoneBind] OTP verify failed for existing user")
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error

		identity, terr := models.NewIdentity(existingUser, pendingUser.Platform, pendingUser.UserMeta)
		if terr != nil {
			return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
		}

		existingIdentity, terr := models.FindIdentityByIdAndProvider(tx, identity.ProviderID, identity.Provider)
		if terr == nil && existingIdentity != nil && existingIdentity.UserID == existingUser.ID {
			logEntry.WithFields(logrus.Fields{
				"provider":    identity.Provider,
				"provider_id": identity.ProviderID,
			}).Info("[ConfirmPhoneBind] Existing account already has this identity, skipping")
		} else {
			if terr = tx.Create(identity); terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}
			logEntry.WithFields(logrus.Fields{
				"provider": identity.Provider,
			}).Info("[ConfirmPhoneBind] OAuth identity added to existing account")
		}

		if terr = tx.Destroy(pendingUser); terr != nil {
			return apierrors.NewInternalServerError("Error deleting pending user").WithInternalError(terr)
		}

		if terr = models.NewAuditLogEntry(a.config.AuditLog, nil, tx, existingUser, models.UserModifiedAction, "", map[string]interface{}{
			"action":              "bind_oauth_to_existing_phone",
			"pending_user_id":    pendingUser.ID.String(),
			"migrated_identities": 1,
		}); terr != nil {
			return terr
		}

		return nil
	})
	if err != nil {
		return err
	}

	logEntry.WithField("existing_user_id", existingUser.ID).Info("[ConfirmPhoneBind] OAuth identity bound to existing account successfully")

	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)
	token, terr := a.issueRefreshToken(r, db, existingUser, models.PasswordGrant, grantParams)
	if terr != nil {
		logEntry.WithError(terr).Error("[ConfirmPhoneBind] Failed to issue token")
		return apierrors.NewInternalServerError("Failed to issue token").WithInternalError(terr)
	}

	return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
		BindToExisting: true,
		UserID:         existingUser.ID.String(),
		Message:        "OAuth identity bound to existing account successfully.",
		AccessToken:   token.Token,
		RefreshToken:  token.RefreshToken,
		ExpiresIn:     token.ExpiresIn,
		TokenType:     token.TokenType,
	})
}

// confirmPhoneBindAuthenticated 已登录用户换绑手机号流程的确认绑定
func (a *API) confirmPhoneBindAuthenticated(ctx context.Context, db *storage.Connection, w http.ResponseWriter, r *http.Request, phone string, params *ConfirmPhoneBindParams, logEntry *logrus.Entry) error {
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not authenticated")
	}

	logEntry = logEntry.WithFields(logrus.Fields{
		"user_id": user.ID,
	})

	// 检查手机号是否已绑定当前用户
	if user.GetPhone() == phone {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Phone number is already bound to your account")
	}

	// 检查手机号是否已被其他用户注册
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, a.requestAud(ctx, r))
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[ConfirmPhoneBind] Database error finding existing user")
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}
		// 手机号未注册 → 更新当前用户的手机号
		logEntry.Info("[ConfirmPhoneBind] No existing user, updating current user's phone")

		// 验证 OTP
		tokenHash := crypto.GenerateTokenHash(phone, params.Token)
		if !isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, a.config.Sms.OtpExp) {
			logEntry.Error("[ConfirmPhoneBind] OTP verify failed for current user")
			return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
		}

		// 更新手机号
		if err := user.SetPhone(db, phone); err != nil {
			logEntry.WithError(err).Error("[ConfirmPhoneBind] Failed to update phone")
			return apierrors.NewInternalServerError("Failed to update phone").WithInternalError(err)
		}

		logEntry.WithField("new_phone", phone).Info("[ConfirmPhoneBind] Phone updated successfully")

		return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
			BindToExisting: false,
			UserID:         user.ID.String(),
			Message:        "Phone number updated successfully.",
		})
	}

	// 手机号已被其他用户注册 → 直接拒绝，不允许绑定他人手机号
	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Warn("[ConfirmPhoneBind] Attempted to bind phone registered by another user - rejected")
	return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "This phone number is already registered by another account and cannot be bound")
}

// verifyPhoneOTPForBind 验证手机号 OTP 并标记已确认（用于绑定流程）
func (a *API) verifyPhoneOTPForBind(db *storage.Connection, user *models.User, phone, token, aud string) error {
	tokenHash := crypto.GenerateTokenHash(phone, token)

	verifyUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Invalid or expired verification code")
	}

	if verifyUser.ID != user.ID {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code mismatch")
	}

	if !isOtpValid(tokenHash, verifyUser.ConfirmationToken, verifyUser.ConfirmationSentAt, a.config.Sms.OtpExp) {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
	}

	now := time.Now()
	verifyUser.PhoneConfirmedAt = &now
	if err := db.UpdateOnly(verifyUser, "phone_confirmed_at"); err != nil {
		return apierrors.NewInternalServerError("Error confirming phone").WithInternalError(err)
	}

	return nil
}

// migrateUserData 调用 Cloud API 将 secondary 用户的工作区数据迁移到 primary 用户
func (a *API) migrateUserData(ctx context.Context, primaryUserUUID, secondaryUserUUID string) (int, error) {
	cloudURL := a.config.Cloud.URL
	if cloudURL == "" {
		logrus.Warn("[migrateUserData] Cloud URL not configured, skipping data migration")
		return 0, nil
	}

	reqBody := struct {
		PrimaryUserUUID   string `json:"primary_user_uuid"`
		SecondaryUserUUID string `json:"secondary_user_uuid"`
	}{
		PrimaryUserUUID:   primaryUserUUID,
		SecondaryUserUUID: secondaryUserUUID,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request body: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Cloud.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		cloudURL+"/internal/migrate-user-data", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Duration(a.config.Cloud.Timeout) * time.Second}
	return doMigrateUserData(client, req)
}

func doMigrateUserData(client *http.Client, req *http.Request) (int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cloud API call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("cloud API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		MigratedWorkspaceCount int `json:"migrated_workspace_count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		logrus.WithError(err).Warn("[migrateUserData] Failed to parse response, treating as partial success")
		return 0, nil
	}

	return result.MigratedWorkspaceCount, nil
}

// CheckEmailRegisteredResponse 是检测邮箱是否已注册的响应
type CheckEmailRegisteredResponse struct {
	EmailExists bool   `json:"email_exists"`
	IsOwnEmail  bool   `json:"is_own_email"`
	ExistingUID string `json:"existing_uid,omitempty"`
	Message     string `json:"message,omitempty"`
}

// CheckEmailRegistered 检测邮箱是否已被其他账号注册
func (a *API) CheckEmailRegistered(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not authenticated")
	}

	params := &struct {
		Email string `json:"email"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body: "+err.Error())
	}

	email, err := a.validateEmail(params.Email)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"user_id": user.ID,
		"email":   email,
		"aud":     aud,
	}).Info("[CheckEmailRegistered] Checking email registration status")

	if user.GetEmail() == email {
		return sendJSON(w, http.StatusOK, &CheckEmailRegisteredResponse{
			EmailExists: false,
			IsOwnEmail:  true,
			Message:     "This email is already bound to your account",
		})
	}

	existingUser, err := models.FindUserByEmailAndAudience(db, email, aud)
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[CheckEmailRegistered] Database error checking email")
			return apierrors.NewInternalServerError("Database error checking email").WithInternalError(err)
		}
		logEntry.Info("[CheckEmailRegistered] Email not registered")
		return sendJSON(w, http.StatusOK, &CheckEmailRegisteredResponse{
			EmailExists: false,
			IsOwnEmail:  false,
		})
	}

	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Info("[CheckEmailRegistered] Email already registered by another user")

	return sendJSON(w, http.StatusOK, &CheckEmailRegisteredResponse{
		EmailExists: true,
		IsOwnEmail:  false,
		ExistingUID: existingUser.ID.String(),
		Message:     "该邮箱已被其他账号注册",
	})
}
