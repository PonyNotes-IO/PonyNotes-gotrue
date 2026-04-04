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
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// SendPhoneBindCodeParams 是绑定手机号发送验证码的参数
type SendPhoneBindCodeParams struct {
	Phone       string `json:"phone"`
	PendingToken string `json:"pending_token"` // OAuth 流程中的临时 token
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
// 使用 pending_token（无需登录态）来识别 OAuth 待绑定用户
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

	// pending_token 是必填的
	if params.PendingToken == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "pending_token is required")
	}

	// 通过 pending_token 找到 OAuth 待绑定用户
	pendingUser, err := models.FindOAuthPendingUserByToken(db, params.PendingToken)
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
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Database error checking phone")
			return apierrors.NewInternalServerError("Database error checking phone").WithInternalError(err)
		}
		// 手机号未被占用，OTP 发送到该手机（将绑定到新建账号）
		logEntry.Info("[SendPhoneBindCode] Phone not registered, sending OTP")

		// OTP 验证时需要一个 user 对象来存储 ConfirmationToken。
		// 创建一个临时 user 对象用于 OTP 管理，不写入数据库。
		tmpUser := &models.User{
			Aud:   aud,
			Phone: storage.NullString(phone),
		}

		if _, err := a.sendPhoneConfirmation(r, db, tmpUser, phone, phoneConfirmationOtp, ""); err != nil {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Failed to send OTP")
			return err
		}

		return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
			CodeSent:    true,
			PhoneExists: false,
			IsOwnPhone:  false,
		})
	}

	// 手机号已被其他账号注册 → OTP 发送到已注册用户，验证手机所有权
	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Info("[SendPhoneBindCode] Phone already registered, sending OTP to existing user")

	if _, err := a.sendPhoneConfirmation(r, db, existingUser, phone, phoneConfirmationOtp, ""); err != nil {
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

// ConfirmPhoneBindParams 是确认手机号绑定的参数
type ConfirmPhoneBindParams struct {
	Phone       string `json:"phone"`
	Token       string `json:"token"`        // 手机验证码
	PendingToken string `json:"pending_token"` // OAuth 流程中的临时 token
	Merge       bool   `json:"merge"`        // 是否绑定到已注册账号
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
// 使用 pending_token（无需登录态）来识别 OAuth 待绑定用户
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

	if params.PendingToken == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "pending_token is required")
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"phone":   phone,
		"merge":   params.Merge,
		"aud":     aud,
	}).Info("[ConfirmPhoneBind] Processing phone bind confirmation")

	// 通过 pending_token 找到 OAuth 待绑定用户
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
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
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

			// 1. 创建新用户
			newUser, terr = models.NewUser(phone, "", "", aud, pendingUser.UserMeta)
			if terr != nil {
				return apierrors.NewInternalServerError("Error creating user").WithInternalError(terr)
			}
			newUser.IsSSOUser = true

			if terr = tx.Create(newUser); terr != nil {
				return apierrors.NewInternalServerError("Database error saving new user").WithInternalError(terr)
			}

			// 设置用户角色
			if terr = newUser.SetRole(tx, a.config.JWT.DefaultGroupName); terr != nil {
				return apierrors.NewInternalServerError("Database error updating user role").WithInternalError(terr)
			}

			// 2. 创建 identity
			identity, terr := models.NewIdentity(newUser, pendingUser.Platform, pendingUser.UserMeta)
			if terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}
			if terr = tx.Create(identity); terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}

			// 3. 验证 OTP（绑定到新用户）
			if err := a.verifyPhoneOTPForBind(tx, newUser, phone, params.Token, aud); err != nil {
				return err
			}

			// 4. 删除 pending 记录
			if terr = tx.Destroy(pendingUser); terr != nil {
				return apierrors.NewInternalServerError("Error deleting pending user").WithInternalError(terr)
			}

			// 5. 记录审计日志
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

		// 签发 token
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
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.ExpiresIn,
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

	// 验证 OTP（发给已注册账号的）
	tokenHash := crypto.GenerateTokenHash(phone, params.Token)
	if !isOtpValid(tokenHash, existingUser.ConfirmationToken, existingUser.ConfirmationSentAt, a.config.Sms.OtpExp) {
		logEntry.Error("[ConfirmPhoneBind] OTP verify failed for existing user")
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
	}

	// 在事务中执行：迁移 identity + 删除 pending 记录
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error

		// 1. 创建 identity 并关联到已注册用户
		identity, terr := models.NewIdentity(existingUser, pendingUser.Platform, pendingUser.UserMeta)
		if terr != nil {
			return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
		}

		// 检查是否已有相同 provider 的 identity
		existingIdentity, terr := models.FindIdentityByIdAndProvider(tx, identity.ProviderID, identity.Provider)
		if terr == nil && existingIdentity != nil && existingIdentity.UserID == existingUser.ID {
			// 已注册账号已有该 provider → 跳过（无需重复添加）
			logEntry.WithFields(logrus.Fields{
				"provider":    identity.Provider,
				"provider_id": identity.ProviderID,
			}).Info("[ConfirmPhoneBind] Existing account already has this identity, skipping")
		} else {
			// 创建新 identity
			if terr = tx.Create(identity); terr != nil {
				return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
			}
			logEntry.WithFields(logrus.Fields{
				"provider": identity.Provider,
			}).Info("[ConfirmPhoneBind] OAuth identity added to existing account")
		}

		// 2. 删除 pending 记录
		if terr = tx.Destroy(pendingUser); terr != nil {
			return apierrors.NewInternalServerError("Error deleting pending user").WithInternalError(terr)
		}

		// 3. 记录审计日志
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

	// 签发 token
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

// verifyPhoneOTPForBind 验证手机号 OTP 并标记已确认（用于绑定流程）
func (a *API) verifyPhoneOTPForBind(db *storage.Connection, user *models.User, phone, token, aud string) error {
	tokenHash := crypto.GenerateTokenHash(phone, token)

	// 查找拥有该 token 的用户
	verifyUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Invalid or expired verification code")
	}

	// 确保 OTP 是发给当前用户的
	if verifyUser.ID != user.ID {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code mismatch")
	}

	// 校验 OTP
	isValid := isOtpValid(tokenHash, verifyUser.ConfirmationToken, verifyUser.ConfirmationSentAt, a.config.Sms.OtpExp)
	if !isValid {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
	}

	// 标记手机已确认
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
