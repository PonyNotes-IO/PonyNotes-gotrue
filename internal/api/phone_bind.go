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
	Phone string `json:"phone"`
}

// SendPhoneBindCodeResponse 是绑定手机号发送验证码的响应
type SendPhoneBindCodeResponse struct {
	CodeSent    bool   `json:"code_sent"`
	PhoneExists bool   `json:"phone_exists"` // 手机号已被其他账号注册
	IsOwnPhone  bool   `json:"is_own_phone"` // 手机号是当前用户的
	ExistingUID string `json:"existing_uid,omitempty"` // 已存在账号的 UID（用于合并时展示）
	Message     string `json:"message,omitempty"`
}

// SendPhoneBindCode 发送绑定手机号的验证码
// 如果手机号已被其他账号注册，返回 phone_exists=true，前端据此弹出"账号合并"确认框
func (a *API) SendPhoneBindCode(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	// 获取当前用户（必须已登录）
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not authenticated")
	}

	params := &SendPhoneBindCodeParams{}
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body: "+err.Error())
	}

	// 验证手机号格式
	phone, err := validatePhone(params.Phone)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"user_id": user.ID,
		"phone":   phone,
		"aud":     aud,
	}).Info("[SendPhoneBindCode] Processing phone bind request")

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
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Database error checking phone")
			return apierrors.NewInternalServerError("Database error checking phone").WithInternalError(err)
		}
		// 没找到 → 手机号未被占用，可以正常发送验证码
		logEntry.Info("[SendPhoneBindCode] Phone not registered, sending code")

		if _, err := a.sendPhoneConfirmation(r, db, user, phone, phoneConfirmationOtp, ""); err != nil {
			logEntry.WithError(err).Error("[SendPhoneBindCode] Failed to send OTP")
			return err
		}

		return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
			CodeSent:    true,
			PhoneExists: false,
			IsOwnPhone:  false,
		})
	}

	// 手机号已被其他账号注册 → 返回已存在账号信息，前端弹出合并确认
	logEntry.WithFields(logrus.Fields{
		"existing_user_id": existingUser.ID,
	}).Info("[SendPhoneBindCode] Phone already registered by another user, returning for merge confirmation")

	return sendJSON(w, http.StatusOK, &SendPhoneBindCodeResponse{
		CodeSent:    false,
		PhoneExists: true,
		IsOwnPhone:  false,
		ExistingUID: existingUser.ID.String(),
		Message:     "This phone number is already registered. Would you like to merge accounts?",
	})
}

// ConfirmPhoneBindParams 是确认手机号绑定的参数
type ConfirmPhoneBindParams struct {
	Phone string `json:"phone"`
	Token string `json:"token"`
	Merge bool   `json:"merge"` // 是否执行账号合并
}

// ConfirmPhoneBindResponse 是确认手机号绑定的响应
type ConfirmPhoneBindResponse struct {
	Merged             bool   `json:"merged"`
	PrimaryUserID      string `json:"primary_user_id"`           // 合并后保留的主账号 ID
	DeletedUserID      string `json:"deleted_user_id,omitempty"` // 被删除的重复账号 ID
	Message            string `json:"message,omitempty"`
	MigratedWorkspaces int    `json:"migrated_workspaces,omitempty"` // 迁移的工作区数量
}

// ConfirmPhoneBind 确认手机号绑定（含账号合并）
func (a *API) ConfirmPhoneBind(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	// 获取当前用户（必须已登录）
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not authenticated")
	}

	params := &ConfirmPhoneBindParams{}
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body: "+err.Error())
	}

	// 验证手机号格式
	phone, err := validatePhone(params.Phone)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"user_id": user.ID,
		"phone":   phone,
		"merge":   params.Merge,
		"aud":     aud,
	}).Info("[ConfirmPhoneBind] Processing phone bind confirmation")

	// 检查手机号是否属于当前用户（已绑定的）
	if user.GetPhone() == phone {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Phone number is already bound to your account")
	}

	// 查找已注册该手机号的账号
	existingUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[ConfirmPhoneBind] Database error finding existing user")
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}
		// 没找到 → 无法合并，验证码应该也是发给当前用户的
		logEntry.Info("[ConfirmPhoneBind] No existing user, proceeding with simple bind")

		// 走普通验证码校验流程
		if _, err := a.verifyPhoneOTPAndBind(db, user, phone, params.Token, aud); err != nil {
			logEntry.WithError(err).Error("[ConfirmPhoneBind] OTP verify failed")
			return err
		}

		return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
			Merged:        false,
			PrimaryUserID: user.ID.String(),
			Message:       "Phone number bound successfully",
		})
	}

	// 找到了已注册账号
	// 如果前端没有传 merge=true（用户取消合并），则返回错误
	if !params.Merge {
		return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
			Merged:        false,
			PrimaryUserID: user.ID.String(),
			Message:       "Account merge was not confirmed by user",
		})
	}

	// 执行账号合并
	logEntry.WithFields(logrus.Fields{
		"primary_user_id":   user.ID,
		"secondary_user_id": existingUser.ID,
	}).Info("[ConfirmPhoneBind] Executing account merge")

	// 确认 OTP（发给当前用户）
	if _, err := a.verifyPhoneOTPAndBind(db, user, phone, params.Token, aud); err != nil {
		logEntry.WithError(err).Error("[ConfirmPhoneBind] OTP verify failed during merge")
		return err
	}

	// 保存 secondaryUser 的 UUID（在数据库删除前）
	secondaryUserUUID := existingUser.ID.String()

	// 执行认证层合并：迁移 identities，失效 sessions，软删除 secondaryUser
	if err := a.mergeAuthUsers(db, user, existingUser); err != nil {
		logEntry.WithError(err).Error("[ConfirmPhoneBind] Auth merge failed")
		return apierrors.NewInternalServerError("Account auth merge failed").WithInternalError(err)
	}

	logEntry.Info("[ConfirmPhoneBind] Auth merge completed, now migrating user data")

	// 调用 Cloud API 执行数据迁移
	migratedCount, err := a.migrateUserData(ctx, user.ID.String(), secondaryUserUUID)
	if err != nil {
		logEntry.WithError(err).Warn("[ConfirmPhoneBind] Data migration failed, but auth merge succeeded")
		// 数据迁移失败不影响整体合并成功（数据可以通过定时任务补迁移）
	}

	if migratedCount > 0 {
		logEntry.WithField("migrated_workspaces", migratedCount).Info("[ConfirmPhoneBind] Data migration completed")
	}

	logEntry.WithFields(logrus.Fields{
		"primary_user_id":    user.ID,
		"deleted_user_id":    secondaryUserUUID,
		"migrated_workspaces": migratedCount,
	}).Info("[ConfirmPhoneBind] Account merge completed successfully")

	return sendJSON(w, http.StatusOK, &ConfirmPhoneBindResponse{
		Merged:             true,
		PrimaryUserID:      user.ID.String(),
		DeletedUserID:      secondaryUserUUID,
		MigratedWorkspaces: migratedCount,
		Message:            fmt.Sprintf("Accounts merged successfully. %d workspace(s) migrated.", migratedCount),
	})
}

// migrateUserData 调用 Cloud API 将 secondary 用户的工作区数据迁移到 primary 用户
// 返回迁移的工作区数量
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

	// 设置请求超时（使用 context，以防 Cloud 服务响应过慢）
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Cloud.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		cloudURL+"/internal/migrate-user-data", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if a.cloudClient == nil {
		// 如果没有初始化 client，创建一个临时 client
		client := &http.Client{Timeout: time.Duration(a.config.Cloud.Timeout) * time.Second}
		return doMigrateUserData(client, req)
	}
	return doMigrateUserData(a.cloudClient, req)
}

// doMigrateUserData 执行实际的 HTTP 请求并解析响应
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

	// 解析响应
	var result struct {
		MigratedWorkspaceCount int `json:"migrated_workspace_count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// 响应格式解析失败，尝试从原始响应中提取
		logrus.WithError(err).Warn("[migrateUserData] Failed to parse response, treating as partial success")
		return 0, nil
	}

	return result.MigratedWorkspaceCount, nil
}

// verifyPhoneOTPAndBind 验证手机号 OTP 并绑定到用户（不触发账号合并）
func (a *API) verifyPhoneOTPAndBind(db *storage.Connection, user *models.User, phone, token, aud string) (*models.User, error) {
	config := a.config

	// 生成 token hash
	tokenHash := crypto.GenerateTokenHash(phone, token)

	// 查找拥有该 token 的用户（应该是当前用户）
	verifyUser, err := models.FindUserByPhoneAndAudience(db, phone, aud)
	if err != nil {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Invalid or expired verification code")
	}

	// 确保 OTP 是发给当前用户的（防止 OTP 发给旧账号时有人用合并请求偷梁换柱）
	if verifyUser.ID != user.ID {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code mismatch")
	}

	// 校验 OTP
	isValid := isOtpValid(tokenHash, verifyUser.ConfirmationToken, verifyUser.ConfirmationSentAt, config.Sms.OtpExp)
	if !isValid {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Verification code expired or invalid")
	}

	// 绑定手机号
	if err := verifyUser.SetPhone(db, phone); err != nil {
		return nil, apierrors.NewInternalServerError("Error binding phone").WithInternalError(err)
	}

	// 标记手机已确认
	now := time.Now()
	verifyUser.PhoneConfirmedAt = &now
	if err := db.UpdateOnly(verifyUser, "phone", "phone_confirmed_at"); err != nil {
		return nil, apierrors.NewInternalServerError("Error confirming phone").WithInternalError(err)
	}

	// 如果是 SSO 用户，清除 SSO 标志
	if verifyUser.IsSSOUser {
		verifyUser.IsSSOUser = false
		if err := db.UpdateOnly(verifyUser, "is_sso_user"); err != nil {
			return nil, apierrors.NewInternalServerError("Error clearing SSO flag").WithInternalError(err)
		}
	}

	return verifyUser, nil
}

// mergeAuthUsers 将 secondaryUser 的认证数据合并到 primaryUser
// 合并策略（仅限认证层）：
//   - identities：从 secondaryUser 迁移到 primaryUser（处理关联的第三方账号）
//   - sessions：失效 secondaryUser 的所有会话
//   - factors：删除 secondaryUser 的所有 MFA factors
//   - refresh_tokens：删除 secondaryUser 的所有 refresh tokens
//   - phone：已在绑定阶段设置到 primaryUser
//   - 删除 secondaryUser（软删除）
// 注意：此函数只处理认证层数据，不涉及业务数据迁移
func (a *API) mergeAuthUsers(db *storage.Connection, primaryUser, secondaryUser *models.User) error {
	logEntry := logrus.WithFields(logrus.Fields{
		"primary_user_id":   primaryUser.ID,
		"secondary_user_id": secondaryUser.ID,
	})

	logEntry.Info("[mergeAuthUsers] Starting auth layer merge")

	err := db.Transaction(func(tx *storage.Connection) error {
		// 1. 迁移 secondaryUser 的 identities 到 primaryUser
		identities, err := models.FindIdentitiesByUserID(tx, secondaryUser.ID)
		if err != nil {
			return err
		}

		for _, identity := range identities {
			// 检查 primaryUser 是否已有相同 provider 的 identity
			existingIdentity, err := models.FindIdentityByIdAndProvider(tx, identity.ProviderID, identity.Provider)
			if err == nil && existingIdentity != nil && existingIdentity.UserID == primaryUser.ID {
				// primaryUser 已有该 provider → 删除 secondaryUser 的这个 identity（避免冲突）
				logEntry.WithFields(logrus.Fields{
					"provider":    identity.Provider,
					"provider_id": identity.ProviderID,
				}).Info("[mergeAuthUsers] Primary user already has this identity, deleting from secondary")
				if err := tx.Destroy(identity); err != nil {
					return err
				}
				continue
			}

			// 将 identity 的 UserID 指向 primaryUser
			identity.UserID = primaryUser.ID
			if err := tx.UpdateOnly(identity, "user_id"); err != nil {
				return err
			}
			logEntry.WithFields(logrus.Fields{
				"provider": identity.Provider,
			}).Info("[mergeAuthUsers] Migrated identity to primary user")
		}

		// 2. 删除 secondaryUser 的所有 MFA factors
		if err := models.DeleteFactorsByUserId(tx, secondaryUser.ID); err != nil {
			return err
		}
		logrus.Info("[mergeAuthUsers] Deleted MFA factors from secondary user")

		// 3. 删除 secondaryUser 的所有 refresh tokens（使其会话失效）
		if err := models.Logout(tx, secondaryUser.ID); err != nil {
			return err
		}
		logEntry.Info("[mergeAuthUsers] Invalidated all sessions of secondary user")

		// 4. 软删除 secondaryUser
		if err := secondaryUser.SoftDeleteUser(tx); err != nil {
			return err
		}
		logEntry.WithField("deleted_user_id", secondaryUser.ID).Info("[mergeAuthUsers] Soft deleted secondary user")

		// 5. 记录审计日志
		if err := models.NewAuditLogEntry(a.config.AuditLog, nil, tx, primaryUser, models.UserModifiedAction, "", map[string]interface{}{
			"action":            "account_merge",
			"deleted_user_id":   secondaryUser.ID.String(),
			"merged_identities": len(identities),
			"merge_type":        "phone_bind_merge",
		}); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		logEntry.WithError(err).Error("[mergeAuthUsers] Auth merge transaction failed")
		return err
	}

	logEntry.Info("[mergeAuthUsers] Auth layer merge completed successfully")
	return nil
}

// CheckEmailRegisteredResponse 是检测邮箱是否已注册的响应
type CheckEmailRegisteredResponse struct {
	EmailExists bool   `json:"email_exists"` // 邮箱已被其他账号注册
	IsOwnEmail  bool   `json:"is_own_email"` // 邮箱是当前用户的
	ExistingUID string `json:"existing_uid,omitempty"` // 已存在账号的 UID
	Message     string `json:"message,omitempty"`
}

// CheckEmailRegistered 检测邮箱是否已被其他账号注册
// 用于邮箱绑定/换绑场景，前端在发送验证码前先检测
func (a *API) CheckEmailRegistered(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	// 获取当前用户（必须已登录）
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

	// 检查邮箱是否属于当前用户
	if user.GetEmail() == email {
		return sendJSON(w, http.StatusOK, &CheckEmailRegisteredResponse{
			EmailExists: false,
			IsOwnEmail:  true,
			Message:     "This email is already bound to your account",
		})
	}

	// 检查邮箱是否已被其他用户注册
	existingUser, err := models.FindUserByEmailAndAudience(db, email, aud)
	if err != nil {
		if !models.IsNotFoundError(err) {
			logEntry.WithError(err).Error("[CheckEmailRegistered] Database error checking email")
			return apierrors.NewInternalServerError("Database error checking email").WithInternalError(err)
		}
		// 没找到 → 邮箱未被占用
		logEntry.Info("[CheckEmailRegistered] Email not registered")
		return sendJSON(w, http.StatusOK, &CheckEmailRegisteredResponse{
			EmailExists: false,
			IsOwnEmail:  false,
		})
	}

	// 邮箱已被其他账号注册
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
