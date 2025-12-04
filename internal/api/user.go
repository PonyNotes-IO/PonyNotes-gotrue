package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// UserUpdateParams parameters for updating a user
type UserUpdateParams struct {
	Email               string                 `json:"email"`
	Password            *string                `json:"password"`
	Nonce               string                 `json:"nonce"`
	Data                map[string]interface{} `json:"data"`
	AppData             map[string]interface{} `json:"app_metadata,omitempty"`
	Phone               string                 `json:"phone"`
	Channel             string                 `json:"channel"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
}

func (a *API) validateUserUpdateParams(ctx context.Context, p *UserUpdateParams) error {
	config := a.config

	var err error
	if p.Email != "" {
		p.Email, err = a.validateEmail(p.Email)
		if err != nil {
			return err
		}
	}

	if p.Phone != "" {
		if p.Phone, err = validatePhone(p.Phone); err != nil {
			return err
		}
		if p.Channel == "" {
			p.Channel = sms_provider.SMSProvider
		}
		if !sms_provider.IsValidMessageChannel(p.Channel, config) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, InvalidChannelError)
		}
	}

	if p.Password != nil {
		if err := a.checkPasswordStrength(ctx, *p.Password); err != nil {
			return err
		}
	}

	return nil
}

// UserGet returns a user
func (a *API) UserGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := getClaims(ctx)
	if claims == nil {
		return apierrors.NewInternalServerError("Could not read claims")
	}

	aud := a.requestAud(ctx, r)
	audienceFromClaims, _ := claims.GetAudience()
	if len(audienceFromClaims) == 0 || aud != audienceFromClaims[0] {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Token audience doesn't match request audience")
	}

	user := getUser(ctx)
	return sendJSON(w, http.StatusOK, user)
}

// CheckPasswordStatusParams parameters for checking password status
type CheckPasswordStatusParams struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

// PasswordIsSet checks if a user has set a password (public endpoint, no auth required)
func (a *API) PasswordIsSet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	params := &CheckPasswordStatusParams{}
	q := r.URL.Query()
	params.Email = q.Get("email")
	params.Phone = q.Get("phone")

	fmt.Println(q)

	emptyEmail := params.Email == ""
	emptyPhone := params.Phone == ""

	var user *models.User
	var err error

	if emptyEmail && emptyPhone {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Either email or phone must be provided")
	}
	if !emptyEmail && !emptyPhone {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Only provide either email or phone, not both")
	}

	if !emptyEmail {
		params.Email, err = a.validateEmail(params.Email)
		if err != nil {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
		}
		user, err = models.FindUserByEmailAndAudience(db, params.Email, aud)
	} else {
		params.Phone, err = validatePhone(params.Phone)
		if err != nil {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
		}
		user, err = models.FindUserByPhoneAndAudience(db, params.Phone, aud)
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			// user not found
			return apierrors.NewNotFoundError(apierrors.ErrorCodeUserNotFound, "User not found")
		}
		// database ot other error
		return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
	}

	// user exists.return password_is_set
	response := map[string]bool{
		"password_is_set": user.PasswordIsSet,
	}

	return sendJSON(w, http.StatusOK, response)
}

// UpdatePassword updates the user's password
func (a *API) UpdatePassword(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config

	// 1. 获取 JWT claims，保证请求已认证
	claims := getClaims(ctx)
	if claims == nil {
		return apierrors.NewInternalServerError("Could not read claims")
	}

	// 2. 获取请求的 audience 并校验
	aud := a.requestAud(ctx, r)
	audienceFromClaims, _ := claims.GetAudience()
	if len(audienceFromClaims) == 0 || aud != audienceFromClaims[0] {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Token audience doesn't match request audience")
	}

	// 3. 获取当前用户
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewInternalServerError("Could not find user in context")
	}

	// 4. 解析请求参数
	params := struct {
		Password string `json:"password"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Could not parse request body as JSON: "+err.Error())
	}
	if params.Password == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Password cannot be empty")
	}

	// 5. 更新密码
	db := a.db.WithContext(ctx)
	if err := user.SetPassword(ctx, params.Password, true, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
		return err
	}
	// directly change this in the database without
	// calling user.UpdatePassword() because this
	// is not a password change, just encryption
	// change in the database
	if err := db.UpdateOnly(user, "encrypted_password"); err != nil {
		return apierrors.NewInternalServerError("Error updating password").WithInternalError(err)
	}

	// 6. 返回结果（REST 风格，仅返回 password_is_set:true）
	user.PasswordIsSet = true // 标记已设置密码
	response := map[string]bool{
		"password_is_set": user.PasswordIsSet,
	}

	return sendJSON(w, http.StatusOK, response)
}

// UserAuthInfo returns user authentication information including password status
func (a *API) UserAuthInfo(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := getClaims(ctx)
	if claims == nil {
		return apierrors.NewInternalServerError("Could not read claims")
	}

	aud := a.requestAud(ctx, r)
	audienceFromClaims, _ := claims.GetAudience()
	if len(audienceFromClaims) == 0 || aud != audienceFromClaims[0] {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Token audience doesn't match request audience")
	}

	user := getUser(ctx)

	response := map[string]interface{}{
		"has_password": user.HasPassword(),
		"email":        user.GetEmail(),
		"phone":        user.GetPhone(),
	}

	return sendJSON(w, http.StatusOK, response)
}

// UserUpdate updates fields on a user
func (a *API) UserUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	aud := a.requestAud(ctx, r)

	params := &UserUpdateParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	user := getUser(ctx)
	session := getSession(ctx)

	if err := a.validateUserUpdateParams(ctx, params); err != nil {
		return err
	}

	if params.AppData != nil && !isAdmin(user, config) {
		if !isAdmin(user, config) {
			return apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "Updating app_metadata requires admin privileges")
		}
	}

	if user.HasMFAEnabled() && !session.IsAAL2() {
		if (params.Password != nil && *params.Password != "") || (params.Email != "" && user.GetEmail() != params.Email) || (params.Phone != "" && user.GetPhone() != params.Phone) {
			return apierrors.NewHTTPError(http.StatusUnauthorized, apierrors.ErrorCodeInsufficientAAL, "AAL2 session is required to update email or password when MFA is enabled.")
		}
	}

	if user.IsAnonymous {
		if params.Password != nil && *params.Password != "" {
			if params.Email == "" && params.Phone == "" {
				return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeValidationFailed, "Updating password of an anonymous user without an email or phone is not allowed")
			}
		}
	}

	if user.IsSSOUser {
		updatingForbiddenFields := false

		updatingForbiddenFields = updatingForbiddenFields || (params.Password != nil && *params.Password != "")
		updatingForbiddenFields = updatingForbiddenFields || (params.Email != "" && params.Email != user.GetEmail())
		updatingForbiddenFields = updatingForbiddenFields || (params.Phone != "" && params.Phone != user.GetPhone())
		updatingForbiddenFields = updatingForbiddenFields || (params.Nonce != "")

		if updatingForbiddenFields {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeUserSSOManaged, "Updating email, phone, password of a SSO account only possible via SSO")
		}
	}

	if params.Email != "" && user.GetEmail() != params.Email {
		if duplicateUser, err := models.IsDuplicatedEmail(db, params.Email, aud, user); err != nil {
			return apierrors.NewInternalServerError("Database error checking email").WithInternalError(err)
		} else if duplicateUser != nil {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailExists, DuplicateEmailMsg)
		}
	}

	if params.Phone != "" && user.GetPhone() != params.Phone {
		if exists, err := models.IsDuplicatedPhone(db, params.Phone, aud); err != nil {
			return apierrors.NewInternalServerError("Database error checking phone").WithInternalError(err)
		} else if exists {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodePhoneExists, DuplicatePhoneMsg)
		}
	}

	if params.Password != nil {
		if config.Security.UpdatePasswordRequireReauthentication {
			now := time.Now()
			// we require reauthentication if the user hasn't signed in recently in the current session
			if session == nil || now.After(session.CreatedAt.Add(24*time.Hour)) {
				if len(params.Nonce) == 0 {
					return apierrors.NewBadRequestError(apierrors.ErrorCodeReauthenticationNeeded, "Password update requires reauthentication")
				}
				if err := a.verifyReauthentication(params.Nonce, db, config, user); err != nil {
					return err
				}
			}
		}

		password := *params.Password
		if password != "" {
			// 只有在用户主动设置过密码时才检查密码是否相同
			// 如果密码是系统自动生成的（OTP/magic link 登录），允许用户"重新设置"密码
			if user.HasPassword() && user.PasswordIsSet {
				isSamePassword, _, err := user.Authenticate(ctx, db, password, config.Security.DBEncryption.DecryptionKeys, false, "")
				if err != nil {
					return err
				}

				if isSamePassword {
					return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeSamePassword, "New password should be different from the old password.")
				}
			}
		}

		if err := user.SetPassword(ctx, password, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
			return err
		}
	}

	err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.Password != nil {
			var sessionID *uuid.UUID
			if session != nil {
				sessionID = &session.ID
			}

			if terr = user.UpdatePassword(tx, sessionID); terr != nil {
				return apierrors.NewInternalServerError("Error during password storage").WithInternalError(terr)
			}

			if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserUpdatePasswordAction, "", nil); terr != nil {
				return terr
			}
		}

		if params.Data != nil {
			if terr = user.UpdateUserMetaData(tx, params.Data); terr != nil {
				return apierrors.NewInternalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.AppData != nil {
			if terr = user.UpdateAppMetaData(tx, params.AppData); terr != nil {
				return apierrors.NewInternalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.Email != "" && params.Email != user.GetEmail() {
			if user.IsAnonymous && config.Mailer.Autoconfirm {
				// anonymous users can add an email with automatic confirmation, which is similar to signing up
				// permanent users always need to verify their email address when changing it
				user.EmailChange = params.Email
				if _, terr := a.emailChangeVerify(r, tx, &VerifyParams{
					Type:  mailer.EmailChangeVerification,
					Email: params.Email,
				}, user); terr != nil {
					return terr
				}

			} else {
				flowType := getFlowFromChallenge(params.CodeChallenge)
				if isPKCEFlow(flowType) {
					_, terr := generateFlowState(tx, models.EmailChange.String(), models.EmailChange, params.CodeChallengeMethod, params.CodeChallenge, &user.ID)
					if terr != nil {
						return terr
					}

				}
				if terr = a.sendEmailChange(r, tx, user, params.Email, flowType); terr != nil {
					return terr
				}
			}
		}

		if params.Phone != "" {
			logEntry := getLogEntry(r)
			logEntry.WithFields(logrus.Fields{
				"requestPhone": params.Phone,
				"currentPhone": user.GetPhone(),
				"autoconfirm":  config.Sms.Autoconfirm,
				"channel":      params.Channel,
			}).Info("📱 [UserUpdate] Phone update/verification request")
			
			// 允许给当前手机号发送验证码（用于身份验证）
			// 或者给新手机号发送验证码（用于换绑）
			if params.Phone == user.GetPhone() {
				// 给当前手机号发送验证码（身份验证场景）
				logEntry.Info("📱 [UserUpdate] Sending verification code to current phone")
				if _, terr := a.sendPhoneConfirmation(r, tx, user, params.Phone, phoneReauthenticationOtp, params.Channel); terr != nil {
					logEntry.WithError(terr).Error("📱 [UserUpdate] Failed to send verification code")
					return terr
				}
				logEntry.Info("📱 [UserUpdate] Verification code sent to current phone successfully")
			} else {
				// 给新手机号发送验证码（换绑场景）
				logEntry.Info("📱 [UserUpdate] Phone change detected - sending code to new phone")
				if config.Sms.Autoconfirm {
					logEntry.Info("📱 [UserUpdate] Using autoconfirm mode")
					user.PhoneChange = params.Phone
					if _, terr := a.smsVerify(r, tx, user, &VerifyParams{
						Type:  phoneChangeVerification,
						Phone: params.Phone,
					}); terr != nil {
						logEntry.WithError(terr).Error("📱 [UserUpdate] smsVerify failed")
						return terr
					}
					logEntry.Info("📱 [UserUpdate] Phone autoconfirmed successfully")
				} else {
					logEntry.Info("📱 [UserUpdate] Sending phone confirmation SMS to new phone")
					if _, terr := a.sendPhoneConfirmation(r, tx, user, params.Phone, phoneChangeVerification, params.Channel); terr != nil {
						logEntry.WithError(terr).Error("📱 [UserUpdate] sendPhoneConfirmation failed")
						return terr
					}
					logEntry.Info("📱 [UserUpdate] Phone confirmation SMS sent to new phone successfully")
				}
			}
		}

		if terr = models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserModifiedAction, "", nil); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
