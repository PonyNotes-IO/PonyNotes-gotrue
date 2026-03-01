package api

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

var e164Format = regexp.MustCompile("^[1-9][0-9]{1,14}$")

const (
	phoneConfirmationOtp     = "confirmation"
	phoneReauthenticationOtp = "reauthentication"
)

func validatePhone(phone string) (string, error) {
	phone = formatPhoneNumber(phone)
	if isValid := validateE164Format(phone); !isValid {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid phone number format (E.164 required)")
	}
	return phone, nil
}

// validateE164Format checks if phone number follows the E.164 format
func validateE164Format(phone string) bool {
	return e164Format.MatchString(phone)
}

// formatPhoneNumber removes "+" and whitespaces in a phone number
func formatPhoneNumber(phone string) string {
	// 先去掉 + 前缀和空格
	phone = strings.ReplaceAll(strings.TrimPrefix(phone, "+"), " ", "")
	// 如果手机号以 86 开头且后面是 11 位数字，去掉 86 前缀（中国大陆手机号）
	// 中国大陆手机号格式：1开头，共11位
	if len(phone) >= 12 && strings.HasPrefix(phone, "86") {
		// 检查是否是有效的中国手机号（以1开头的11位数字）
		rest := phone[2:]
		if len(rest) == 11 && strings.HasPrefix(rest, "1") {
			return rest
		}
	}
	return phone
}

// sendPhoneConfirmation sends an otp to the user's phone number
func (a *API) sendPhoneConfirmation(r *http.Request, tx *storage.Connection, user *models.User, phone, otpType string, channel string) (string, error) {
	config := a.config
	
	logEntry := observability.GetLogEntry(r).Entry
	logEntry.WithFields(logrus.Fields{
		"phone":   phone,
		"otpType": otpType,
		"channel": channel,
		"userId":  user.ID,
	}).Info("[SEND_PHONE_CONFIRMATION] START - Sending phone confirmation")

	var token *string
	var sentAt *time.Time

	includeFields := []string{}
	switch otpType {
	case phoneChangeVerification:
		token = &user.PhoneChangeToken
		sentAt = user.PhoneChangeSentAt
		// 规范化手机号格式，确保存储和查询时的格式一致
		user.PhoneChange = formatPhoneNumber(phone)
		includeFields = append(includeFields, "phone_change", "phone_change_token", "phone_change_sent_at")
		logEntry.Info("[SEND_PHONE_CONFIRMATION] Type: phoneChangeVerification")
	case phoneConfirmationOtp:
		token = &user.ConfirmationToken
		sentAt = user.ConfirmationSentAt
		includeFields = append(includeFields, "confirmation_token", "confirmation_sent_at")
		logEntry.Info("[SEND_PHONE_CONFIRMATION] Type: phoneConfirmationOtp")
	case phoneReauthenticationOtp:
		token = &user.ReauthenticationToken
		sentAt = user.ReauthenticationSentAt
		includeFields = append(includeFields, "reauthentication_token", "reauthentication_sent_at")
		logEntry.Info("[SEND_PHONE_CONFIRMATION] Type: phoneReauthenticationOtp")
	default:
		return "", apierrors.NewInternalServerError("invalid otp type")
	}

	// intentionally keeping this before the test OTP, so that the behavior
	// of regular and test OTPs is similar
	if sentAt != nil && !sentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return "", apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverSMSSendRateLimit, generateFrequencyLimitErrorMessage(sentAt, config.Sms.MaxFrequency))
	}

	now := time.Now()

	var otp, messageID string

	if testOTP, ok := config.Sms.GetTestOTP(phone, now); ok {
		otp = testOTP
		messageID = "test-otp"
	}

	// not using test OTPs
	if otp == "" {
		logEntry.Info("📱 [sendPhoneConfirmation] Generating OTP...")
		// TODO(km): Deprecate this behaviour - rate limits should still be applied to autoconfirm
		if !config.Sms.Autoconfirm {
			// apply rate limiting before the sms is sent out
			if ok := a.limiterOpts.Phone.Allow(); !ok {
				return "", apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverSMSSendRateLimit, "SMS rate limit exceeded")
			}
		}
		otp = crypto.GenerateOtp(config.Sms.OtpLength)
		logEntry.WithField("otpLength", len(otp)).Info("📱 [sendPhoneConfirmation] OTP generated")

		if config.Hook.SendSMS.Enabled {
			logEntry.Info("📱 [sendPhoneConfirmation] Using SendSMS hook")
			input := v0hooks.SendSMSInput{
				User: user,
				SMS: v0hooks.SMS{
					OTP: otp,
				},
			}
			output := v0hooks.SendSMSOutput{}
			err := a.hooksMgr.InvokeHook(tx, r, &input, &output)
			if err != nil {
				logEntry.WithError(err).Error("📱 [sendPhoneConfirmation] Hook failed")
				return "", err
			}
			logEntry.Info("📱 [sendPhoneConfirmation] Hook succeeded")
		} else {
			logEntry.Info("📱 [sendPhoneConfirmation] Using SMS provider")
			smsProvider, err := sms_provider.GetSmsProvider(*config)
			if err != nil {
				logEntry.WithError(err).Error("📱 [sendPhoneConfirmation] Failed to get SMS provider")
				return "", apierrors.NewInternalServerError("Unable to get SMS provider").WithInternalError(err)
			}
			logEntry.Info("📱 [sendPhoneConfirmation] SMS provider obtained")
			message, err := generateSMSFromTemplate(config.Sms.SMSTemplate, otp)
			if err != nil {
				logEntry.WithError(err).Error("📱 [sendPhoneConfirmation] Failed to generate SMS template")
				return "", apierrors.NewInternalServerError("error generating sms template").WithInternalError(err)
			}
			logEntry.WithField("message", message).Info("📱 [sendPhoneConfirmation] Sending SMS...")
			messageID, err := smsProvider.SendMessage(phone, message, channel, otp)
			if err != nil {
				logEntry.WithError(err).Error("📱 [sendPhoneConfirmation] Failed to send SMS")
				return messageID, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeSMSSendFailed, "Error sending %s OTP to provider: %v", otpType, err)
			}
			logEntry.WithField("messageID", messageID).Info("📱 [sendPhoneConfirmation] SMS sent successfully!")
		}
	} else {
		logEntry.WithField("otp", otp).Info("📱 [sendPhoneConfirmation] Using test OTP")
	}

	*token = crypto.GenerateTokenHash(phone, otp)

	switch otpType {
	case phoneConfirmationOtp:
		user.ConfirmationSentAt = &now
	case phoneChangeVerification:
		user.PhoneChangeSentAt = &now
	case phoneReauthenticationOtp:
		user.ReauthenticationSentAt = &now
	}

	if err := tx.UpdateOnly(user, includeFields...); err != nil {
		return messageID, errors.Wrap(err, "Database error updating user for phone")
	}

	var ottErr error
	switch otpType {
	case phoneConfirmationOtp:
		if err := models.CreateOneTimeToken(tx, user.ID, user.GetPhone(), user.ConfirmationToken, models.ConfirmationToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating confirmation token for phone")
		}
	case phoneChangeVerification:
		if err := models.CreateOneTimeToken(tx, user.ID, user.PhoneChange, user.PhoneChangeToken, models.PhoneChangeToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating phone change token")
		}
	case phoneReauthenticationOtp:
		if err := models.CreateOneTimeToken(tx, user.ID, user.GetPhone(), user.ReauthenticationToken, models.ReauthenticationToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating reauthentication token for phone")
		}
	}
	if ottErr != nil {
		return messageID, apierrors.NewInternalServerError("error creating one time token").WithInternalError(ottErr)
	}
	return messageID, nil
}

func generateSMSFromTemplate(SMSTemplate *template.Template, otp string) (string, error) {
	var message bytes.Buffer
	if err := SMSTemplate.Execute(&message, struct {
		Code string
	}{Code: otp}); err != nil {
		return "", err
	}
	return message.String(), nil
}
