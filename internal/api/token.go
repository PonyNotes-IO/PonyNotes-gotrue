package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sethvargo/go-password/password"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// AccessTokenClaims is a struct thats used for JWT claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Email                         string                 `json:"email"`
	Phone                         string                 `json:"phone"`
	AppMetaData                   map[string]interface{} `json:"app_metadata"`
	UserMetaData                  map[string]interface{} `json:"user_metadata"`
	Role                          string                 `json:"role"`
	AuthenticatorAssuranceLevel   string                 `json:"aal,omitempty"`
	AuthenticationMethodReference []models.AMREntry      `json:"amr,omitempty"`
	SessionId                     string                 `json:"session_id,omitempty"`
	IsAnonymous                   bool                   `json:"is_anonymous"`
	// TODO(cemalkilic) : client_id claim will be added later
	// ClientId                      string                 `json:"client_id,omitempty"`
}

// AccessTokenResponse represents an OAuth2 success response
type AccessTokenResponse struct {
	Token                string             `json:"access_token"`
	TokenType            string             `json:"token_type"` // Bearer
	ExpiresIn            int                `json:"expires_in"`
	ExpiresAt            int64              `json:"expires_at"`
	RefreshToken         string             `json:"refresh_token"`
	User                 *models.User       `json:"user"`
	ProviderAccessToken  string             `json:"provider_token,omitempty"`
	ProviderRefreshToken string             `json:"provider_refresh_token,omitempty"`
	WeakPassword         *WeakPasswordError `json:"weak_password,omitempty"`
}

// AsRedirectURL encodes the AccessTokenResponse as a redirect URL that
// includes the access token response data in a URL fragment.
func (r *AccessTokenResponse) AsRedirectURL(redirectURL string, extraParams url.Values) string {
	extraParams.Set("access_token", r.Token)
	extraParams.Set("token_type", r.TokenType)
	extraParams.Set("expires_in", strconv.Itoa(r.ExpiresIn))
	extraParams.Set("expires_at", strconv.FormatInt(r.ExpiresAt, 10))
	extraParams.Set("refresh_token", r.RefreshToken)

	return redirectURL + "#" + extraParams.Encode()
}

// PasswordGrantParams are the parameters the ResourceOwnerPasswordGrant method accepts
type PasswordGrantParams struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type ThirdPartyParams struct {
	Platform string `json:"platform"`
	Code     string `json:"code"`
}

// PKCEGrantParams are the parameters the PKCEGrant method accepts
type PKCEGrantParams struct {
	AuthCode     string `json:"auth_code"`
	CodeVerifier string `json:"code_verifier"`
}

const useCookieHeader = "x-use-cookie"
const InvalidLoginMessage = "Invalid login credentials"

// Token is the endpoint for OAuth access token requests
func (a *API) Token(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	grantType := r.FormValue("grant_type")

	handler := a.ResourceOwnerPasswordGrant
	limiter := a.limiterOpts.Token

	switch grantType {
	case "password":
		// set above
		return a.ResourceOwnerPasswordGrant(ctx, w, r)
	case "refresh_token":
		handler = a.RefreshTokenGrant
	case "id_token":
		handler = a.IdTokenGrant
	case "pkce":
		handler = a.PKCE
	case "web3":
		handler = a.Web3Grant
		limiter = a.limiterOpts.Web3
	case "third_party":
		handler = a.ThirdPartyGrant
	default:
		return apierrors.NewBadRequestError(apierrors.ErrorCodeInvalidCredentials, "unsupported_grant_type")
	}

	if err := a.performRateLimiting(limiter, r); err != nil {
		return err
	}

	return handler(ctx, w, r)
}

// ResourceOwnerPasswordGrant implements the password grant type flow
func (a *API) ResourceOwnerPasswordGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)

	params := &PasswordGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	config := a.config

	if params.Email != "" && params.Phone != "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Only an email address or phone number should be provided on login.")
	}
	var user *models.User
	var grantParams models.GrantParams
	var provider string
	var err error

	grantParams.FillGrantParams(r)

	if params.Email != "" {
		provider = "email"
		if !config.External.Email.Enabled {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailProviderDisabled, "Email logins are disabled")
		}
		user, err = models.FindUserByEmailAndAudience(db, params.Email, aud)
	} else if params.Phone != "" {
		provider = "phone"
		if !config.External.Phone.Enabled {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodePhoneProviderDisabled, "Phone logins are disabled")
		}
		params.Phone = formatPhoneNumber(params.Phone)
		user, err = models.FindUserByPhoneAndAudience(db, params.Phone, aud)
	} else {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "missing email or phone")
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			// record failed password login (user not found)
			go func() {
				_ = a.recordSignInEvent(ctx, r, uuid.Nil, metering.LoginTypePassword, &metering.LoginData{Provider: provider}, false, "user_not_found")
			}()
			return apierrors.NewBadRequestError(apierrors.ErrorCodeInvalidCredentials, InvalidLoginMessage)
		}
		return apierrors.NewInternalServerError("Database error querying schema").WithInternalError(err)
	}

	if !user.HasPassword() {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeInvalidCredentials, InvalidLoginMessage)
	}

	if !user.PasswordIsSet {
		return apierrors.NewBadRequestError(apierrors.ErrorCodePasswordNotSet, "User has not set a password")
	}

	if user.IsBanned() {
		// record banned login attempt
		go func() {
			_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePassword, &metering.LoginData{Provider: provider}, false, "user_banned")
		}()
		return apierrors.NewBadRequestError(apierrors.ErrorCodeUserBanned, "User is banned")
	}

	isValidPassword, shouldReEncrypt, err := user.Authenticate(ctx, db, params.Password, config.Security.DBEncryption.DecryptionKeys, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID)
	if err != nil {
		return err
	}

	var weakPasswordError *WeakPasswordError
	if isValidPassword {
		if err := a.checkPasswordStrength(ctx, params.Password); err != nil {
			if wpe, ok := err.(*WeakPasswordError); ok {
				weakPasswordError = wpe
			} else {
				observability.GetLogEntry(r).Entry.WithError(err).Warn("Password strength check on sign-in failed")
			}
		}

		if shouldReEncrypt {
			if err := user.SetPassword(ctx, params.Password, true, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
				return err
			}

			// directly change this in the database without
			// calling user.UpdatePassword() because this
			// is not a password change, just encryption
			// change in the database
			if err := db.UpdateOnly(user, "encrypted_password"); err != nil {
				return err
			}
		}
	}

	if config.Hook.PasswordVerificationAttempt.Enabled {
		input := v0hooks.PasswordVerificationAttemptInput{
			UserID: user.ID,
			Valid:  isValidPassword,
		}
		output := v0hooks.PasswordVerificationAttemptOutput{}
		if err := a.hooksMgr.InvokeHook(nil, r, &input, &output); err != nil {
			return err
		}

		if output.Decision == v0hooks.HookRejection {
			if output.Message == "" {
				output.Message = v0hooks.DefaultPasswordHookRejectionMessage
			}
			if output.ShouldLogoutUser {
				if err := models.Logout(a.db, user.ID); err != nil {
					return err
				}
			}
			// record hook rejection as failed sign-in
			go func() {
				_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePassword, &metering.LoginData{Provider: provider, Extra: map[string]interface{}{"hook_message": output.Message}}, false, "hook_rejection")
			}()
			return apierrors.NewBadRequestError(apierrors.ErrorCodeInvalidCredentials, output.Message)
		}
	}
	if !isValidPassword {
		// record failed password attempt
		go func() {
			_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePassword, &metering.LoginData{Provider: provider}, false, "invalid_password")
		}()
		return apierrors.NewBadRequestError(apierrors.ErrorCodeInvalidCredentials, InvalidLoginMessage)
	}

	if params.Email != "" && !user.IsConfirmed() {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeEmailNotConfirmed, "Email not confirmed")
	} else if params.Phone != "" && !user.IsPhoneConfirmed() {
		return apierrors.NewBadRequestError(apierrors.ErrorCodePhoneNotConfirmed, "Phone not confirmed")
	}

	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": provider,
		}); terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(r, tx, user, models.PasswordGrant, grantParams)
		if terr != nil {
			return terr
		}

		return nil
	})
	if err != nil {
		return err
	}

	token.WeakPassword = weakPasswordError

	metering.RecordLogin(metering.LoginTypePassword, user.ID, &metering.LoginData{
		Provider: provider,
	})
	// persist structured sign-in log asynchronously
	go func() {
		_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePassword, &metering.LoginData{Provider: provider}, true, "")
	}()
	return sendJSON(w, http.StatusOK, token)
}

func (a *API) ThirdPartyGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)

	params := &ThirdPartyParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	config := a.config

	//var user *models.User
	var grantParams models.GrantParams
	var err error
	var user *models.User

	grantParams.FillGrantParams(r)

	provider, err := a.ThirdPartyProviderProvider(params.Code, params.Platform)
	if err != nil {
		// record third-party provider creation error
		go func() {
			_ = a.recordSignInEvent(ctx, r, uuid.Nil, metering.LoginTypeOAuth, &metering.LoginData{Provider: params.Platform, Extra: map[string]interface{}{"error": err.Error()}}, false, "third_party_provider_error")
		}()
		return err
	}

	providerId := provider.GetProviderId()
	if providerId == nil || strings.TrimSpace(*providerId) == "" {
		return apierrors.NewInternalServerError("Third party provider id is missing").WithInternalError(errors.New("empty provider id from third party provider"))
	}
	providerIdValue := strings.TrimSpace(*providerId)

	identity, err := models.FindIdentityByIdAndProvider(a.db, providerIdValue, params.Platform)
	if err != nil {
		// 如果没找到就是没号
		if models.IsNotFoundError(err) {
			userMeta, err := provider.GetUserMeta()
			if err != nil {
				return err
			}
			// Satisfy NewIdentity requirement: ensure provider id exists as "sub"
			if _, ok := userMeta["sub"]; !ok {
				userMeta["sub"] = providerIdValue
			}
			newPassword, err := password.Generate(64, 10, 1, false, true)
			if err != nil {
				return apierrors.NewInternalServerError("Error generating password").WithInternalError(err)
			}
			user, err = models.NewUser("", "", newPassword, aud, nil)
			if err != nil {
				if errors.Is(err, bcrypt.ErrPasswordTooLong) {
					return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
				}
				return apierrors.NewInternalServerError("Error creating user").WithInternalError(err)
			}
			user.IsSSOUser = true
			user.UserMetaData = userMeta
			user.PasswordIsSet = false

			identity, err := models.NewIdentity(user, params.Platform, userMeta)
			if err != nil {
				return apierrors.NewInternalServerError("new identity fail.").WithInternalError(err)
			}
			err = a.db.Transaction(func(tx *storage.Connection) error {
				// 使用 Create 而不是 Save，确保正确创建新记录
				if terr := tx.Create(user); terr != nil {
					return apierrors.NewInternalServerError("Database error saving new user").WithInternalError(terr)
				}
				// 设置用户角色
				if terr := user.SetRole(tx, config.JWT.DefaultGroupName); terr != nil {
					return apierrors.NewInternalServerError("Database error updating user role").WithInternalError(terr)
				}
				// 创建 identity
				if terr := tx.Create(identity); terr != nil {
					return apierrors.NewInternalServerError("Error creating identity").WithInternalError(terr)
				}
				return nil
			})
			if err != nil {
				return apierrors.NewInternalServerError("Database operation failed during account creation.").WithInternalError(err)
			}
		} else {
			// 报错了
			return apierrors.NewInternalServerError("Database error querying schema").WithInternalError(err)
		}
	} else {
		// 有号
		user, err = models.FindUserByID(a.db, identity.UserID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewInternalServerError("Incomplete account data; no corresponding user found.").WithInternalError(err)

			}
			return apierrors.NewInternalServerError("Database error querying schema").WithInternalError(err)
		}
	}

	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": params.Platform,
		}); terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(r, tx, user, models.PasswordGrant, grantParams)
		if terr != nil {
			return terr
		}

		return nil
	})
	if err != nil {
		return err
	}

	metering.RecordLogin(metering.LoginTypePassword, user.ID, &metering.LoginData{
		Provider: params.Platform,
	})
	// persist structured sign-in log asynchronously
	go func() {
		_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePassword, &metering.LoginData{Provider: params.Platform}, true, "")
	}()
	return sendJSON(w, http.StatusOK, token)
}

func (a *API) PKCE(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)
	config := a.config
	var grantParams models.GrantParams

	// There is a slight problem with this as it will pick-up the
	// User-Agent and IP addresses from the server if used on the server
	// side. Currently there's no mechanism to distinguish, but the server
	// can be told to at least propagate the User-Agent header.
	grantParams.FillGrantParams(r)

	params := &PKCEGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.AuthCode == "" || params.CodeVerifier == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "invalid request: both auth code and code verifier should be non-empty")
	}

	flowState, err := models.FindFlowStateByAuthCode(db, params.AuthCode)
	// Sanity check in case user ID was not set properly
	if models.IsNotFoundError(err) || flowState.UserID == nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeFlowStateNotFound, "invalid flow state, no valid flow state found")
	} else if err != nil {
		return err
	}
	if flowState.IsExpired(a.config.External.FlowStateExpiryDuration) {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeFlowStateExpired, "invalid flow state, flow state has expired")
	}

	user, err := models.FindUserByID(db, *flowState.UserID)
	if err != nil {
		return err
	}
	if err := flowState.VerifyPKCE(params.CodeVerifier); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadCodeVerifier, err.Error())
	}

	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		authMethod, err := models.ParseAuthenticationMethod(flowState.AuthenticationMethod)
		if err != nil {
			return err
		}
		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider_type": flowState.ProviderType,
		}); terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(r, tx, user, authMethod, grantParams)
		if terr != nil {
			// error type is already handled in issueRefreshToken
			return terr
		}
		token.ProviderAccessToken = flowState.ProviderAccessToken
		// Because not all providers give out a refresh token
		// See corresponding OAuth2 spec: <https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1>
		if flowState.ProviderRefreshToken != "" {
			token.ProviderRefreshToken = flowState.ProviderRefreshToken
		}
		if terr = tx.Destroy(flowState); terr != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	metering.RecordLogin(metering.LoginTypePKCE, user.ID, &metering.LoginData{
		Provider: flowState.ProviderType,
	})
	// persist structured sign-in log asynchronously
	go func() {
		_ = a.recordSignInEvent(ctx, r, user.ID, metering.LoginTypePKCE, &metering.LoginData{Provider: flowState.ProviderType}, true, "")
	}()
	return sendJSON(w, http.StatusOK, token)
}

func (a *API) generateAccessToken(r *http.Request, tx *storage.Connection, user *models.User, sessionId *uuid.UUID, authenticationMethod models.AuthenticationMethod) (string, int64, error) {
	config := a.config
	if sessionId == nil {
		return "", 0, apierrors.NewInternalServerError("Session is required to issue access token")
	}
	sid := sessionId.String()
	session, terr := models.FindSessionByID(tx, *sessionId, false)
	if terr != nil {
		return "", 0, terr
	}
	aal, amr, terr := session.CalculateAALAndAMR(user)
	if terr != nil {
		return "", 0, terr
	}

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Second * time.Duration(config.JWT.Exp))

	claims := &v0hooks.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{user.Aud},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    config.JWT.Issuer,
		},
		Email:                         user.GetEmail(),
		Phone:                         user.GetPhone(),
		AppMetaData:                   user.AppMetaData,
		UserMetaData:                  user.UserMetaData,
		Role:                          user.Role,
		SessionId:                     sid,
		AuthenticatorAssuranceLevel:   aal.String(),
		AuthenticationMethodReference: amr,
		IsAnonymous:                   user.IsAnonymous,
	}

	var gotrueClaims jwt.Claims = claims
	if config.Hook.CustomAccessToken.Enabled {
		input := v0hooks.CustomAccessTokenInput{
			UserID:               user.ID,
			Claims:               claims,
			AuthenticationMethod: authenticationMethod.String(),
		}

		output := v0hooks.CustomAccessTokenOutput{}

		err := a.hooksMgr.InvokeHook(tx, r, &input, &output)
		if err != nil {
			return "", 0, err
		}
		if err := validateTokenClaims(output.Claims); err != nil {
			return "", 0, err
		}
		gotrueClaims = jwt.MapClaims(output.Claims)
	}

	signed, err := signJwt(&config.JWT, gotrueClaims)
	if err != nil {
		return "", 0, err
	}
	return signed, expiresAt.Unix(), nil
}

func (a *API) issueRefreshToken(r *http.Request, conn *storage.Connection, user *models.User, authenticationMethod models.AuthenticationMethod, grantParams models.GrantParams) (*AccessTokenResponse, error) {
	config := a.config

	now := time.Now()
	user.LastSignInAt = &now

	var tokenString string
	var expiresAt int64
	var refreshToken *models.RefreshToken

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error

		refreshToken, terr = models.GrantAuthenticatedUser(tx, user, grantParams)
		if terr != nil {
			return apierrors.NewInternalServerError("Database error granting user").WithInternalError(terr)
		}

		terr = models.AddClaimToSession(tx, *refreshToken.SessionId, authenticationMethod)
		if terr != nil {
			return terr
		}

		tokenString, expiresAt, terr = a.generateAccessToken(r, tx, user, refreshToken.SessionId, authenticationMethod)
		if terr != nil {
			// Account for Hook Error
			httpErr, ok := terr.(*HTTPError)
			if ok {
				return httpErr
			}
			return apierrors.NewInternalServerError("error generating jwt token").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &AccessTokenResponse{
		Token:        tokenString,
		TokenType:    "bearer",
		ExpiresIn:    config.JWT.Exp,
		ExpiresAt:    expiresAt,
		RefreshToken: refreshToken.Token,
		User:         user,
	}, nil
}

func (a *API) updateMFASessionAndClaims(r *http.Request, tx *storage.Connection, user *models.User, authenticationMethod models.AuthenticationMethod, grantParams models.GrantParams) (*AccessTokenResponse, error) {
	ctx := r.Context()
	config := a.config
	var tokenString string
	var expiresAt int64
	var refreshToken *models.RefreshToken
	currentClaims := getClaims(ctx)
	sessionId, err := uuid.FromString(currentClaims.SessionId)
	if err != nil {
		return nil, apierrors.NewInternalServerError("Cannot read SessionId claim as UUID").WithInternalError(err)
	}

	err = tx.Transaction(func(tx *storage.Connection) error {
		if terr := models.AddClaimToSession(tx, sessionId, authenticationMethod); terr != nil {
			return terr
		}
		session, terr := models.FindSessionByID(tx, sessionId, false)
		if terr != nil {
			return terr
		}
		currentToken, terr := models.FindTokenBySessionID(tx, &session.ID)
		if terr != nil {
			return terr
		}
		if err := tx.Load(user, "Identities"); err != nil {
			return err
		}
		// Swap to ensure current token is the latest one
		refreshToken, terr = models.GrantRefreshTokenSwap(config.AuditLog, r, tx, user, currentToken)
		if terr != nil {
			return terr
		}
		aal, _, terr := session.CalculateAALAndAMR(user)
		if terr != nil {
			return terr
		}

		if err := session.UpdateAALAndAssociatedFactor(tx, aal, grantParams.FactorID); err != nil {
			return err
		}

		tokenString, expiresAt, terr = a.generateAccessToken(r, tx, user, &session.ID, authenticationMethod)
		if terr != nil {
			httpErr, ok := terr.(*HTTPError)
			if ok {
				return httpErr
			}
			return apierrors.NewInternalServerError("error generating jwt token").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &AccessTokenResponse{
		Token:        tokenString,
		TokenType:    "bearer",
		ExpiresIn:    config.JWT.Exp,
		ExpiresAt:    expiresAt,
		RefreshToken: refreshToken.Token,
		User:         user,
	}, nil
}

var schemaLoader = gojsonschema.NewStringLoader(MinimumViableTokenSchema)

func validateTokenClaims(outputClaims map[string]interface{}) error {
	documentLoader := gojsonschema.NewGoLoader(outputClaims)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}

	if !result.Valid() {
		var errorMessages string

		for _, desc := range result.Errors() {
			errorMessages += fmt.Sprintf("- %s\n", desc)
		}
		err = fmt.Errorf(
			"output claims do not conform to the expected schema: \n%s", errorMessages)
	}
	if err != nil {
		httpError := &apierrors.HTTPError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		return httpError
	}
	return nil
}

// #nosec
const MinimumViableTokenSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "aud": {
      "type": ["string", "array"]
    },
    "exp": {
      "type": "integer"
    },
    "jti": {
      "type": "string"
    },
    "iat": {
      "type": "integer"
    },
    "iss": {
      "type": "string"
    },
    "nbf": {
      "type": "integer"
    },
    "sub": {
      "type": "string"
    },
    "email": {
      "type": "string"
    },
    "phone": {
      "type": "string"
    },
    "app_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "user_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "role": {
      "type": "string"
    },
    "aal": {
      "type": "string"
    },
    "amr": {
      "type": "array",
      "items": {
        "type": "object"
      }
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": ["aud", "exp", "iat", "sub", "email", "phone", "role", "aal", "session_id", "is_anonymous"]
}`
