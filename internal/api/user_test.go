package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
)

type UserTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestUser(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &UserTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *UserTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("123456789", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *UserTestSuite) generateToken(user *models.User, sessionId *uuid.UUID) string {
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, sessionId, models.PasswordGrant)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *UserTestSuite) generateAccessTokenAndSession(user *models.User) string {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *UserTestSuite) TestUserGet() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error finding user")
	token := ts.generateAccessTokenAndSession(u)

	require.NoError(ts.T(), err, "Error generating access token")

	req := httptest.NewRequest(http.MethodGet, "http://localhost/user", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	// 打印响应 body 内容
	fmt.Println("Response Body:", w.Body.String())
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *UserTestSuite) TestUserUpdateEmail() {
	cases := []struct {
		desc                       string
		userData                   map[string]interface{}
		isSecureEmailChangeEnabled bool
		isMailerAutoconfirmEnabled bool
		expectedCode               int
	}{
		{
			desc: "User doesn't have an existing email",
			userData: map[string]interface{}{
				"email": "",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User doesn't have an existing email and double email confirmation required",
			userData: map[string]interface{}{
				"email": "",
				"phone": "234567890",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email",
			userData: map[string]interface{}{
				"email": "foo@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email and double email confirmation required",
			userData: map[string]interface{}{
				"email": "bar@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "Update email with mailer autoconfirm enabled",
			userData: map[string]interface{}{
				"email": "bar@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: true,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "Update email with mailer autoconfirm enabled and anonymous user",
			userData: map[string]interface{}{
				"email":        "bar@example.com",
				"phone":        "",
				"is_anonymous": true,
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: true,
			expectedCode:               http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			u, err := models.NewUser("", "", "", ts.Config.JWT.Aud, nil)
			require.NoError(ts.T(), err, "Error creating test user model")
			require.NoError(ts.T(), u.SetEmail(ts.API.db, c.userData["email"].(string)), "Error setting user email")
			require.NoError(ts.T(), u.SetPhone(ts.API.db, c.userData["phone"].(string)), "Error setting user phone")
			if isAnonymous, ok := c.userData["is_anonymous"]; ok {
				u.IsAnonymous = isAnonymous.(bool)
			}
			require.NoError(ts.T(), ts.API.db.Create(u), "Error saving test user")

			token := ts.generateAccessTokenAndSession(u)

			require.NoError(ts.T(), err, "Error generating access token")

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"email": "new@example.com",
			}))
			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.Config.Mailer.SecureEmailChangeEnabled = c.isSecureEmailChangeEnabled
			ts.Config.Mailer.Autoconfirm = c.isMailerAutoconfirmEnabled
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)

			var data models.User
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			if c.isMailerAutoconfirmEnabled && u.IsAnonymous {
				require.Empty(ts.T(), data.EmailChange)
				require.Equal(ts.T(), "new@example.com", data.GetEmail())
				require.Len(ts.T(), data.Identities, 1)
			} else {
				require.Equal(ts.T(), "new@example.com", data.EmailChange)
				require.Len(ts.T(), data.Identities, 0)
			}

			// remove user after each case
			require.NoError(ts.T(), ts.API.db.Destroy(u))
		})
	}

}
func (ts *UserTestSuite) TestUserUpdatePhoneAutoconfirmEnabled() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	existingUser, err := models.NewUser("22222222", "", "", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(existingUser))

	cases := []struct {
		desc         string
		userData     map[string]string
		expectedCode int
	}{
		{
			desc: "New phone number is the same as current phone number",
			userData: map[string]string{
				"phone": "123456789",
			},
			expectedCode: http.StatusOK,
		},
		{
			desc: "New phone number exists already",
			userData: map[string]string{
				"phone": "22222222",
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			desc: "New phone number is different from current phone number",
			userData: map[string]string{
				"phone": "234567890",
			},
			expectedCode: http.StatusOK,
		},
	}

	ts.Config.Sms.Autoconfirm = true

	for _, c := range cases {
		ts.Run(c.desc, func() {
			token := ts.generateAccessTokenAndSession(u)
			require.NoError(ts.T(), err, "Error generating access token")

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"phone": c.userData["phone"],
			}))
			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)

			if c.expectedCode == http.StatusOK {
				// check that the user response returned contains the updated phone field
				data := &models.User{}
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
				require.Equal(ts.T(), data.GetPhone(), c.userData["phone"])
			}
		})
	}

}

func (ts *UserTestSuite) TestUserUpdatePassword() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	r, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)

	r2, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)

	// create a session and modify it's created_at time to simulate a session that is not recently logged in
	notRecentlyLoggedIn, err := models.FindSessionByID(ts.API.db, *r2.SessionId, true)
	require.NoError(ts.T(), err)

	// cannot use Update here because Update doesn't removes the created_at field
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"update "+notRecentlyLoggedIn.TableName()+" set created_at = ? where id = ?",
		time.Now().Add(-24*time.Hour),
		notRecentlyLoggedIn.ID).Exec(),
	)

	type expected struct {
		code            int
		isAuthenticated bool
	}

	var cases = []struct {
		desc                    string
		newPassword             string
		nonce                   string
		requireReauthentication bool
		sessionId               *uuid.UUID
		expected                expected
	}{
		{
			desc:                    "Need reauthentication because outside of recently logged in window",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: true,
			sessionId:               &notRecentlyLoggedIn.ID,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
		{
			desc:                    "No nonce provided",
			newPassword:             "newpassword123",
			nonce:                   "",
			sessionId:               &notRecentlyLoggedIn.ID,
			requireReauthentication: true,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
		{
			desc:                    "Invalid nonce",
			newPassword:             "newpassword1234",
			nonce:                   "123456",
			sessionId:               &notRecentlyLoggedIn.ID,
			requireReauthentication: true,
			expected:                expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
		},
		{
			desc:                    "No need reauthentication because recently logged in",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: true,
			sessionId:               r.SessionId,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"password": c.newPassword, "nonce": c.nonce}))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			token := ts.generateToken(u, c.sessionId)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Request body
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, c.newPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, isAuthenticated)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordNoReauthenticationRequired() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	type expected struct {
		code            int
		isAuthenticated bool
	}

	var cases = []struct {
		desc                    string
		newPassword             string
		nonce                   string
		requireReauthentication bool
		expected                expected
	}{
		{
			desc:                    "Invalid password length",
			newPassword:             "",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
		},

		{
			desc:                    "Valid password length",
			newPassword:             "newpassword",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"password": c.newPassword, "nonce": c.nonce}))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			token := ts.generateAccessTokenAndSession(u)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Request body
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, c.newPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, isAuthenticated)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordReauthentication() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = true

	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Confirm the test user
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	token := ts.generateAccessTokenAndSession(u)

	// request for reauthentication nonce
	req := httptest.NewRequest(http.MethodGet, "http://localhost/reauthenticate", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), u.ReauthenticationToken)
	require.NotEmpty(ts.T(), u.ReauthenticationSentAt)

	// update reauthentication token to a known token
	u.ReauthenticationToken = crypto.GenerateTokenHash(u.GetEmail(), "123456")
	require.NoError(ts.T(), ts.API.db.Update(u))

	// update password with reauthentication token
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"password": "newpass",
		"nonce":    "123456",
	}))

	req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	// Request body
	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, "newpass", ts.Config.Security.DBEncryption.DecryptionKeys, ts.Config.Security.DBEncryption.Encrypt, ts.Config.Security.DBEncryption.EncryptionKeyID)
	require.NoError(ts.T(), err)

	require.True(ts.T(), isAuthenticated)
	require.Empty(ts.T(), u.ReauthenticationToken)
	require.Nil(ts.T(), u.ReauthenticationSentAt)
}

func (ts *UserTestSuite) TestUserUpdatePasswordLogoutOtherSessions() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = false
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Confirm the test user
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	// Login the test user to get first session
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	session1 := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&session1))

	// Login test user to get second session
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))
	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	session2 := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&session2))

	// Update user's password using first session
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"password": "newpass",
	}))

	req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session1.Token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Attempt to refresh session1 should pass
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": session1.RefreshToken,
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Attempt to refresh session2 should fail
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": session2.RefreshToken,
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.NotEqual(ts.T(), http.StatusOK, w.Code)
}

func (ts *UserTestSuite) TestPasswordIsSetEndpoint() {
	type testCase struct {
		name           string
		email          string
		phone          string
		expectedStatus int
		expectedBody   string // 可以部分匹配 password_is_set 值
	}

	// 填写符合要求的测试账号
	existingEmailWithPassword := "test@example.com"
	existingEmailNoPassword := "test@example.com"
	existingPhoneWithPassword := "+1234567890"
	existingPhoneNoPassword := "+1987654321"
	nonExistingEmail := "not_exist@example.com"
	nonExistingPhone := "+1000000000"

	testCases := []testCase{
		{
			name:           "email exists and password is set",
			email:          existingEmailWithPassword,
			phone:          "",
			expectedStatus: http.StatusOK,
			expectedBody:   `"password_is_set":true`,
		},
		{
			name:           "email exists and password is not set",
			email:          existingEmailNoPassword,
			phone:          "",
			expectedStatus: http.StatusOK,
			expectedBody:   `"password_is_set":false`,
		},
		{
			name:           "phone exists and password is set",
			email:          "",
			phone:          existingPhoneWithPassword,
			expectedStatus: http.StatusOK,
			expectedBody:   `"password_is_set":true`,
		},
		{
			name:           "phone exists and password is not set",
			email:          "",
			phone:          existingPhoneNoPassword,
			expectedStatus: http.StatusOK,
			expectedBody:   `"password_is_set":false`,
		},
		{
			name:           "email and phone both empty",
			email:          "",
			phone:          "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Either email or phone must be provided",
		},
		{
			name:           "email and phone both provided",
			email:          existingEmailWithPassword,
			phone:          existingPhoneWithPassword,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Only provide either email or phone, not both",
		},
		{
			name:           "non-existing email",
			email:          nonExistingEmail,
			phone:          "",
			expectedStatus: http.StatusNotFound,
			expectedBody:   "User not found",
		},
		{
			name:           "non-existing phone",
			email:          "",
			phone:          nonExistingPhone,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "User not found",
		},
	}

	for _, tc := range testCases {
		ts.T().Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/user/password/status", nil)

			// 构造 query 参数
			q := req.URL.Query()
			if tc.email != "" {
				q.Add("email", tc.email)
			}
			if tc.phone != "" {
				q.Add("phone", tc.phone)
			}
			req.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()
			err := ts.API.PasswordIsSet(w, req)
			require.NoError(t, err, "Handler returned unexpected error")
			require.Equal(t, tc.expectedStatus, w.Code, "Status code mismatch")

			body := w.Body.String()
			require.Contains(t, body, tc.expectedBody, "Response body mismatch")
			// 打印响应方便调试
			fmt.Printf("[%s] Response Body: %s\n", tc.name, body)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePassword1() {
	// 准备用户
	userEmail := "test@example.com"
	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error finding user")

	token := ts.generateAccessTokenAndSession(user)
	require.NoError(ts.T(), err, "Error generating access token")

	// 新密码
	newPassword := "123456"

	reqBody := fmt.Sprintf(`{"password":"%s"}`, newPassword)
	req := httptest.NewRequest(http.MethodPut, "http://localhost:8081/user", strings.NewReader(reqBody))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code, "Expected 200 OK response")

	// 打印响应体，调试用
	fmt.Println("Response Body:", w.Body.String())

	// 可选：验证数据库中密码是否被修改
	dbUser, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), dbUser.HasPassword(), "User should have password set")
	require.True(ts.T(), dbUser.PasswordIsSet, "PasswordIsSet should be true")
}
