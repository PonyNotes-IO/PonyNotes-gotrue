package models

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage/test"
)

const modelsTestConfig = "../../hack/test.env"

func TestSignInLogCreateAndQuery(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	defer conn.Close()

	// clean DB
	require.NoError(t, TruncateAll(conn))

	// create a user
	u, err := NewUser("", "test@example.com", "secret", "test", nil)
	require.NoError(t, err)
	require.NoError(t, conn.Create(u))

	// insert a sign in log
	log := &SignInLog{
		ID:        uuid.Must(uuid.NewV4()),
		UserUUID:  u.ID,
		Provider:  ptrString("email"),
		Success:   true,
		Metadata:  JSONMap{"foo": "bar"},
	}
	require.NoError(t, conn.Transaction(func(tx *storage.Connection) error {
		return CreateSignInLog(tx, log)
	}))

	// query logs
	logs, err := FindSignInLogsByUser(conn, u.ID, nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(logs), 1)
	require.Equal(t, logs[0].UserUUID, u.ID)
}

func ptrString(s string) *string { return &s }


