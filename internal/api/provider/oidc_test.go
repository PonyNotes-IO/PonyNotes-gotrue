package provider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

type realIDToken struct {
	AccessToken string
	IDToken     string
	Time        time.Time
	Email       string
	Verifier    func(context.Context, *oidc.Config) *oidc.IDTokenVerifier
}

func googleIDTokenVerifier(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
	keyBytes, err := base64.RawURLEncoding.DecodeString("")
	if err != nil {
		panic(err)
	}

	n := big.NewInt(0)
	n.SetBytes(keyBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	return oidc.NewVerifier(
		"https://accounts.google.com",
		&oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{publicKey},
		},
		config,
	)
}

func azureIDTokenVerifier(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
	keyBytes, err := base64.RawURLEncoding.DecodeString("")
	if err != nil {
		panic(err)
	}

	n := big.NewInt(0)
	n.SetBytes(keyBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	return oidc.NewVerifier(
		IssuerAzureMicrosoft,
		&oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{publicKey},
		},
		config,
	)
}

var realIDTokens map[string]realIDToken = map[string]realIDToken{
	IssuerGoogle: {
		AccessToken: "",
		Time:        time.Unix(1686659933, 0), // 1 sec after iat
		Verifier:    googleIDTokenVerifier,
	},
	IssuerAzureMicrosoft: {
		AccessToken: "access-token",
		Time:        time.Unix(1697277774, 0), // 1 sec after iat
		IDToken:     "",
		Verifier:    azureIDTokenVerifier,
	},
	IssuerVercelMarketplace: {
		AccessToken: "access-token",
		Time:        time.Unix(1744883141, 0), // 1 sec after iat
		IDToken:     "",
	},
}

func TestParseIDToken(t *testing.T) {
	defer func() {
		OverrideVerifiers = make(map[string]func(context.Context, *oidc.Config) *oidc.IDTokenVerifier)
		OverrideClock = nil
	}()

	// note that this test can fail if/when the issuers rotate their
	// signing keys (which happens rarely if ever)
	// then you should obtain new ID tokens and update this test
	for issuer, token := range realIDTokens {
		oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
		require.NoError(t, err)

		OverrideVerifiers[oidcProvider.Endpoint().AuthURL] = token.Verifier

		_, user, err := ParseIDToken(context.Background(), oidcProvider, &oidc.Config{
			SkipClientIDCheck: true,
			Now: func() time.Time {
				return token.Time
			},
		}, token.IDToken, ParseIDTokenOptions{
			AccessToken: token.AccessToken,
		})
		require.NoError(t, err)

		require.NotEmpty(t, user.Emails[0].Email)
		require.Equal(t, user.Emails[0].Verified, true)
	}
}

func TestAzureIDTokenClaimsIsEmailVerified(t *testing.T) {
	positiveExamples := []AzureIDTokenClaims{
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: nil,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: true,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "1",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "true",
		},
	}

	negativeExamples := []AzureIDTokenClaims{
		{
			Email:                              "",
			XMicrosoftEmailDomainOwnerVerified: true,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: false,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "0",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "false",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: float32(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: float64(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int32(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int64(0),
		},
	}

	for i, example := range positiveExamples {
		if !example.IsEmailVerified() {
			t.Errorf("positive example %v reports negative result", i)
		}
	}

	for i, example := range negativeExamples {
		if example.IsEmailVerified() {
			t.Errorf("negative example %v reports positive result", i)
		}
	}
}
