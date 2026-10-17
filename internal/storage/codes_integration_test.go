//go:build integration

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

func TestCodes_HashedAtRest(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}

	// --- device_code / user_code ---
	if err := s.StoreDeviceAuthorization(ctx, "test-client", "dev-code-1", "USERCODE1", s.clock.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("store device auth: %v", err)
	}
	dc, err := s.GetDeviceCodeByUserCode(ctx, "USERCODE1")
	if err != nil {
		t.Fatalf("lookup by user_code: %v", err)
	}
	if dc.UserCode != "USERCODE1" {
		t.Errorf("returned UserCode=%q, want plaintext input", dc.UserCode)
	}
	if _, err := s.GetDeviceCodeByUserCode(ctx, "WRONG-CODE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong user_code err=%v, want ErrNotFound", err)
	}

	var storedUC, storedDC string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT user_code, device_code FROM device_codes WHERE client_id='test-client'`,
	).Scan(&storedUC, &storedDC); err != nil {
		t.Fatalf("read device row: %v", err)
	}
	if storedUC == "USERCODE1" || storedDC == "dev-code-1" {
		t.Error("device/user code stored in plaintext")
	}

	// --- OAuth authorization code ---
	arID, err := s.CreateTestAuthRequest(ctx, "code-test")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}
	if err := s.SaveAuthCode(ctx, arID, "AUTHCODE-XYZ"); err != nil {
		t.Fatalf("save auth code: %v", err)
	}
	ar, err := s.AuthRequestByCode(ctx, "AUTHCODE-XYZ")
	if err != nil {
		t.Fatalf("lookup by code: %v", err)
	}
	// The returned model surfaces the plaintext code, not the stored hash.
	arm, ok := ar.(*AuthRequestModel)
	if !ok {
		t.Fatalf("unexpected auth request type %T", ar)
	}
	if arm.Code == nil || *arm.Code != "AUTHCODE-XYZ" {
		t.Errorf("returned Code=%v, want plaintext AUTHCODE-XYZ", arm.Code)
	}

	var storedCode string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT code FROM auth_requests WHERE id=$1`, arID,
	).Scan(&storedCode); err != nil {
		t.Fatalf("read auth request row: %v", err)
	}
	if storedCode == "AUTHCODE-XYZ" {
		t.Error("authorization code stored in plaintext")
	}
}

// login-prompt-007: the OIDC prompt values survive CreateAuthRequest, and an
// absent prompt is stored as an empty array (the column is NOT NULL).
func TestCreateAuthRequest_PromptRoundTrip(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	s.LoadClients([]oauthclient.ConfigEntry{{
		ClientID:          "prompt-app",
		ClientType:        "public",
		LoginChannel:      "browser",
		Name:              "Prompt App",
		RedirectURIs:      []string{"https://app.example.com/cb"},
		AllowedScopes:     []string{"openid"},
		AllowedGrantTypes: []string{"authorization_code"},
	}})

	for _, prompt := range [][]string{{"login", "consent"}, {"none"}, nil} {
		created, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID:            "prompt-app",
			RedirectURI:         "https://app.example.com/cb",
			Scopes:              []string{"openid"},
			ResponseType:        oidc.ResponseTypeCode,
			CodeChallenge:       "challenge",
			CodeChallengeMethod: oidc.CodeChallengeMethodS256,
			Prompt:              prompt,
		}, "")
		if err != nil {
			t.Fatalf("CreateAuthRequest(prompt=%v): %v", prompt, err)
		}
		got, err := s.GetAuthRequestModel(ctx, created.GetID())
		if err != nil {
			t.Fatalf("GetAuthRequestModel: %v", err)
		}
		if strings.Join(got.Prompt, " ") != strings.Join(prompt, " ") {
			t.Fatalf("stored prompt = %v, want %v", got.Prompt, prompt)
		}
	}
}
