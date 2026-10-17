//go:build integration

package service

import (
	"context"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func setupDeviceService(t *testing.T) (*DeviceService, *storage.Storage, clock.Clock, *upstream.UserInfo) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{
			Sub:           "device-sub-123",
			Email:         "device@example.com",
			EmailVerified: true,
			Name:          "Device User",
		},
	}

	svc := NewDeviceService(store, fakeProvider.Name(), "http://localhost:8080", 24*time.Hour, clk)
	return svc, store, clk, fakeProvider.User
}

func insertDeviceCode(t *testing.T, store *storage.Storage, userCode string, clk clock.Clock) {
	t.Helper()
	ctx := context.Background()
	// Register the test client so audit-row metadata (#205) can carry both
	// client_id and the human-readable client_name resolved via ResolveClient.
	store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "test-client", Name: "Test Device Client", LoginChannel: "browser"}})
	err := store.StoreDeviceAuthorization(ctx, "test-client", "dc-"+userCode, userCode,
		clk.Now().Add(5*time.Minute), []string{"openid"})
	if err != nil {
		t.Fatalf("insert device code: %v", err)
	}
}

func TestDevicePage_NoUserCode_ShowEntry(t *testing.T) {
	svc, _, _, _ := setupDeviceService(t)
	result := svc.HandleDevicePage(context.Background(), "", "")
	if result.Action != DeviceShowEntry {
		t.Errorf("action = %v, want DeviceShowEntry", result.Action)
	}
}

func TestDevicePage_InvalidUserCode_ShowEntryWithError(t *testing.T) {
	svc, _, _, _ := setupDeviceService(t)
	result := svc.HandleDevicePage(context.Background(), "INVALID", "")
	if result.Action != DeviceShowEntry {
		t.Errorf("action = %v, want DeviceShowEntry", result.Action)
	}
	if result.Error == "" {
		t.Error("should have error message for invalid code")
	}
}

func TestDevicePage_ValidCode_NoSession_RedirectIdP(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	insertDeviceCode(t, store, "BCDF-GHKM", clk)

	result := svc.HandleDevicePage(context.Background(), "BCDF-GHKM", "")
	if result.Action != DeviceRedirectIdP {
		t.Errorf("action = %v, want DeviceRedirectIdP", result.Action)
	}
}

func TestDevicePage_ValidCode_WithSession_ShowApprove(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	// Create active user and session
	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-approve@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-approve-sub"})
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "APPR-CODE", clk)

	result := svc.HandleDevicePage(ctx, "APPR-CODE", sessionID)
	if result.Action != DeviceShowApprove {
		t.Errorf("action = %v, want DeviceShowApprove", result.Action)
	}
}

func TestDevicePage_InactiveUser_Rejected(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	// Create disabled user
	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-inactive@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-inactive-sub"})
	store.DisableUser(ctx, user.ID)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "INCM-CODE", clk)

	result := svc.HandleDevicePage(ctx, "INCM-CODE", sessionID)
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (account_inactive)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

func TestDeviceApprove_Allow(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-allow@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-allow-sub"})
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "ALLW-CODE", clk)

	result := svc.HandleDeviceApprove(ctx, "ALLW-CODE", "approve", sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
}

func TestDeviceApprove_Deny(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-deny@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-deny-sub"})
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "DENY-CODE", clk)

	result := svc.HandleDeviceApprove(ctx, "DENY-CODE", "deny", sessionID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected denial, got success")
	}
}

func TestDeviceApprove_NoSession_Unauthorized(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	insertDeviceCode(t, store, "NSES-CODE", clk)

	result := svc.HandleDeviceApprove(context.Background(), "NSES-CODE", "approve", "", "127.0.0.1", "test")
	if result.Success {
		t.Error("expected failure without session")
	}
	if result.ErrorCode != 401 {
		t.Errorf("errorCode = %d, want 401", result.ErrorCode)
	}
}

func TestDeviceCallback_NewUser_SignupRequired(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceService(t)
	// #186: callback now front-loads the user_code lookup, so seed a
	// pending row before invoking — the post-Exchange "no user account"
	// branch is what this test is asserting.
	insertDeviceCode(t, store, "CBCK-CODE", clk)
	// FakeProvider returns a user that doesn't exist in DB yet
	result := svc.CompleteDeviceLogin(context.Background(), "CBCK-CODE", fakeUser, "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (account_not_found)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

func TestDeviceCallback_ExistingUser_RedirectBack(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceService(t)
	ctx := context.Background()

	store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-cb@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-sub-123"})
	insertDeviceCode(t, store, "RDIR-CODE", clk)

	result := svc.CompleteDeviceLogin(ctx, "RDIR-CODE", fakeUser, "127.0.0.1", "test")
	if result.Action != DeviceRedirectBack {
		t.Errorf("action = %v, want DeviceRedirectBack", result.Action)
	}
	if result.UserCode != "RDIR-CODE" {
		t.Errorf("userCode = %q, want RDIR-CODE", result.UserCode)
	}
	if result.SessionID == "" {
		t.Error("sessionID should be returned for callback redirect")
	}
}

// device-005: recoverable_browser_only callback → account_inactive
func TestDevice005_RecoverableCallback_Rejected(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceExtTest(t, "dev-recover-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "dev-recover@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "dev-recover-sub"})
	store.SetUserStatus(ctx, user.ID, "pending_deletion")
	insertDeviceCode(t, store, "RECV-CODE", clk)

	result := svc.CompleteDeviceLogin(ctx, "RECV-CODE", fakeUser, "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (recoverable on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-006: inactive callback → account_inactive
func TestDevice006_InactiveCallback_Rejected(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceExtTest(t, "dev-inactive-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "dev-inactive@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "dev-inactive-sub"})
	store.DisableUser(ctx, user.ID)
	insertDeviceCode(t, store, "INAC-CODE", clk)

	result := svc.CompleteDeviceLogin(ctx, "INAC-CODE", fakeUser, "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (inactive on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-004: deleted callback -> account_inactive
func TestDeviceCallback_DeletedUser_Rejected(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceExtTest(t, "dev-deleted-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "dev-deleted@test.com", EmailVerified: true, Name: "Deleted", Provider: "google", ProviderUserID: "dev-deleted-sub"})
	_ = store.SetUserStatus(ctx, user.ID, "deleted")
	insertDeviceCode(t, store, "DELD-CODE", clk)

	result := svc.CompleteDeviceLogin(ctx, "DELD-CODE", fakeUser, "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (deleted on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-011: approve 직전 inactive로 변경 → account_inactive
func TestDevice011_ApproveAfterDisable(t *testing.T) {
	svc, store, clk, _ := setupDeviceExtTest(t, "dev-approve-dis-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "dev-approve-dis@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "dev-approve-dis-sub"})
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "ADIS-CODE", clk)

	// Disable user AFTER session creation
	store.DisableUser(ctx, user.ID)

	result := svc.HandleDeviceApprove(ctx, "ADIS-CODE", "approve", sessionID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected rejection after disable at approve time")
	}
	if result.Message != "account_inactive" {
		t.Errorf("message = %q, want account_inactive", result.Message)
	}
}

// device-008 확장: approve 직전 pending/deleted 변경 시 account_inactive
func TestDeviceApprove_AfterStatusTransition_Rejected(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "pending_deletion", status: "pending_deletion"},
		{name: "deleted", status: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, store, clk, _ := setupDeviceExtTest(t, "dev-approve-"+tt.status)
			ctx := context.Background()

			user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "dev-approve-" + tt.status + "@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "dev-approve-" + tt.status})
			sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
			insertDeviceCode(t, store, "ASTA-"+tt.status, clk)

			_ = store.SetUserStatus(ctx, user.ID, tt.status)

			result := svc.HandleDeviceApprove(ctx, "ASTA-"+tt.status, "approve", sessionID, "127.0.0.1", "test")
			if result.Success {
				t.Fatalf("expected rejection after status transition to %s", tt.status)
			}
			if result.ErrorCode != 403 {
				t.Fatalf("errorCode = %d, want 403", result.ErrorCode)
			}
			if result.Message != "account_inactive" {
				t.Fatalf("message = %q, want account_inactive", result.Message)
			}
		})
	}
}
