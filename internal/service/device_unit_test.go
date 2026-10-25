package service

import (
	"context"
	"errors"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type fakeDeviceStore struct {
	getDeviceCodeByUserCodeFn func(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error)
	getValidSessionFn         func(ctx context.Context, sessionID string) (*storage.User, error)
	auditLogFn                func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	getUserByProviderIdentity func(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	createSessionFn           func(ctx context.Context, userID string, ttl time.Duration) (string, error)
	denyDeviceCodeFn          func(ctx context.Context, userCode string) error
	approveDeviceCodeFn       func(ctx context.Context, userCode, subject string) error
	resolveClientFn           func(ctx context.Context, clientID string) (*oauthclient.Model, error)
	setHostedDomainFn         func(ctx context.Context, provider, providerUserID, hostedDomain string) error
	sessionAuthTime           time.Time
	sessionAuthTimeErr        error
	approvedAuthTime          time.Time
}

func (f *fakeDeviceStore) SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error {
	if f.setHostedDomainFn == nil {
		return nil
	}
	return f.setHostedDomainFn(ctx, provider, providerUserID, hostedDomain)
}

func (f *fakeDeviceStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error) {
	if f.getDeviceCodeByUserCodeFn == nil {
		return nil, storage.ErrNotFound
	}
	return f.getDeviceCodeByUserCodeFn(ctx, userCode)
}

func (f *fakeDeviceStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeDeviceStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	if f.auditLogFn == nil {
		return
	}
	f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func (f *fakeDeviceStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error) {
	return f.getUserByProviderIdentity(ctx, provider, providerUserID)
}

func (f *fakeDeviceStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	return f.createSessionFn(ctx, userID, ttl)
}

func (f *fakeDeviceStore) DenyDeviceCode(ctx context.Context, userCode string) error {
	return f.denyDeviceCodeFn(ctx, userCode)
}

func (f *fakeDeviceStore) ApproveDeviceCode(ctx context.Context, userCode, subject string, authTime time.Time) error {
	f.approvedAuthTime = authTime
	return f.approveDeviceCodeFn(ctx, userCode, subject)
}

// SessionAuthTime answers with sessionAuthTime, defaulting to "just now".
func (f *fakeDeviceStore) SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error) {
	if f.sessionAuthTimeErr != nil {
		return time.Time{}, f.sessionAuthTimeErr
	}
	if f.sessionAuthTime.IsZero() {
		return time.Now(), nil
	}
	return f.sessionAuthTime, nil
}

func (f *fakeDeviceStore) ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	if f.resolveClientFn != nil {
		return f.resolveClientFn(ctx, clientID)
	}
	return nil, storage.ErrNotFound
}

func TestDevice_HandleDevicePage_NoSession_Redirects(t *testing.T) {
	clk := &clock.FixedClock{T: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)}
	store := &fakeDeviceStore{
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{
				UserCode:  "UCODE",
				State:     "pending",
				ExpiresAt: clk.Now().Add(5 * time.Minute),
			}, nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clk)

	result := svc.HandleDevicePage(context.Background(), "UCODE", "")

	if result.Action != DeviceRedirectIdP {
		t.Fatalf("action = %v, want %v", result.Action, DeviceRedirectIdP)
	}
}

func TestDevice_HandleDeviceApprove_Deny(t *testing.T) {
	denyCalled := false
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "test-client", State: "pending"}, nil
		},
		denyDeviceCodeFn: func(context.Context, string) error {
			denyCalled = true
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "deny", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("deny action should return success=false")
	}
	if !denyCalled {
		t.Fatal("DenyDeviceCode should be called")
	}
}

// TestDevice_HandleDeviceApprove_Deny_NotPending_SkipsMutation asserts that
// denyDeviceCode aborts when the device_code is no longer pending — the deny
// mutation must not run and no auth.device_denied audit row may be emitted
// (#205, Codex review blocker).
func TestDevice_HandleDeviceApprove_Deny_NotPending_SkipsMutation(t *testing.T) {
	denyCalled := false
	auditCalled := false
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "test-client", State: "approved"}, nil
		},
		denyDeviceCodeFn: func(context.Context, string) error {
			denyCalled = true
			return nil
		},
		auditLogFn: func(context.Context, *string, string, string, string, map[string]any) {
			auditCalled = true
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "deny", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("deny on non-pending should still return success=false to the user")
	}
	if denyCalled {
		t.Fatal("DenyDeviceCode must not be called when state != pending")
	}
	if auditCalled {
		t.Fatal("auth.device_denied audit must not be emitted when state != pending")
	}
}

// TestDevice_HandleDeviceApprove_InvalidAction asserts that any action value
// outside {approve, deny} returns 400 without running any mutation or audit
// (#205, Codex review blocker — strict consent surface).
func TestDevice_HandleDeviceApprove_InvalidAction(t *testing.T) {
	approveCalled := false
	denyCalled := false
	auditCalled := false
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		approveDeviceCodeFn: func(context.Context, string, string) error {
			approveCalled = true
			return nil
		},
		denyDeviceCodeFn: func(context.Context, string) error {
			denyCalled = true
			return nil
		},
		auditLogFn: func(context.Context, *string, string, string, string, map[string]any) {
			auditCalled = true
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "bogus", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("invalid action must not return success")
	}
	if result.ErrorCode != 400 {
		t.Fatalf("errorCode = %d, want 400", result.ErrorCode)
	}
	if approveCalled || denyCalled {
		t.Fatal("invalid action must not run approve or deny mutations")
	}
	if auditCalled {
		t.Fatal("invalid action must not emit audit rows")
	}
}

func TestDevice_HandleDeviceApprove_ApproveError(t *testing.T) {
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "test-client", State: "pending"}, nil
		},
		approveDeviceCodeFn: func(context.Context, string, string) error {
			return errors.New("expired")
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "approve", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("approve with error should fail")
	}
	if result.ErrorCode != 400 {
		t.Fatalf("errorCode = %d, want 400", result.ErrorCode)
	}
}

// #186: the device callback must reject invalid local user_code state.
// Pre-exchange amplification protection now lives in the high-level
// CodeExchangeHandler (state cookie + PKCE verified before the upstream
// token call), so the service-level guard runs on the post-exchange
// CompleteDeviceLogin path. Each local-state failure mode — not_found,
// expired, non-pending — must still surface DeviceError, and must reject
// before any user lookup binds the freshly-authenticated subject.
func TestDevice_CompleteDeviceLogin_RejectsInvalidLocalState(t *testing.T) {
	clk := &clock.FixedClock{T: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)}
	cases := []struct {
		name string
		dc   *storage.DeviceCodeModel
		err  error
	}{
		{name: "not_found", err: storage.ErrNotFound},
		{name: "expired", dc: &storage.DeviceCodeModel{UserCode: "UCODE", State: "pending", ExpiresAt: clk.Now().Add(-1 * time.Minute)}},
		{name: "consumed", dc: &storage.DeviceCodeModel{UserCode: "UCODE", State: "consumed", ExpiresAt: clk.Now().Add(5 * time.Minute)}},
		{name: "approved", dc: &storage.DeviceCodeModel{UserCode: "UCODE", State: "approved", ExpiresAt: clk.Now().Add(5 * time.Minute)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getUserCalled := false
			store := &fakeDeviceStore{
				getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
					return tc.dc, tc.err
				},
				getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
					getUserCalled = true
					return &storage.User{ID: "u1", Status: "active"}, nil
				},
			}
			svc := NewDeviceService(store, "google", "http://localhost", 24*time.Hour, clk)

			result := svc.CompleteDeviceLogin(context.Background(), "UCODE", &upstream.UserInfo{Sub: "sub"}, "127.0.0.1", "ua")

			if result.Action != DeviceError {
				t.Errorf("action = %v, want DeviceError", result.Action)
			}
			if getUserCalled {
				t.Errorf("user lookup ran despite invalid local state (must reject first)")
			}
		})
	}
}

func TestDevice_HandleDeviceCallback_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	clk := &clock.FixedClock{T: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)}
	store := &fakeDeviceStore{
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{
				UserCode:  "UCODE",
				ClientID:  "device-client",
				State:     "pending",
				ExpiresAt: clk.Now().Add(5 * time.Minute),
			}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
			gotEventType = eventType
			gotMetadata = metadata
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider.Name(), "http://localhost", 24*time.Hour, clk)

	result := svc.CompleteDeviceLogin(context.Background(), "UCODE", provider.User, "127.0.0.1", "ua")

	if result.Action != DeviceRedirectBack {
		t.Fatalf("action = %v, want %v", result.Action, DeviceRedirectBack)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "device" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "device-client" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}

// device-auth-time-001: approving a device records when the approving user
// actually authenticated — the session's creation time. Clicking approve is
// not a new authentication, and an ID token minted from this device code
// carries this auth_time (OIDC Core 2).
func TestDevice_Approve_AuthTimeIsTheSessionsOwn(t *testing.T) {
	signedInAt := time.Now().Add(-4 * time.Hour)
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "test-client", State: "pending"}, nil
		},
		approveDeviceCodeFn: func(context.Context, string, string) error { return nil },
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "test-client", Name: "Test Client", LoginChannel: "browser"}, nil
		},
	}
	store.sessionAuthTime = signedInAt

	svc := NewDeviceService(store, "google", "http://localhost", 24*time.Hour, clock.RealClock{})
	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "approve", "sess-1", "127.0.0.1", "ua")
	if !result.Success {
		t.Fatalf("approve failed: %s", result.Message)
	}
	if drift := store.approvedAuthTime.Sub(signedInAt); drift > time.Second || drift < -time.Second {
		t.Errorf("auth_time = %v, want the session's creation time %v", store.approvedAuthTime, signedInAt)
	}
}
