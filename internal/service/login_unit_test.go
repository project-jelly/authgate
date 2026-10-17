package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type fakeLoginStore struct {
	getValidSessionFn         func(ctx context.Context, sessionID string) (*storage.User, error)
	auditLogFn                func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	recoverUserFn             func(ctx context.Context, userID string) error
	completeAuthRequestFn     func(ctx context.Context, authRequestID, userID string) error
	getUserByProviderIdentity func(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	createUserWithIdentityFn  func(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error)
	getUserByIDFn             func(ctx context.Context, userID string) (*storage.User, error)
	createSessionFn           func(ctx context.Context, userID string, ttl time.Duration) (string, error)
	getAuthRequestModelFn     func(ctx context.Context, id string) (*storage.AuthRequestModel, error)
	resolveClientFn           func(ctx context.Context, clientID string) (*oauthclient.Model, error)
	setHostedDomainFn         func(ctx context.Context, provider, providerUserID, hostedDomain string) error
	sessionAuthTimeFn         func(ctx context.Context, sessionID string) (time.Time, error)
	sessionAuthTime           time.Time
	completedAuthTime         time.Time
}

func (f *fakeLoginStore) SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error {
	if f.setHostedDomainFn == nil {
		return nil
	}
	return f.setHostedDomainFn(ctx, provider, providerUserID, hostedDomain)
}

func (f *fakeLoginStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeLoginStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	if f.auditLogFn == nil {
		return
	}
	f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func (f *fakeLoginStore) RecoverUser(ctx context.Context, userID string) error {
	return f.recoverUserFn(ctx, userID)
}

func (f *fakeLoginStore) CompleteAuthRequest(ctx context.Context, authRequestID, userID string, authTime time.Time) error {
	f.completedAuthTime = authTime
	return f.completeAuthRequestFn(ctx, authRequestID, userID)
}

// SessionAuthTime answers with sessionAuthTime, defaulting to "just now" so
// tests that do not care about max_age keep reusing sessions.
func (f *fakeLoginStore) SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error) {
	if f.sessionAuthTimeFn != nil {
		return f.sessionAuthTimeFn(ctx, sessionID)
	}
	if f.sessionAuthTime.IsZero() {
		return time.Now(), nil
	}
	return f.sessionAuthTime, nil
}

func (f *fakeLoginStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error) {
	return f.getUserByProviderIdentity(ctx, provider, providerUserID)
}

func (f *fakeLoginStore) CreateUserWithIdentity(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error) {
	return f.createUserWithIdentityFn(ctx, input)
}

func (f *fakeLoginStore) GetUserByID(ctx context.Context, userID string) (*storage.User, error) {
	return f.getUserByIDFn(ctx, userID)
}

func (f *fakeLoginStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	return f.createSessionFn(ctx, userID, ttl)
}

func TestLogin_HandleLogin_RecoversPendingDeletionSession(t *testing.T) {
	calledRecover := false
	calledComplete := false

	store := &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "pending_deletion"}, nil
		},
		recoverUserFn: func(context.Context, string) error {
			calledRecover = true
			return nil
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			calledComplete = true
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "s1"}}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if !calledRecover {
		t.Fatal("RecoverUser should be called for pending_deletion")
	}
	if !calledComplete {
		t.Fatal("CompleteAuthRequest should be called")
	}
}

func TestLogin_HandleCallback_EmailConflict(t *testing.T) {
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return nil, storage.ErrNotFound
		},
		createUserWithIdentityFn: func(context.Context, storage.CreateUserWithIdentityInput) (*storage.User, error) {
			return nil, storage.ErrEmailConflict
		},
	}
	provider := &upstream.FakeProvider{
		ProviderName: "google",
		User: &upstream.UserInfo{
			Sub:           "sub-1",
			Email:         "dup@example.com",
			EmailVerified: true,
			Name:          "Dup",
		},
	}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.CompleteBrowserLogin(context.Background(), "ar-1", provider.User, "127.0.0.1", "ua")

	if result.Action != ActionError {
		t.Fatalf("action = %v, want %v", result.Action, ActionError)
	}
	if result.ErrorCode != 409 {
		t.Fatalf("errorCode = %d, want 409", result.ErrorCode)
	}
}

func TestLogin_HandleCallback_ExistingUser_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
			gotEventType = eventType
			gotMetadata = metadata
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.CompleteBrowserLogin(context.Background(), "ar-1", provider.User, "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "browser" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "client-a" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}

func TestLogin_HandleCallback_SignupAuditLogIncludesChannel(t *testing.T) {
	type auditEntry struct {
		eventType string
		metadata  map[string]any
	}
	var gotEvents []auditEntry
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return nil, storage.ErrNotFound
		},
		createUserWithIdentityFn: func(context.Context, storage.CreateUserWithIdentityInput) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "client-a", Name: "Client A", LoginChannel: "browser"}, nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
			gotEvents = append(gotEvents, auditEntry{eventType: eventType, metadata: metadata})
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.CompleteBrowserLogin(context.Background(), "ar-1", provider.User, "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	var signupEvent *auditEntry
	for i := range gotEvents {
		if gotEvents[i].eventType == "auth.signup" {
			signupEvent = &gotEvents[i]
			break
		}
	}
	if signupEvent == nil {
		t.Fatalf("auth.signup event not found in %v", gotEvents)
	}
	if signupEvent.metadata["channel"] != "browser" {
		t.Fatalf("signup channel = %v, want browser; metadata = %#v", signupEvent.metadata["channel"], signupEvent.metadata)
	}
	if signupEvent.metadata["client_id"] != "client-a" {
		t.Fatalf("signup client_id = %v, want client-a (#204); metadata = %#v", signupEvent.metadata["client_id"], signupEvent.metadata)
	}
	if signupEvent.metadata["client_name"] != "Client A" {
		t.Fatalf("signup client_name = %v, want \"Client A\" (#204); metadata = %#v", signupEvent.metadata["client_name"], signupEvent.metadata)
	}
}

// #149: completing an mcp-channel auth_request via the browser /login flow
// must be rejected and audited as auth.channel_mismatch.
func TestLogin_HandleLogin_RejectsCrossChannelAuthRequest(t *testing.T) {
	type evt struct {
		eventType string
		metadata  map[string]any
	}
	var events []evt
	store := &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "mcp-client"}, nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "mcp-client", Name: "MCP Client", LoginChannel: "mcp"}, nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			t.Fatal("CompleteAuthRequest must not be called on channel mismatch")
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
			events = append(events, evt{eventType: eventType, metadata: metadata})
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "s1"}}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	if result.Action != ActionError || result.Error != "channel_mismatch" {
		t.Fatalf("action=%v error=%q, want channel_mismatch error", result.Action, result.Error)
	}
	var found *evt
	for i := range events {
		if events[i].eventType == storage.EventAuthChannelMismatch {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("auth.channel_mismatch not audited; events=%v", events)
	}
	if found.metadata["expected_channel"] != "browser" || found.metadata["actual_channel"] != "mcp" {
		t.Fatalf("audit metadata=%#v", found.metadata)
	}
}

func TestMCPLogin_HandleCallback_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "mcp-client", Resource: "http://localhost/mcp"}, nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "mcp-client", Name: "MCP Client", LoginChannel: "mcp"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
			gotEventType = eventType
			gotMetadata = metadata
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewMCPLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.CompleteMCPLogin(context.Background(), "ar-1", provider.User, "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "mcp" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "mcp-client" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}

func TestLogin_HandleLogin_NoSession_Redirect(t *testing.T) {
	store := &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("no session")
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "s1"}}
	svc := NewLoginService(store, provider.Name(), "http://authgate.test", 24*time.Hour)

	result := svc.HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	if result.Action != ActionRedirectToIdP {
		t.Fatalf("action = %v, want %v", result.Action, ActionRedirectToIdP)
	}
}

func (f *fakeLoginStore) GetAuthRequestModel(ctx context.Context, id string) (*storage.AuthRequestModel, error) {
	if f.getAuthRequestModelFn != nil {
		return f.getAuthRequestModelFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}

func (f *fakeLoginStore) ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	if f.resolveClientFn != nil {
		return f.resolveClientFn(ctx, clientID)
	}
	// Default: a browser client, matching the permissive channel default the
	// removed getClientLoginChannelFn used to provide. Tests exercising the
	// mcp channel or a specific client name set resolveClientFn explicitly.
	return &oauthclient.Model{ID: clientID, Name: "Test Client", LoginChannel: "browser"}, nil
}

// promptTestStore serves one auth request with the given prompt for clientID,
// a session for "sess-1" whose user has status (no session when status is
// empty), and records whether the request was completed.
func promptTestStore(t *testing.T, prompt []string, status, channel string, completed *bool) *fakeLoginStore {
	t.Helper()
	return &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			switch status {
			case "":
				return nil, storage.ErrNotFound
			case "deleted":
				return &storage.User{ID: "u1", Status: status}, storage.ErrUserAccountClosed
			default:
				return &storage.User{ID: "u1", Status: status}, nil
			}
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{
				ID:          "ar-1",
				ClientID:    "client-a",
				RedirectURI: "https://app.example.com/cb?tenant=t1",
				State:       "st-1",
				Prompt:      prompt,
			}, nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "client-a", Name: "Client A", LoginChannel: channel}, nil
		},
		recoverUserFn: func(context.Context, string) error { return nil },
		completeAuthRequestFn: func(context.Context, string, string) error {
			*completed = true
			return nil
		},
	}
}

type promptLoginFunc func(store LoginStore) *LoginResult

var promptChannels = []struct {
	channel string
	login   promptLoginFunc
}{
	{"browser", func(store LoginStore) *LoginResult {
		return NewLoginService(store, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
	}},
	{"mcp", func(store LoginStore) *LoginResult {
		return NewMCPLoginService(store, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
	}},
}

// login-prompt-001: prompt=none with a usable session completes like a normal
// session reuse.
func TestLoginPrompt_None_WithSession_AutoApproves(t *testing.T) {
	for _, tc := range promptChannels {
		t.Run(tc.channel, func(t *testing.T) {
			completed := false
			result := tc.login(promptTestStore(t, []string{"none"}, "active", tc.channel, &completed))
			if result.Action != ActionAutoApprove || !completed {
				t.Fatalf("action=%v completed=%v, want auto-approve", result.Action, completed)
			}
		})
	}
}

// login-prompt-002: prompt=none without a session redirects login_required to
// the client with the request state and issuer, never to the IdP.
func TestLoginPrompt_None_NoSession_LoginRequired(t *testing.T) {
	for _, tc := range promptChannels {
		t.Run(tc.channel, func(t *testing.T) {
			completed := false
			result := tc.login(promptTestStore(t, []string{"none"}, "", tc.channel, &completed))
			assertLoginRequired(t, result)
			if completed {
				t.Fatal("auth request must not be completed")
			}
		})
	}
}

// login-prompt-003: prompt=none whose session belongs to an account that may
// not sign in on the channel gets login_required, not the account_inactive page.
func TestLoginPrompt_None_InactiveAccount_LoginRequired(t *testing.T) {
	cases := []struct{ channel, status string }{
		{"browser", "disabled"},
		{"browser", "deleted"},
		{"mcp", "disabled"},
		{"mcp", "pending_deletion"},
	}
	for _, c := range cases {
		t.Run(c.channel+"/"+c.status, func(t *testing.T) {
			var login promptLoginFunc
			for _, tc := range promptChannels {
				if tc.channel == c.channel {
					login = tc.login
				}
			}
			completed := false
			var events []string
			store := promptTestStore(t, []string{"none"}, c.status, c.channel, &completed)
			store.auditLogFn = func(_ context.Context, _ *string, eventType, _, _ string, _ map[string]any) {
				events = append(events, eventType)
			}
			result := login(store)
			assertLoginRequired(t, result)
			if completed {
				t.Fatal("auth request must not be completed")
			}
			if len(events) != 1 || events[0] != "auth.inactive_user" {
				t.Fatalf("audit events = %v, want [auth.inactive_user]", events)
			}
		})
	}
}

// login-prompt-008: prompt=none must not cancel a pending deletion. Recovery
// follows an interaction the user started; a background session check on the
// browser channel gets login_required and leaves the account as it is.
func TestLoginPrompt_None_PendingDeletion_DoesNotRecover(t *testing.T) {
	completed := false
	recovered := false
	var events []string
	store := promptTestStore(t, []string{"none"}, "pending_deletion", "browser", &completed)
	store.recoverUserFn = func(context.Context, string) error {
		recovered = true
		return nil
	}
	store.auditLogFn = func(_ context.Context, _ *string, eventType, _, _ string, _ map[string]any) {
		events = append(events, eventType)
	}

	result := NewLoginService(store, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	assertLoginRequired(t, result)
	if recovered || completed {
		t.Fatalf("recovered=%v completed=%v, want neither for prompt=none", recovered, completed)
	}
	if len(events) != 1 || events[0] != "auth.inactive_user" {
		t.Fatalf("audit events = %v, want [auth.inactive_user]", events)
	}
}

// login-prompt-004: prompt=none on the wrong login channel keeps the
// channel_mismatch page instead of redirecting to the client.
func TestLoginPrompt_None_ChannelMismatch_ErrorPage(t *testing.T) {
	completed := false
	store := promptTestStore(t, []string{"none"}, "", "mcp", &completed)
	result := promptChannels[0].login(store)
	if result.Action != ActionError || result.Error != "channel_mismatch" {
		t.Fatalf("action=%v error=%q, want channel_mismatch page", result.Action, result.Error)
	}
}

// login-prompt-005: prompt=login and prompt=select_account skip a usable
// session and send the user upstream with prompt=select_account.
func TestLoginPrompt_LoginOrSelectAccount_SkipsSession(t *testing.T) {
	for _, prompt := range [][]string{{"login"}, {"select_account"}, {"login", "consent"}} {
		for _, tc := range promptChannels {
			t.Run(tc.channel+"/"+strings.Join(prompt, "+"), func(t *testing.T) {
				completed := false
				store := promptTestStore(t, prompt, "active", tc.channel, &completed)
				store.getValidSessionFn = func(context.Context, string) (*storage.User, error) {
					t.Fatal("session must not be looked up")
					return nil, nil
				}
				result := tc.login(store)
				if result.Action != ActionRedirectToIdP || result.UpstreamPrompt != "select_account" {
					t.Fatalf("action=%v upstreamPrompt=%q, want IdP redirect with select_account", result.Action, result.UpstreamPrompt)
				}
				if completed {
					t.Fatal("session must not be reused")
				}
			})
		}
	}
}

// login-prompt-006: prompt=consent and no prompt keep session reuse and a
// plain upstream redirect.
func TestLoginPrompt_ConsentOrAbsent_DefaultBehavior(t *testing.T) {
	for _, prompt := range [][]string{nil, {"consent"}} {
		for _, tc := range promptChannels {
			name := tc.channel + "/" + strings.Join(prompt, "+")
			t.Run(name+"/session", func(t *testing.T) {
				completed := false
				result := tc.login(promptTestStore(t, prompt, "active", tc.channel, &completed))
				if result.Action != ActionAutoApprove || !completed {
					t.Fatalf("action=%v completed=%v, want auto-approve", result.Action, completed)
				}
			})
			t.Run(name+"/no-session", func(t *testing.T) {
				completed := false
				result := tc.login(promptTestStore(t, prompt, "", tc.channel, &completed))
				if result.Action != ActionRedirectToIdP || result.UpstreamPrompt != "" {
					t.Fatalf("action=%v upstreamPrompt=%q, want plain IdP redirect", result.Action, result.UpstreamPrompt)
				}
			})
		}
	}
}

func assertLoginRequired(t *testing.T, result *LoginResult) {
	t.Helper()
	if result.Action != ActionRedirectToClient {
		t.Fatalf("action=%v error=%q, want redirect to client", result.Action, result.Error)
	}
	u, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", result.RedirectURL, err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://app.example.com/cb" {
		t.Fatalf("redirect target = %q, want client redirect_uri", result.RedirectURL)
	}
	q := u.Query()
	if q.Get("error") != "login_required" || q.Get("state") != "st-1" || q.Get("iss") != "http://authgate.test" || q.Get("tenant") != "t1" {
		t.Fatalf("redirect query = %v", q)
	}
}

// login-prompt-009: an expired auth request is the client's stale link, so
// both login channels answer 400 auth_request_expired, not 500.
func TestLogin_ExpiredAuthRequest_BadRequest(t *testing.T) {
	for _, tc := range promptChannels {
		t.Run(tc.channel, func(t *testing.T) {
			completed := false
			store := promptTestStore(t, nil, "active", tc.channel, &completed)
			store.getAuthRequestModelFn = func(context.Context, string) (*storage.AuthRequestModel, error) {
				return nil, &oidc.Error{ErrorType: "invalid_request", Description: "auth request expired"}
			}
			result := tc.login(store)
			if result.Action != ActionError || result.ErrorCode != http.StatusBadRequest || result.Error != "auth_request_expired" {
				t.Fatalf("result = %+v, want 400 auth_request_expired", result)
			}
		})
	}
}
