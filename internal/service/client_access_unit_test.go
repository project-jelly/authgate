package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type auditRecord struct {
	userID    *string
	eventType string
	metadata  map[string]any
}

// accessHarness is a fake login store for a client whose policy admits only
// allowed@example.com and the corp.example Google Workspace.
type accessHarness struct {
	store     *fakeLoginStore
	events    []auditRecord
	completed bool
	created   bool
	sessions  int
	recovered bool
	hdSet     []string
}

func restrictedPolicy(t *testing.T) *clientaccess.Policy {
	t.Helper()
	p, err := clientaccess.New(clientaccess.Rules{
		GoogleWorkspaceDomains: []string{"corp.example"},
		Emails:                 []string{"allowed@example.com"},
	}, clientaccess.DenyRules{})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// newAccessHarness serves auth request ar-1 for client-a on channel with the
// given prompt. sessionUser is returned for session "sess-1" (nil: no
// session); identityUser for the upstream identity (nil: not found).
func newAccessHarness(t *testing.T, channel string, prompt []string, policy *clientaccess.Policy, sessionUser, identityUser *storage.User) *accessHarness {
	t.Helper()
	h := &accessHarness{}
	h.store = &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			if sessionUser == nil {
				return nil, storage.ErrNotFound
			}
			u := *sessionUser
			if u.Status == "disabled" || u.Status == "deleted" {
				return &u, storage.ErrUserAccountClosed
			}
			return &u, nil
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{
				ID:          "ar-1",
				ClientID:    "client-a",
				Resource:    "http://authgate.test/mcp",
				RedirectURI: "https://app.example.com/cb?tenant=t1",
				State:       "st-1",
				Prompt:      prompt,
			}, nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "client-a", Name: "Client A", LoginChannel: channel, Access: policy}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			if identityUser == nil {
				return nil, storage.ErrNotFound
			}
			u := *identityUser
			return &u, nil
		},
		createUserWithIdentityFn: func(_ context.Context, in storage.CreateUserWithIdentityInput) (*storage.User, error) {
			h.created = true
			return &storage.User{ID: "new-user", Email: in.Email, EmailVerified: in.EmailVerified, HostedDomain: in.HostedDomain, Status: "active"}, nil
		},
		getUserByIDFn: func(_ context.Context, id string) (*storage.User, error) {
			return &storage.User{ID: id, Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			h.sessions++
			return "sess-new", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			h.completed = true
			return nil
		},
		recoverUserFn: func(context.Context, string) error {
			h.recovered = true
			return nil
		},
		setHostedDomainFn: func(_ context.Context, _, _, hd string) error {
			h.hdSet = append(h.hdSet, hd)
			return nil
		},
		auditLogFn: func(_ context.Context, userID *string, eventType, _, _ string, metadata map[string]any) {
			h.events = append(h.events, auditRecord{userID: userID, eventType: eventType, metadata: metadata})
		},
	}
	return h
}

func (h *accessHarness) eventTypes() []string {
	out := make([]string, 0, len(h.events))
	for _, e := range h.events {
		out = append(out, e.eventType)
	}
	return out
}

func (h *accessHarness) accessDenied(t *testing.T) auditRecord {
	t.Helper()
	var found []auditRecord
	for _, e := range h.events {
		if e.eventType == storage.EventAuthAccessDenied {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("auth.access_denied rows = %d, want 1; events = %v", len(found), h.eventTypes())
	}
	return found[0]
}

func assertAccessDenied(t *testing.T, action LoginAction, redirectURL string) {
	t.Helper()
	if action != ActionRedirectToClient {
		t.Fatalf("action = %v, want redirect to client", action)
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", redirectURL, err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://app.example.com/cb" {
		t.Fatalf("redirect target = %q, want client redirect_uri", redirectURL)
	}
	q := u.Query()
	if q.Get("error") != "access_denied" || q.Get("state") != "st-1" || q.Get("iss") != "http://authgate.test" || q.Get("tenant") != "t1" {
		t.Fatalf("redirect query = %v", q)
	}
}

func assertDeniedMetadata(t *testing.T, e auditRecord, channel, reason, domain string, signup bool) {
	t.Helper()
	md := e.metadata
	if md["client_id"] != "client-a" || md["client_name"] != "Client A" || md["channel"] != channel ||
		md["reason"] != reason || md["domain"] != domain || md["signup"] != signup {
		t.Fatalf("auth.access_denied metadata = %#v", md)
	}
	for _, v := range md {
		if s, ok := v.(string); ok && strings.Contains(s, "@") {
			t.Fatalf("metadata carries an address: %#v", md)
		}
	}
}

func browserCallback(h *accessHarness, info *upstream.UserInfo) *CallbackResult {
	return NewLoginService(h.store, "google", "http://authgate.test", time.Hour).CompleteBrowserLogin(context.Background(), "ar-1", info, "127.0.0.1", "ua")
}

// client-access-200: a refused signup redirects access_denied, creates no
// account and no session, and writes one auth.access_denied without user_id.
func TestClientAccess_BrowserSignup_Denied(t *testing.T) {
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, nil)
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "Outsider@Other.example", EmailVerified: true})

	assertAccessDenied(t, result.Action, result.RedirectURL)
	if h.created || h.sessions != 0 || h.completed {
		t.Fatalf("created=%v sessions=%d completed=%v, want none", h.created, h.sessions, h.completed)
	}
	e := h.accessDenied(t)
	if e.userID != nil {
		t.Fatalf("user_id = %v, want nil for a refused signup", *e.userID)
	}
	assertDeniedMetadata(t, e, "browser", clientaccess.ReasonNotAllowed, "other.example", true)
	if len(h.events) != 1 {
		t.Fatalf("events = %v, want only auth.access_denied", h.eventTypes())
	}
}

// client-access-201: an unverified address that an email rule names is still
// refused at signup, with the reason saying so.
func TestClientAccess_BrowserSignup_UnverifiedDenied(t *testing.T) {
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, nil)
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "allowed@example.com"})
	assertAccessDenied(t, result.Action, result.RedirectURL)
	if h.created {
		t.Fatal("account created for an unverified address")
	}
	assertDeniedMetadata(t, h.accessDenied(t), "browser", clientaccess.ReasonEmailUnverified, "example.com", true)
}

// client-access-202: an allowed signup proceeds and stores the hosted domain.
func TestClientAccess_BrowserSignup_AllowedStoresHostedDomain(t *testing.T) {
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, nil)
	var input storage.CreateUserWithIdentityInput
	h.store.createUserWithIdentityFn = func(_ context.Context, in storage.CreateUserWithIdentityInput) (*storage.User, error) {
		input = in
		return &storage.User{ID: "new-user", Status: "active"}, nil
	}
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "x@corp.example", EmailVerified: true, HostedDomain: "corp.example"})
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v error = %q, want auto-approve", result.Action, result.Error)
	}
	if input.HostedDomain != "corp.example" {
		t.Fatalf("CreateUserWithIdentity HostedDomain = %q, want corp.example", input.HostedDomain)
	}
}

// client-access-203: an existing account the client refuses is redirected
// access_denied without a session; the login's hosted domain is still recorded.
func TestClientAccess_BrowserExistingUser_Denied(t *testing.T) {
	user := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "active", HostedDomain: "corp.example"}
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, user)
	// The account left the workspace: the IdP no longer sends hd, so the
	// stale stored value must not admit it.
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "outsider@other.example", EmailVerified: true})

	assertAccessDenied(t, result.Action, result.RedirectURL)
	if h.sessions != 0 || h.completed {
		t.Fatalf("sessions=%d completed=%v, want none", h.sessions, h.completed)
	}
	if len(h.hdSet) != 1 || h.hdSet[0] != "" {
		t.Fatalf("hosted domain writes = %q, want one clearing write", h.hdSet)
	}
	e := h.accessDenied(t)
	if e.userID == nil || *e.userID != "u1" {
		t.Fatalf("user_id = %v, want u1", e.userID)
	}
	assertDeniedMetadata(t, e, "browser", clientaccess.ReasonNotAllowed, "other.example", false)
}

// client-access-204: the hosted domain the IdP just sent is what an existing
// account is evaluated with.
func TestClientAccess_BrowserExistingUser_FreshHostedDomainAllows(t *testing.T) {
	user := &storage.User{ID: "u1", Email: "x@personal.example", EmailVerified: true, Status: "active"}
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, user)
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "x@personal.example", EmailVerified: true, HostedDomain: "corp.example"})
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v error = %q, want auto-approve", result.Action, result.Error)
	}
	if len(h.hdSet) != 1 || h.hdSet[0] != "corp.example" {
		t.Fatalf("hosted domain writes = %q, want [corp.example]", h.hdSet)
	}
}

// client-access-205: a failed hosted-domain write stops the login rather than
// leaving later refresh checks on stale data.
func TestClientAccess_BrowserExistingUser_HostedDomainWriteFails(t *testing.T) {
	user := &storage.User{ID: "u1", Email: "allowed@example.com", EmailVerified: true, Status: "active"}
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, user)
	h.store.setHostedDomainFn = func(context.Context, string, string, string) error { return errors.New("db down") }
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "allowed@example.com", EmailVerified: true})
	if result.Action != ActionError || result.ErrorCode != 500 || h.completed {
		t.Fatalf("action=%v code=%d completed=%v, want 500 error", result.Action, result.ErrorCode, h.completed)
	}
}

// client-access-206: a disabled account is reported as inactive, not as
// refused by the client, so the audit trail keeps one meaningful row.
func TestClientAccess_BrowserExistingUser_DisabledStaysInactive(t *testing.T) {
	user := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "disabled"}
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, user)
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "outsider@other.example", EmailVerified: true})
	if result.Action != ActionError || result.Error != "account_inactive" {
		t.Fatalf("action=%v error=%q, want account_inactive", result.Action, result.Error)
	}
	if got := h.eventTypes(); len(got) != 1 || got[0] != "auth.inactive_user" {
		t.Fatalf("events = %v, want [auth.inactive_user]", got)
	}
}

// client-access-207: a refused login never cancels a pending deletion.
func TestClientAccess_BrowserExistingUser_PendingDeletionNotRecovered(t *testing.T) {
	user := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "pending_deletion"}
	h := newAccessHarness(t, "browser", nil, restrictedPolicy(t), nil, user)
	result := browserCallback(h, &upstream.UserInfo{Sub: "s1", Email: "outsider@other.example", EmailVerified: true})
	assertAccessDenied(t, result.Action, result.RedirectURL)
	if h.recovered {
		t.Fatal("pending deletion cancelled by a refused login")
	}

	// Session reuse on the same account behaves the same.
	h = newAccessHarness(t, "browser", nil, restrictedPolicy(t), user, nil)
	login := NewLoginService(h.store, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
	assertAccessDenied(t, login.Action, login.RedirectURL)
	if h.recovered || h.completed {
		t.Fatalf("recovered=%v completed=%v, want neither", h.recovered, h.completed)
	}
}

// client-access-208: session reuse on browser and mcp, with and without
// prompt=none, is refused with access_denied (never login_required) for an
// account the client does not admit, and allowed for one it does.
func TestClientAccess_SessionReuse(t *testing.T) {
	logins := map[string]func(LoginStore) *LoginResult{
		"browser": func(s LoginStore) *LoginResult {
			return NewLoginService(s, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
		},
		"mcp": func(s LoginStore) *LoginResult {
			return NewMCPLoginService(s, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
		},
	}
	for channel, login := range logins {
		for _, prompt := range [][]string{nil, {"none"}} {
			t.Run(channel+"/prompt="+joinPrompt(prompt), func(t *testing.T) {
				outsider := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "active"}
				h := newAccessHarness(t, channel, prompt, restrictedPolicy(t), outsider, nil)
				result := login(h.store)
				assertAccessDenied(t, result.Action, result.RedirectURL)
				if h.completed {
					t.Fatal("auth request completed for a refused account")
				}
				assertDeniedMetadata(t, h.accessDenied(t), channel, clientaccess.ReasonNotAllowed, "other.example", false)
				if len(h.events) != 1 {
					t.Fatalf("events = %v, want only auth.access_denied", h.eventTypes())
				}

				// The stored hosted domain admits a workspace account.
				member := &storage.User{ID: "u2", Email: "x@personal.example", EmailVerified: true, Status: "active", HostedDomain: "corp.example"}
				h = newAccessHarness(t, channel, prompt, restrictedPolicy(t), member, nil)
				result = login(h.store)
				if result.Action != ActionAutoApprove || !h.completed {
					t.Fatalf("action=%v completed=%v, want auto-approve", result.Action, h.completed)
				}

				// A public client admits the outsider.
				h = newAccessHarness(t, channel, prompt, nil, outsider, nil)
				if result = login(h.store); result.Action != ActionAutoApprove {
					t.Fatalf("public client: action=%v error=%q, want auto-approve", result.Action, result.Error)
				}
			})
		}
	}
}

func joinPrompt(p []string) string {
	if len(p) == 0 {
		return "default"
	}
	return p[0]
}

// client-access-209: a channel mismatch is reported as such before the policy
// is considered.
func TestClientAccess_ChannelMismatchBeforePolicy(t *testing.T) {
	outsider := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "active"}
	h := newAccessHarness(t, "mcp", nil, restrictedPolicy(t), outsider, nil)
	result := NewLoginService(h.store, "google", "http://authgate.test", time.Hour).HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")
	if result.Action != ActionError || result.Error != "channel_mismatch" {
		t.Fatalf("action=%v error=%q, want channel_mismatch", result.Action, result.Error)
	}
	if got := h.eventTypes(); len(got) != 1 || got[0] != storage.EventAuthChannelMismatch {
		t.Fatalf("events = %v, want [auth.channel_mismatch]", got)
	}
}

// client-access-210: the MCP callback refuses an account the client does not
// admit, without a session, after recording the hosted domain.
func TestClientAccess_MCPCallback(t *testing.T) {
	outsider := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "active"}
	h := newAccessHarness(t, "mcp", nil, restrictedPolicy(t), nil, outsider)
	svc := NewMCPLoginService(h.store, "google", "http://authgate.test", time.Hour)
	result := svc.CompleteMCPLogin(context.Background(), "ar-1", &upstream.UserInfo{Sub: "s1", Email: "outsider@other.example", EmailVerified: true, HostedDomain: "other.example"}, "127.0.0.1", "ua")
	assertAccessDenied(t, result.Action, result.RedirectURL)
	if h.sessions != 0 || h.completed {
		t.Fatalf("sessions=%d completed=%v, want none", h.sessions, h.completed)
	}
	if len(h.hdSet) != 1 || h.hdSet[0] != "other.example" {
		t.Fatalf("hosted domain writes = %q", h.hdSet)
	}
	assertDeniedMetadata(t, h.accessDenied(t), "mcp", clientaccess.ReasonNotAllowed, "other.example", false)

	h = newAccessHarness(t, "mcp", nil, restrictedPolicy(t), nil, outsider)
	svc = NewMCPLoginService(h.store, "google", "http://authgate.test", time.Hour)
	result = svc.CompleteMCPLogin(context.Background(), "ar-1", &upstream.UserInfo{Sub: "s1", HostedDomain: "corp.example"}, "127.0.0.1", "ua")
	if result.Action != ActionAutoApprove {
		t.Fatalf("workspace member: action=%v error=%q, want auto-approve", result.Action, result.Error)
	}
}

func deviceAccessStore(t *testing.T, policy *clientaccess.Policy, user *storage.User, approved *bool, events *[]auditRecord) *fakeDeviceStore {
	t.Helper()
	return &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			u := *user
			return &u, nil
		},
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "client-a", State: "pending"}, nil
		},
		resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
			return &oauthclient.Model{ID: "client-a", Name: "Client A", Access: policy}, nil
		},
		approveDeviceCodeFn: func(context.Context, string, string) error {
			*approved = true
			return nil
		},
		auditLogFn: func(_ context.Context, userID *string, eventType, _, _ string, metadata map[string]any) {
			*events = append(*events, auditRecord{userID: userID, eventType: eventType, metadata: metadata})
		},
	}
}

// client-access-220: device approval is refused before the code is approved.
func TestClientAccess_DeviceApprove(t *testing.T) {
	outsider := &storage.User{ID: "u1", Email: "outsider@other.example", EmailVerified: true, Status: "active"}
	var approved bool
	var events []auditRecord
	svc := NewDeviceService(deviceAccessStore(t, restrictedPolicy(t), outsider, &approved, &events), "google", "http://authgate.test", time.Hour, clock.RealClock{})
	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "approve", "sess", "127.0.0.1", "ua")
	if result.Success || result.ErrorCode != 403 || result.Message != deviceAccessDeniedMessage {
		t.Fatalf("result = %+v, want 403 with the access-denied message", result)
	}
	if approved {
		t.Fatal("device code approved for a refused account")
	}
	if len(events) != 1 || events[0].eventType != storage.EventAuthAccessDenied {
		t.Fatalf("events = %+v, want one auth.access_denied", events)
	}
	h := &accessHarness{events: events}
	assertDeniedMetadata(t, h.accessDenied(t), "device", clientaccess.ReasonNotAllowed, "other.example", false)

	// A workspace member (stored hd) is approved.
	member := &storage.User{ID: "u2", Email: "x@personal.example", EmailVerified: true, Status: "active", HostedDomain: "corp.example"}
	approved, events = false, nil
	svc = NewDeviceService(deviceAccessStore(t, restrictedPolicy(t), member, &approved, &events), "google", "http://authgate.test", time.Hour, clock.RealClock{})
	if result = svc.HandleDeviceApprove(context.Background(), "UCODE", "approve", "sess", "127.0.0.1", "ua"); !result.Success || !approved {
		t.Fatalf("member: result=%+v approved=%v, want approved", result, approved)
	}

	// Denying the code is never blocked by the policy.
	denied := false
	store := deviceAccessStore(t, restrictedPolicy(t), outsider, &approved, &events)
	store.denyDeviceCodeFn = func(context.Context, string) error { denied = true; return nil }
	svc = NewDeviceService(store, "google", "http://authgate.test", time.Hour, clock.RealClock{})
	svc.HandleDeviceApprove(context.Background(), "UCODE", "deny", "sess", "127.0.0.1", "ua")
	if !denied {
		t.Fatal("deny action blocked by the access policy")
	}
}

// client-access-221: the device callback records the login's hosted domain.
func TestClientAccess_DeviceCallbackRecordsHostedDomain(t *testing.T) {
	var hd []string
	store := &fakeDeviceStore{
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "client-a", State: "pending", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) { return "sess", nil },
		setHostedDomainFn: func(_ context.Context, _, _, v string) error {
			hd = append(hd, v)
			return nil
		},
	}
	svc := NewDeviceService(store, "google", "http://authgate.test", time.Hour, clock.RealClock{})
	result := svc.CompleteDeviceLogin(context.Background(), "UCODE", &upstream.UserInfo{Sub: "s1", HostedDomain: "corp.example"}, "127.0.0.1", "ua")
	if result.Action != DeviceRedirectBack {
		t.Fatalf("action = %v error = %q", result.Action, result.Error)
	}
	if len(hd) != 1 || hd[0] != "corp.example" {
		t.Fatalf("hosted domain writes = %q, want [corp.example]", hd)
	}
}

// client-access-211: every upstream callback (browser, mcp, device) evaluates
// the email and email_verified the IdP just asserted, never the email stored at
// signup, which nothing updates. A stored address the policy admits does not
// carry an upstream address it deny-lists, and a deny-listed stored address
// does not refuse an upstream one it admits.
func TestClientAccess_CallbacksEvaluateUpstreamEmail(t *testing.T) {
	policy, err := clientaccess.New(clientaccess.Rules{EmailDomains: []string{"example.com"}},
		clientaccess.DenyRules{Emails: []string{"gone@example.com"}})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	type outcome struct {
		allowed bool
		events  []auditRecord
	}
	callbacks := map[string]func(t *testing.T, stored *storage.User, info *upstream.UserInfo) outcome{
		"browser": func(t *testing.T, stored *storage.User, info *upstream.UserInfo) outcome {
			h := newAccessHarness(t, "browser", nil, policy, nil, stored)
			result := browserCallback(h, info)
			if result.Action != ActionAutoApprove {
				assertAccessDenied(t, result.Action, result.RedirectURL)
			}
			return outcome{allowed: result.Action == ActionAutoApprove && h.sessions == 1, events: h.events}
		},
		"mcp": func(t *testing.T, stored *storage.User, info *upstream.UserInfo) outcome {
			h := newAccessHarness(t, "mcp", nil, policy, nil, stored)
			result := NewMCPLoginService(h.store, "google", "http://authgate.test", time.Hour).CompleteMCPLogin(context.Background(), "ar-1", info, "127.0.0.1", "ua")
			if result.Action != ActionAutoApprove {
				assertAccessDenied(t, result.Action, result.RedirectURL)
			}
			return outcome{allowed: result.Action == ActionAutoApprove && h.sessions == 1, events: h.events}
		},
		"device": func(t *testing.T, stored *storage.User, info *upstream.UserInfo) outcome {
			var events []auditRecord
			sessions := 0
			store := &fakeDeviceStore{
				getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
					return &storage.DeviceCodeModel{UserCode: "UCODE", ClientID: "client-a", State: "pending", ExpiresAt: time.Now().Add(time.Hour)}, nil
				},
				getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
					u := *stored
					return &u, nil
				},
				resolveClientFn: func(context.Context, string) (*oauthclient.Model, error) {
					return &oauthclient.Model{ID: "client-a", Name: "Client A", Access: policy}, nil
				},
				createSessionFn: func(context.Context, string, time.Duration) (string, error) {
					sessions++
					return "sess", nil
				},
				auditLogFn: func(_ context.Context, userID *string, eventType, _, _ string, metadata map[string]any) {
					events = append(events, auditRecord{userID: userID, eventType: eventType, metadata: metadata})
				},
			}
			result := NewDeviceService(store, "google", "http://authgate.test", time.Hour, clock.RealClock{}).CompleteDeviceLogin(context.Background(), "UCODE", info, "127.0.0.1", "ua")
			if result.Action != DeviceRedirectBack && (result.ErrorCode != 403 || result.Error != deviceAccessDeniedMessage) {
				t.Fatalf("device refusal = %+v, want 403 with the access-denied message", result)
			}
			return outcome{allowed: result.Action == DeviceRedirectBack && sessions == 1, events: events}
		},
	}

	for channel, callback := range callbacks {
		t.Run(channel+"/stored allowed, upstream deny-listed", func(t *testing.T) {
			stored := &storage.User{ID: "u1", Email: "kept@example.com", EmailVerified: true, Status: "active"}
			got := callback(t, stored, &upstream.UserInfo{Sub: "s1", Email: "gone@example.com", EmailVerified: true})
			if got.allowed {
				t.Fatal("login allowed on the stored email although the IdP asserted a deny-listed one")
			}
			h := &accessHarness{events: got.events}
			assertDeniedMetadata(t, h.accessDenied(t), channel, clientaccess.ReasonDenyListed, "example.com", false)
		})
		t.Run(channel+"/stored allowed, upstream unverified", func(t *testing.T) {
			stored := &storage.User{ID: "u1", Email: "kept@example.com", EmailVerified: true, Status: "active"}
			got := callback(t, stored, &upstream.UserInfo{Sub: "s1", Email: "kept@example.com"})
			if got.allowed {
				t.Fatal("login allowed on the stored email_verified although the IdP asserted an unverified address")
			}
			h := &accessHarness{events: got.events}
			assertDeniedMetadata(t, h.accessDenied(t), channel, clientaccess.ReasonEmailUnverified, "example.com", false)
		})
		// Every later token path evaluates the stored address, so admitting on
		// the fresh one alone would mint a session and a code the exchange then
		// refuses. Both must pass, and one refusal writes one row.
		t.Run(channel+"/stored deny-listed, upstream allowed", func(t *testing.T) {
			stored := &storage.User{ID: "u1", Email: "gone@example.com", EmailVerified: true, Status: "active"}
			got := callback(t, stored, &upstream.UserInfo{Sub: "s1", Email: "kept@example.com", EmailVerified: true})
			if got.allowed {
				t.Fatal("login allowed on the fresh email although the stored one, which every token path uses, is deny-listed")
			}
			h := &accessHarness{events: got.events}
			assertDeniedMetadata(t, h.accessDenied(t), channel, clientaccess.ReasonDenyListed, "example.com", false)
		})
		t.Run(channel+"/both allowed", func(t *testing.T) {
			stored := &storage.User{ID: "u1", Email: "kept@example.com", EmailVerified: true, Status: "active"}
			got := callback(t, stored, &upstream.UserInfo{Sub: "s1", Email: "kept@example.com", EmailVerified: true})
			if !got.allowed {
				t.Fatalf("login refused although both addresses are allowed; events = %+v", got.events)
			}
			for _, e := range got.events {
				if e.eventType == storage.EventAuthAccessDenied {
					t.Fatalf("auth.access_denied written for an allowed login: %+v", e)
				}
			}
		})
	}
}
