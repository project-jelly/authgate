package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type DeviceService struct {
	store        DeviceStore
	providerName string
	sessionTTL   time.Duration
	publicURL    string
	clock        clock.Clock
}

type DeviceStore interface {
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error)
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	DenyDeviceCode(ctx context.Context, userCode string) error
	ApproveDeviceCode(ctx context.Context, userCode, subject string, authTime time.Time) error
	// SessionAuthTime is when the session's owner last authenticated upstream.
	SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error)
	ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error)
	SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error
}

func NewDeviceService(store DeviceStore, providerName string, publicURL string, sessionTTL time.Duration, clk clock.Clock) *DeviceService {
	return &DeviceService{
		store:        store,
		providerName: providerName,
		publicURL:    publicURL,
		sessionTTL:   sessionTTL,
		clock:        clk,
	}
}

type DevicePageResult struct {
	Action    DeviceAction
	UserCode  string
	SessionID string
	CSRFToken string
	Error     string
	ErrorCode int
}

type DeviceAction int

const (
	DeviceShowEntry    DeviceAction = iota // Show user_code input form
	DeviceShowApprove                      // Show approve/deny buttons
	DeviceShowResult                       // Show success/failure result
	DeviceRedirectIdP                      // Redirect to IdP for login
	DeviceRedirectBack                     // Redirect back to /device?user_code=X after callback
	DeviceError                            // Show error page
)

// HandleDevicePage handles GET /device and GET /device?user_code=XXXX
func (s *DeviceService) HandleDevicePage(ctx context.Context, userCode, sessionID string) *DevicePageResult {
	if userCode == "" {
		return &DevicePageResult{Action: DeviceShowEntry}
	}

	if result := s.validateDevicePage(ctx, userCode); result != nil {
		return result
	}

	if sessionID == "" {
		return s.redirectDeviceToProvider(userCode)
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrNotFound) {
		return s.redirectDeviceToProvider(userCode)
	}
	if errors.Is(err, storage.ErrUserAccountClosed) {
		// Storage flagged a terminal status; ensureDeviceSessionAccess
		// performs the audit + 403 response.
		return s.ensureDeviceSessionAccess(ctx, user)
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	if result := s.ensureDeviceSessionAccess(ctx, user); result != nil {
		return result
	}

	return &DevicePageResult{Action: DeviceShowApprove, UserCode: userCode}
}

// CompleteDeviceLogin finishes the device callback after the upstream code
// exchange has already happened inside the high-level CodeExchangeHandler
// (which verified the state cookie / PKCE before exchange). state carries the
// user_code; info is the resolved upstream identity.
func (s *DeviceService) CompleteDeviceLogin(ctx context.Context, state string, info *upstream.UserInfo, ipAddress, userAgent string) *DevicePageResult {
	userCode := state
	if userCode == "" || info == nil {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}

	// The state-cookie check inside CodeExchangeHandler already gated this
	// request before the upstream exchange (anti-amplification per #186). We
	// still validate the local user_code lifecycle before binding the subject.
	deviceCode, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if s.clock.Now().After(deviceCode.ExpiresAt) {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}
	// Only `pending` user_codes are eligible for callback consumption.
	// `approved`/`consumed`/`denied` already finished their lifecycle and
	// must not silently re-bind a freshly-IdP-authenticated subject; the
	// device-flow client is expected to start a new device-authorization.
	if deviceCode.State != "pending" {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}

	userInfo := info

	user, result := s.findDeviceCallbackUser(ctx, userInfo.Sub)
	if result != nil {
		return result
	}
	if r := recordHostedDomain(ctx, s.store, s.providerName, userInfo, user); r != nil {
		return &DevicePageResult{Action: DeviceError, Error: r.Error, ErrorCode: r.ErrorCode}
	}
	if result := s.ensureDeviceCallbackAccess(ctx, user, ipAddress, userAgent); result != nil {
		return result
	}
	if result := s.ensureDeviceCallbackClientAccess(ctx, deviceCode.ClientID, user, userInfo, ipAddress, userAgent); result != nil {
		return result
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "device",
		"session_id":  sessionID,
		"client_id":   deviceCode.ClientID,
		"client_name": resolveClientName(ctx, s.store, deviceCode.ClientID),
	})

	return &DevicePageResult{Action: DeviceRedirectBack, UserCode: userCode, SessionID: sessionID}
}

type DeviceApproveResult struct {
	Success   bool
	Message   string
	SessionID string
	ErrorCode int
}

// HandleDeviceApprove handles POST /device/approve
func (s *DeviceService) HandleDeviceApprove(ctx context.Context, userCode, action, sessionID, ipAddress, userAgent string) *DeviceApproveResult {
	if sessionID == "" {
		return &DeviceApproveResult{Success: false, Message: "no session", ErrorCode: http.StatusUnauthorized}
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "device"})
		return &DeviceApproveResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &DeviceApproveResult{Success: false, Message: "invalid session", ErrorCode: http.StatusUnauthorized}
	}

	if CheckAccess(user.Status, "device") != AccessAllow {
		return &DeviceApproveResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	switch action {
	case "approve":
		return s.approveDeviceCode(ctx, userCode, user, sessionID, ipAddress, userAgent)
	case "deny":
		s.denyDeviceCode(ctx, userCode, user.ID, ipAddress, userAgent)
		return &DeviceApproveResult{Success: false, Message: "You denied the authorization request. You can close this window."}
	default:
		// Reject any other form value to keep the device-consent surface
		// strict. A blank-or-typo "action" must not silently fall through to
		// approve and generate an auth.device_approved audit row (#205).
		return &DeviceApproveResult{Success: false, Message: "invalid action", ErrorCode: http.StatusBadRequest}
	}
}

func (s *DeviceService) validateDevicePage(ctx context.Context, userCode string) *DevicePageResult {
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "Invalid code. Please check and try again."}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	now := s.clock.Now()
	if now.After(dc.ExpiresAt) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has expired. Please request a new one."}
	}
	if dc.State != "pending" {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has already been used."}
	}

	return nil
}

func (s *DeviceService) redirectDeviceToProvider(userCode string) *DevicePageResult {
	return &DevicePageResult{Action: DeviceRedirectIdP, UserCode: userCode}
}

func (s *DeviceService) ensureDeviceSessionAccess(ctx context.Context, user *storage.User) *DevicePageResult {
	if CheckAccess(user.Status, "device") == AccessAllow {
		return nil
	}

	info := clientinfo.FromContext(ctx)
	s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", info.IP, info.UserAgent, map[string]any{"status": user.Status, "channel": "device"})
	return &DevicePageResult{Action: DeviceError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
}

func (s *DeviceService) findDeviceCallbackUser(ctx context.Context, providerUserID string) (*storage.User, *DevicePageResult) {
	user, err := s.store.GetUserByProviderIdentity(ctx, s.providerName, providerUserID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, &DevicePageResult{Action: DeviceError, Error: "account_not_found: please sign up via browser first", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return nil, &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	return user, nil
}

func (s *DeviceService) ensureDeviceCallbackAccess(ctx context.Context, user *storage.User, ipAddress, userAgent string) *DevicePageResult {
	if CheckAccess(user.Status, "device") == AccessAllow {
		return nil
	}

	s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "device"})
	return &DevicePageResult{Action: DeviceError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
}

// ensureDeviceCallbackClientAccess evaluates the client's access policy for
// the account at the device callback, against both what the IdP just asserted
// and what approval will see (see checkExistingAccountAccess). A refusal creates
// no session and leaves the device code pending. A client that cannot be
// resolved is left to approval, which refuses it; the callback grants nothing by
// itself.
func (s *DeviceService) ensureDeviceCallbackClientAccess(ctx context.Context, clientID string, user *storage.User, userInfo *upstream.UserInfo, ipAddress, userAgent string) *DevicePageResult {
	client, err := s.store.ResolveClient(ctx, clientID)
	if err != nil || client == nil {
		return nil
	}
	if !checkExistingAccountAccess(ctx, s.store, client, "device", user, userInfo, ipAddress, userAgent) {
		return &DevicePageResult{Action: DeviceError, Error: deviceAccessDeniedMessage, ErrorCode: http.StatusForbidden}
	}
	return nil
}

// deviceAccessDeniedMessage is shown when the client's access policy refuses
// the signed-in account on the device pages.
const deviceAccessDeniedMessage = "This account is not allowed to use this application. You can close this window."

func (s *DeviceService) denyDeviceCode(ctx context.Context, userCode, userID, ipAddress, userAgent string) {
	dc, metadata, err := s.loadDeviceAuditContext(ctx, userCode)
	if err != nil {
		slog.WarnContext(ctx, "device deny: skipping audit (context lookup failed)",
			"user_id", userID,
			"error", err,
		)
		return
	}
	// DenyDeviceCodeByUserCode is `:exec` (no rows-affected check available),
	// so guard against issuing audit when the row is already terminal — the
	// underlying UPDATE would no-op and we must not record auth.device_denied
	// for a code that was already approved/denied/consumed (#205).
	if dc.State != "pending" {
		slog.WarnContext(ctx, "device deny: skipping audit (state not pending)",
			"user_id", userID,
			"state", dc.State,
		)
		return
	}
	if err := s.store.DenyDeviceCode(ctx, userCode); err != nil {
		slog.WarnContext(ctx, "device deny: skipping audit (mutation failed)",
			"user_id", userID,
			"error", err,
		)
		return
	}
	s.store.AuditLog(ctx, &userID, "auth.device_denied", ipAddress, userAgent, metadata)
}

// approveDeviceCode binds the device code to the user. The client's access
// policy is checked first: approval is the last interactive step of the device
// flow, and once it succeeds the CLI's next poll receives tokens. A refused
// approval leaves the code pending, so the user can sign in with another
// account before it expires.
func (s *DeviceService) approveDeviceCode(ctx context.Context, userCode string, user *storage.User, sessionID, ipAddress, userAgent string) *DeviceApproveResult {
	userID := user.ID
	dc, metadata, err := s.loadDeviceAuditContext(ctx, userCode)
	if err != nil {
		// audit-011 requires client_id on the auth.device_approved row, so a
		// failed lookup must abort the mutation+audit pair rather than emit a
		// metadataless row (#205). Surface the same user-facing message as a
		// stale code so the consent page does not leak the lookup failure.
		slog.WarnContext(ctx, "device approve: aborting (context lookup failed)",
			"user_id", userID,
			"error", err,
		)
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}
	// The policy must be known before approving; a client that cannot be
	// resolved is refused rather than treated as public.
	client, err := s.store.ResolveClient(ctx, dc.ClientID)
	if err != nil || client == nil {
		slog.WarnContext(ctx, "device approve: aborting (client lookup failed)",
			"user_id", userID,
			"error", err,
		)
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}
	if !checkClientAccess(ctx, s.store, client, "device", &userID, storage.AccessSubject(user), false, ipAddress, userAgent) {
		return &DeviceApproveResult{Success: false, Message: deviceAccessDeniedMessage, ErrorCode: http.StatusForbidden}
	}
	// The approval carries the session's own auth time: the user signed in
	// before reaching this page, and clicking approve is not a new login.
	authTime, err := s.store.SessionAuthTime(ctx, sessionID)
	if err != nil {
		return &DeviceApproveResult{Success: false, Message: "Your session has expired. Sign in again.", ErrorCode: http.StatusUnauthorized}
	}
	if err := s.store.ApproveDeviceCode(ctx, userCode, userID, authTime); err != nil {
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}

	s.store.AuditLog(ctx, &userID, "auth.device_approved", ipAddress, userAgent, metadata)
	return &DeviceApproveResult{Success: true, Message: "You have successfully authorized the CLI application. You can close this window."}
}

// loadDeviceAuditContext loads the device_code and resolves its client so the
// auth.device_approved / auth.device_denied audit rows can identify which
// CLI/client was acted upon (audit-011, #205). It returns the device_code
// (callers may inspect State for additional guards) alongside a metadata map
// suitable for AuditLog. A non-nil error means the row should not be audited
// — audit-011 requires client_id, so we prefer skipping the audit (with a
// warn log) over emitting a row with no client identification.
func (s *DeviceService) loadDeviceAuditContext(ctx context.Context, userCode string) (*storage.DeviceCodeModel, map[string]any, error) {
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return nil, nil, err
	}
	if dc == nil {
		return nil, nil, storage.ErrNotFound
	}
	md := map[string]any{"client_id": dc.ClientID}
	if c, err := s.store.ResolveClient(ctx, dc.ClientID); err == nil && c != nil {
		md["client_name"] = c.Name
	}
	return dc, md, nil
}
