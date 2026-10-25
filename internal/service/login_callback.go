package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// CompleteBrowserLogin finishes the browser callback after the upstream code
// exchange has already happened inside the high-level CodeExchangeHandler
// (which verified the state cookie / PKCE before exchange). state carries the
// authRequestID; info is the resolved upstream identity.
func (s *LoginService) CompleteBrowserLogin(ctx context.Context, state string, info *upstream.UserInfo, ipAddress, userAgent string) *CallbackResult {
	authRequestID, userInfo := state, info
	if authRequestID == "" || userInfo == nil {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// The state-cookie check inside CodeExchangeHandler already gated this
	// request before the upstream exchange, so the anti-amplification ordering
	// is satisfied. We still resolve the local auth_request and verify its
	// channel binding before completing it.
	authReq, result := loadCallbackAuthRequest(ctx, s.store, authRequestID)
	if result != nil {
		return result
	}
	client, errMsg, statusCode := verifyAuthRequestChannel(ctx, s.store, authReq, "browser", ipAddress, userAgent, nil)
	if errMsg != "" {
		return &CallbackResult{Action: ActionError, Error: errMsg, ErrorCode: statusCode}
	}
	clientName := client.Name

	user, signedUp, recovered, result := s.prepareBrowserCallbackUser(ctx, userInfo, authReq, client, ipAddress, userAgent)
	if result != nil {
		return result
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}
	if recovered {
		s.auditDeletionCancelled(ctx, user.ID, sessionID, authReq, ipAddress, userAgent)
	}

	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID, time.Time{}); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "browser",
		"session_id":  sessionID,
		"client_id":   authReq.ClientID,
		"client_name": clientName,
		"signup":      signedUp,
	})

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

// prepareBrowserCallbackUser performs the user-lookup or signup half of the
// browser callback flow. The caller passes the already-fetched authReq so that
// the signup audit row and the subsequent auth.login row reference the same
// request context — duplicate loadCallbackAuthRequest calls would otherwise
// race against expiration/cleanup between fetch and audit (Codex review NIT
// on PR #218).
//
// The client's access policy runs before signup, so a refused person never gets
// an account, and for an existing account after the inactive check and before
// recovery, so a refused login neither masks a disabled account nor cancels a
// pending deletion. Both evaluate what the IdP just asserted, not the email
// stored at signup, which nothing updates.
func (s *LoginService) prepareBrowserCallbackUser(ctx context.Context, userInfo *upstream.UserInfo, authReq *storage.AuthRequestModel, client *oauthclient.Model, ipAddress, userAgent string) (*storage.User, bool, bool, *CallbackResult) {
	providerName := s.providerName
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		if !checkClientAccess(ctx, s.store, client, "browser", nil, accessSubjectFromUpstream(userInfo), true, ipAddress, userAgent) {
			return nil, false, false, callbackResultFrom(accessDeniedRedirect(s.issuer, authReq))
		}
		user, result := s.signupBrowserUser(ctx, providerName, userInfo, authReq, ipAddress, userAgent)
		return user, true, false, result
	}
	if err != nil {
		return nil, false, false, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if result := recordHostedDomain(ctx, s.store, providerName, userInfo, user); result != nil {
		return nil, false, false, result
	}

	if CheckAccess(user.Status, "browser") != AccessDeny &&
		!checkExistingAccountAccess(ctx, s.store, client, "browser", user, userInfo, ipAddress, userAgent) {
		return nil, false, false, callbackResultFrom(accessDeniedRedirect(s.issuer, authReq))
	}

	user, recovered, result := s.ensureBrowserAccess(ctx, user, ipAddress, userAgent)
	if result != nil {
		return nil, false, false, result
	}
	return user, false, recovered, nil
}

func (s *LoginService) signupBrowserUser(ctx context.Context, providerName string, userInfo *upstream.UserInfo, authReq *storage.AuthRequestModel, ipAddress, userAgent string) (*storage.User, *CallbackResult) {
	user, err := s.store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
		Name:           userInfo.Name,
		Provider:       providerName,
		ProviderUserID: userInfo.Sub,
		HostedDomain:   userInfo.HostedDomain,
	})
	if errors.Is(err, storage.ErrEmailConflict) {
		return nil, &CallbackResult{Action: ActionError, Error: "email_conflict", ErrorCode: http.StatusConflict}
	}
	if err != nil {
		return nil, &CallbackResult{Action: ActionError, Error: fmt.Sprintf("signup failed: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	// audit-011 (#204): signup always happens inside an auth_request, so the
	// originating client_id / client_name must be carried on the audit row.
	s.store.AuditLog(ctx, &user.ID, "auth.signup", ipAddress, userAgent, map[string]any{
		"channel":     "browser",
		"client_id":   authReq.ClientID,
		"client_name": resolveClientName(ctx, s.store, authReq.ClientID),
	})
	return user, nil
}

func (s *LoginService) ensureBrowserAccess(ctx context.Context, user *storage.User, ipAddress, userAgent string) (*storage.User, bool, *CallbackResult) {
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return nil, false, &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	case AccessRecover:
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return nil, false, &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}

		recoveredUser, err := s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return nil, false, &CallbackResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
		return recoveredUser, true, nil
	default:
		return user, false, nil
	}
}
