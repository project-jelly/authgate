package service

import (
	"context"
	"net/http"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// checkClientAccess evaluates the client's access policy for an account and,
// when it refuses, writes one auth.access_denied row. userID is nil for a
// refused signup, where no account exists. It returns whether access is
// allowed. A client without a policy allows everyone and writes nothing.
func checkClientAccess(ctx context.Context, store clientAuditor, client *oauthclient.Model, channel string, userID *string, subject clientaccess.Subject, signup bool, ipAddress, userAgent string) bool {
	decision := client.Access.Evaluate(subject)
	if decision.Allowed {
		return true
	}
	store.AuditLog(ctx, userID, storage.EventAuthAccessDenied, ipAddress, userAgent,
		storage.AccessDeniedAuditMetadata(client.ID, client.Name, channel, decision.Reason, subject.Email, signup))
	return false
}

// checkExistingAccountAccess evaluates the client's policy for an existing
// account at an upstream login callback. Both the address the IdP just asserted
// and the one stored at signup must pass: the callback sees the fresh claims,
// but every later token path (code exchange, session reuse, device approval and
// polling, refresh) sees only the stored ones, so admitting on the fresh claims
// alone would create a session and a code the exchange then refuses. The fresh
// claims are evaluated first so that, when both fail, the audit row describes
// what the IdP says now. One refusal writes one auth.access_denied row.
func checkExistingAccountAccess(ctx context.Context, store clientAuditor, client *oauthclient.Model, channel string, user *storage.User, info *upstream.UserInfo, ipAddress, userAgent string) bool {
	return checkClientAccess(ctx, store, client, channel, &user.ID, accessSubjectFromUpstream(info), false, ipAddress, userAgent) &&
		checkClientAccess(ctx, store, client, channel, &user.ID, storage.AccessSubject(user), false, ipAddress, userAgent)
}

type clientAuditor interface {
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
}

// accessDeniedRedirect ends a browser or mcp auth request refused by the
// client's access policy with access_denied sent to the client, so the relying
// party learns the outcome instead of the user being stranded on an authgate
// page. prompt=none gets the same answer: login_required would invite the
// client to retry interactively, which cannot succeed.
func accessDeniedRedirect(issuer string, authReq *storage.AuthRequestModel) *LoginResult {
	return authorizationErrorRedirect(issuer, authReq, "access_denied")
}

// callbackResultFrom carries a login result into the callback result shape.
func callbackResultFrom(r *LoginResult) *CallbackResult {
	return &CallbackResult{Action: r.Action, RedirectURL: r.RedirectURL, AuthRequestID: r.AuthRequestID, Error: r.Error, ErrorCode: r.ErrorCode}
}

// accessSubjectFromUpstream is the subject of an upstream login: what the IdP
// just asserted. Every callback evaluates it, for a new account and an existing
// one alike, because the stored email is the one from signup and is never
// updated; the stored subject (AccessSubject) is for paths with no IdP round
// trip: session reuse, device approval, code exchange, device polling and
// refresh.
func accessSubjectFromUpstream(info *upstream.UserInfo) clientaccess.Subject {
	return clientaccess.Subject{Email: info.Email, EmailVerified: info.EmailVerified, HostedDomain: info.HostedDomain}
}

type hostedDomainRecorder interface {
	SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error
}

// recordHostedDomain stores the hosted domain the IdP just asserted for an
// existing identity and applies it to user, so this login and every later
// session reuse, device approval and refresh evaluate the IdP's latest answer.
// It runs on every successful upstream login, whether or not the login is then
// allowed: the stored value is a fact about the account, not a grant.
func recordHostedDomain(ctx context.Context, store hostedDomainRecorder, provider string, info *upstream.UserInfo, user *storage.User) *CallbackResult {
	if err := store.SetIdentityHostedDomain(ctx, provider, info.Sub, info.HostedDomain); err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	user.HostedDomain = info.HostedDomain
	return nil
}
