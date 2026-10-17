package service

import (
	"context"
	"errors"
	"net/http"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/storage"
)

// verifyAuthRequestChannel ensures the auth_request's client uses the expected
// login_channel. On mismatch it audits an auth.channel_mismatch event and
// returns an error message + HTTP status suitable for a *LoginResult or
// *CallbackResult. Lookup errors return ("internal_error", 500); a clean match
// returns ("", 0).
// It resolves the client once and returns it so the caller's access-policy
// check and success audit can reuse it instead of resolving a second time — for
// MCP clients a resolve may trigger an outbound CIMD fetch, so collapsing the
// lookups avoids a duplicate fetch per login (#302 M2). The client is non-nil
// whenever errMsg is empty.
func verifyAuthRequestChannel(ctx context.Context, store LoginStore, authReq *storage.AuthRequestModel, expected, ipAddress, userAgent string, userID *string) (client *oauthclient.Model, errMsg string, statusCode int) {
	client, err := store.ResolveClient(ctx, authReq.ClientID)
	if err != nil || client == nil {
		return nil, "internal_error", http.StatusInternalServerError
	}
	if client.LoginChannel != expected {
		store.AuditLog(ctx, userID, storage.EventAuthChannelMismatch, ipAddress, userAgent, map[string]any{
			"expected_channel": expected,
			"actual_channel":   client.LoginChannel,
			"client_id":        authReq.ClientID,
			"client_name":      client.Name,
		})
		return client, "channel_mismatch", http.StatusBadRequest
	}
	return client, "", 0
}

// completeReusedSessionLogin runs the shared tail of a session-reuse login for
// the browser and mcp channels (device flow has a different shape — it shows an
// approval page instead of auto-completing). The caller has already resolved
// the session, run CheckAccess, verified the channel binding, checked the
// client's access policy, and performed any channel-specific recovery;
// `recovered` is only ever true for the browser channel, which is the only one
// whose CheckAccess returns AccessRecover. This audits a deletion-cancelled
// recovery when applicable, completes the request, and writes the auth.login
// audit — identically across channels except for the channel label.
func completeReusedSessionLogin(ctx context.Context, store LoginStore, channel, clientName string, user *storage.User, authReq *storage.AuthRequestModel, authTime time.Time, sessionID, ipAddress, userAgent string, recovered bool) *LoginResult {
	authRequestID := authReq.ID
	if recovered {
		store.AuditLog(ctx, &user.ID, storage.EventAuthDeletionCancelled, ipAddress, userAgent, lifecycleAuditMetadata(
			channel, sessionID, authReq.ClientID, clientName,
		))
	}

	// auth_time is when this session's owner authenticated upstream, not now:
	// reusing a session does not re-authenticate anyone (OIDC Core 2).
	if err := store.CompleteAuthRequest(ctx, authRequestID, user.ID, authTime); err != nil {
		return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":        channel,
		"session_id":     sessionID,
		"client_id":      authReq.ClientID,
		"client_name":    clientName,
		"reused_session": true,
	})
	return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
}

// loadCallbackAuthRequest preserves callback error semantics: unlike login entry,
// an expired request is reported as an internal error here.
func loadCallbackAuthRequest(ctx context.Context, store LoginStore, authRequestID string) (*storage.AuthRequestModel, *CallbackResult) {
	authReq, err := store.GetAuthRequestModel(ctx, authRequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, &CallbackResult{Action: ActionError, Error: "auth_request_not_found", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return nil, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	return authReq, nil
}
