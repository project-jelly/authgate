package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/storage"
)

// logoutParams are the RP-Initiated Logout 1.0 §2 request parameters carried
// through the confirmation form, so the confirmed POST is validated against
// exactly what the relying party sent.
var logoutParams = []string{"id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales"}

// EndSessionProvider is the zitadel OP as the logout handler needs it: the
// request decoder, id_token_hint verification and client lookup, plus the
// issuer the hint's iss claim is checked against. *op.Provider satisfies it.
type EndSessionProvider interface {
	op.SessionEnder
	IssuerFromRequest(r *http.Request) string
}

// LogoutStore resolves and ends browser sessions.
type LogoutStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	// TerminateSession revokes the user's sessions and writes auth.logout. It
	// does not touch refresh tokens (Spec 005 "Logout vs. Revoke").
	TerminateSession(ctx context.Context, userID, clientID string) error
}

type LogoutHandler struct {
	provider EndSessionProvider
	store    LogoutStore
	devMode  bool
	brand    pages.Brand
}

func NewLogoutHandler(provider EndSessionProvider, store LogoutStore, devMode bool, brand pages.Brand) *LogoutHandler {
	return &LogoutHandler{provider: provider, store: store, devMode: devMode, brand: brand}
}

// HandleEndSession handles GET and POST /end_session (OIDC RP-Initiated
// Logout 1.0).
//
// It only ever ends the session of the browser making the request. The OP must
// ask that user first unless the request carries an id_token_hint for them
// (§2, §3); a confirmation page stands in otherwise, and its POST is protected
// by a double-submit CSRF token like /device/approve. A request without a
// session cookie ends nothing: an id_token_hint alone is a token that has been
// handed to relying parties and may be old, not a request from its owner, so it
// does not sign that user out anywhere.
func (h *LogoutHandler) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r = r.WithContext(op.ContextWithIssuer(r.Context(), h.provider.IssuerFromRequest(r)))

	req, err := op.ParseEndSessionRequest(r, h.provider.Decoder())
	if err != nil {
		renderError(w, h.brand, http.StatusBadRequest, "invalid logout request")
		return
	}

	confirmed := r.Method == http.MethodPost && r.PostForm.Get("confirm") != ""
	if confirmed && !h.validLogoutCSRF(r) {
		renderError(w, h.brand, http.StatusForbidden, "CSRF validation failed")
		return
	}

	ctx := r.Context()
	session, err := op.ValidateEndSessionRequest(ctx, req, h.provider)
	if err != nil && req.PostLogoutRedirectURI != "" {
		// A post_logout_redirect_uri the client did not register is never
		// followed, but it must not keep the user signed in either: client
		// libraries send one by default. Drop it and log out to the
		// signed-out page instead.
		slog.InfoContext(ctx, "end_session: ignoring unregistered post_logout_redirect_uri", "error", err)
		req.PostLogoutRedirectURI = ""
		session, err = op.ValidateEndSessionRequest(ctx, req, h.provider)
	}
	if err != nil {
		slog.InfoContext(ctx, "end_session: invalid request", "error", err)
		renderError(w, h.brand, http.StatusBadRequest, "invalid logout request")
		return
	}

	hasSessionCookie := getSessionCookie(r, h.devMode) != ""
	browserUserID, lookupErr := h.browserUserID(ctx, r)
	if lookupErr != nil {
		// The cookie cannot be resolved (e.g. the database is unavailable).
		// Still let the user sign this browser out after confirming, by
		// clearing the cookie; the server-side session is left to expire.
		slog.ErrorContext(ctx, "end_session: resolve browser session", "error", lookupErr)
	}
	browserSignedIn := browserUserID != "" || (hasSessionCookie && lookupErr != nil)
	hintMatchesBrowser := browserUserID != "" && session.UserID == browserUserID

	if browserSignedIn && !hintMatchesBrowser && !confirmed {
		h.renderConfirm(w, r)
		return
	}

	if browserUserID != "" {
		if err := h.store.TerminateSession(ctx, browserUserID, session.ClientID); err != nil {
			slog.ErrorContext(ctx, "end_session: terminate session", "error", err)
			renderError(w, h.brand, http.StatusInternalServerError, "internal error")
			return
		}
	}

	// Expire only cookies the request actually carried. A cross-site POST does
	// not send the Lax session cookie, yet a deleting Set-Cookie on that
	// top-level response would still be honored, signing the visitor out of
	// this browser without any confirmation.
	if hasSessionCookie {
		clearSessionCookie(w, h.devMode)
	}
	if _, err := r.Cookie(csrfCookieName(logoutCSRFCookie, h.devMode)); err == nil {
		h.clearCSRFCookie(w)
	}

	// Redirect only to a post_logout_redirect_uri the OP validated against
	// the client. session.RedirectURI alone is not enough: with no client it
	// still holds the (empty) default merged with state.
	if req.PostLogoutRedirectURI != "" && session.ClientID != "" && session.RedirectURI != "" {
		http.Redirect(w, r, session.RedirectURI, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.RenderLogoutDone(w, pages.LogoutDoneData{Brand: h.brand})
}

// browserUserID returns the user signed in to this browser, or "" when there
// is no live session. A closed account still has a session worth ending.
func (h *LogoutHandler) browserUserID(ctx context.Context, r *http.Request) (string, error) {
	sessionID := getSessionCookie(r, h.devMode)
	if sessionID == "" {
		return "", nil
	}
	user, err := h.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrNotFound) {
		return "", nil
	}
	if user != nil && (err == nil || errors.Is(err, storage.ErrUserAccountClosed)) {
		return user.ID, nil
	}
	return "", err
}

func (h *LogoutHandler) renderConfirm(w http.ResponseWriter, r *http.Request) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		renderError(w, h.brand, http.StatusInternalServerError, "internal error")
		return
	}
	setCSRFCookie(w, logoutCSRFCookie, csrfToken, h.devMode)

	var params []pages.LogoutParam
	for _, name := range logoutParams {
		if v := r.Form.Get(name); v != "" {
			params = append(params, pages.LogoutParam{Name: name, Value: v})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.RenderLogoutConfirm(w, pages.LogoutConfirmData{
		Brand:     h.brand,
		Params:    params,
		CSRFToken: csrfToken,
	})
}

func (h *LogoutHandler) clearCSRFCookie(w http.ResponseWriter) {
	clearCSRFCookie(w, logoutCSRFCookie, h.devMode)
}

// validLogoutCSRF checks the browser's same-origin signal and the
// double-submit token. Both must hold for a confirmed logout POST.
func (h *LogoutHandler) validLogoutCSRF(r *http.Request) bool {
	return sameOriginPost(r, h.devMode) && validCSRFToken(r, logoutCSRFCookie, r.PostForm.Get("csrf_token"), h.devMode)
}
