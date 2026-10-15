package handler

import "net/http"

// Production never accepts the unprefixed development name: a sibling host
// could otherwise inject a parent-domain cookie under that name.
func sessionCookieName(devMode bool) string {
	if devMode {
		return "authgate_session"
	}
	return "__Host-authgate_session"
}

// setSessionCookie issues the browser session.
//
// SameSite is Lax rather than Strict, and it has to be. Every login ends with
// the upstream IdP redirecting to one of our callbacks, which mints the
// session and immediately redirects on — to /device?user_code=… for the device
// flow. WebKit decides whether that final hop is same-site by looking at the
// whole redirect chain, and the chain was started cross-site by the IdP, so a
// Strict cookie is withheld there. The device page then sees no session and
// bounces back to the IdP, which signs the user in again: the flow could not
// be completed in Safari at all. Chromium updates its site-for-cookies per
// hop and does send a Strict cookie, which is why this only ever broke on one
// engine. See internal/handler/session_cookie_test.go.
//
// Lax costs little here. It only adds the cookie to top-level cross-site GET
// navigations, and no GET endpoint acts on its own: /device merely renders the
// consent screen, and the state-changing POST /device/approve is guarded by
// the same-origin check and the double-submit __Host-device_csrf cookie, which
// stays Strict (see csrf.go).
func setSessionCookie(w http.ResponseWriter, sessionID string, devMode bool) {
	//nolint:gosec // Secure=false is allowed only in explicit DEV_MODE for localhost development.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(devMode),
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !devMode,
	})
}

// clearSessionCookie expires the browser session on logout. Every attribute
// but the value and MaxAge must match setSessionCookie, or the browser treats
// it as a different cookie and keeps the session.
func clearSessionCookie(w http.ResponseWriter, devMode bool) {
	//nolint:gosec // Secure=false is allowed only in explicit DEV_MODE for localhost development.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(devMode),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !devMode,
	})
}

func getSessionCookie(r *http.Request, devMode bool) string {
	c, err := r.Cookie(sessionCookieName(devMode))
	if err != nil {
		return ""
	}
	return c.Value
}
