package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

type AuthHandler struct {
	sessions     *SessionStore
	clientID     string
	redirectURI  string
	authURL      string // browser-facing authorize URL
	tokenURL     string // server-to-server token URL
	userinfoURL  string // server-to-server userinfo URL
	scopes       []string
	cookieSecure bool
}

func NewAuthHandler(sessions *SessionStore, clientID, redirectURI, authURL, tokenURL, userinfoURL string) *AuthHandler {
	redirect, _ := url.Parse(redirectURI)
	return &AuthHandler{
		sessions:     sessions,
		clientID:     clientID,
		redirectURI:  redirectURI,
		authURL:      authURL,
		tokenURL:     tokenURL,
		userinfoURL:  userinfoURL,
		scopes:       []string{"openid", "profile", "email", "offline_access"},
		cookieSecure: redirect != nil && redirect.Scheme == "https",
	}
}

// HandleLogin initiates the OAuth2/PKCE flow.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	sid, sess := h.sessions.Create()

	// Generate PKCE
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Generate state
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	sess.State = state
	sess.CodeVerifier = codeVerifier

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// Build authorize URL
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {h.clientID},
		"redirect_uri":          {h.redirectURI},
		"scope":                 {strings.Join(h.scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	http.Redirect(w, r, h.authURL+"?"+params.Encode(), http.StatusFound)
}

// HandleCallback exchanges the authorization code for tokens.
func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Get session
	sidCookie, err := r.Cookie("sid")
	if err != nil {
		http.Error(w, "no session", 400)
		return
	}
	sess := h.sessions.Get(sidCookie.Value)
	if sess == nil {
		http.Error(w, "invalid session", 400)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	if state != sess.State {
		http.Error(w, "state mismatch", 400)
		return
	}

	// Check for error from authgate
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("auth error: %s — %s", errParam, desc), 400)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", 400)
		return
	}

	// Exchange code for tokens (server-to-server)
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.redirectURI},
		"client_id":     {h.clientID},
		"code_verifier": {sess.CodeVerifier},
	}

	resp, err := http.Post(h.tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		slog.Error("token exchange failed", "error", err)
		http.Error(w, "token exchange failed", 500)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errBody map[string]any
		json.NewDecoder(resp.Body).Decode(&errBody)
		slog.Error("token exchange error", "status", resp.StatusCode, "body", errBody)
		http.Error(w, fmt.Sprintf("token exchange failed: %v", errBody), 500)
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "decode token response failed", 500)
		return
	}

	// Fetch user info from authgate /userinfo
	userInfoReq, _ := http.NewRequest("GET", h.userinfoURL, nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uiResp, err := http.DefaultClient.Do(userInfoReq)
	if err == nil && uiResp.StatusCode == 200 {
		var ui struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			Name          string `json:"name"`
			EmailVerified bool   `json:"email_verified"`
		}
		json.NewDecoder(uiResp.Body).Decode(&ui)
		uiResp.Body.Close()
		sess.UserID = ui.Sub
		sess.Email = ui.Email
		sess.Name = ui.Name
	}

	// Store tokens
	sess.RefreshToken = tokenResp.RefreshToken
	sess.State = ""        // consumed
	sess.CodeVerifier = "" // consumed

	// Set access_token as httpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   tokenResp.ExpiresIn,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogout clears the session and cookies.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		h.sessions.Delete(c.Value)
	}

	// Clear cookies
	http.SetCookie(w, &http.Cookie{
		Name: "access_token", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// RefreshAccessToken attempts to refresh the access token using the stored refresh token.
func (h *AuthHandler) RefreshAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	sidCookie, err := r.Cookie("sid")
	if err != nil {
		return "", false
	}
	sess := h.sessions.Get(sidCookie.Value)
	if sess == nil || sess.RefreshToken == "" {
		return "", false
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sess.RefreshToken},
		"client_id":     {h.clientID},
	}

	resp, err := http.Post(h.tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", false
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", false
	}

	// Update stored refresh token (rotation)
	sess.RefreshToken = tokenResp.RefreshToken

	// Update access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   tokenResp.ExpiresIn,
	})

	return tokenResp.AccessToken, true
}
