package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type LoginHandler struct {
	loginService *service.LoginService
	provider     upstream.Provider
	devMode      bool
	brand        pages.Brand
}

func NewLoginHandler(loginService *service.LoginService, provider upstream.Provider, devMode bool, brand pages.Brand) *LoginHandler {
	return &LoginHandler{
		loginService: loginService,
		provider:     provider,
		devMode:      devMode,
		brand:        brand,
	}
}

// HandleLogin handles GET /login?authRequestID=xxx
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r, h.devMode)
	info := clientinfo.FromContext(r.Context())

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, info.IP, info.UserAgent)

	writeLoginResult(w, r, result, h.provider, h.brand)
}

// HandleCallback handles GET /login/callback?code=xxx&state=authRequestID
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	info := clientinfo.FromContext(r.Context())

	h.provider.Callback(w, r, func(w http.ResponseWriter, r *http.Request, state string, userInfo *upstream.UserInfo) {
		result := h.loginService.CompleteBrowserLogin(r.Context(), state, userInfo, info.IP, info.UserAgent)

		writeCallbackResult(w, r, result, h.devMode, h.brand)
	})
}
