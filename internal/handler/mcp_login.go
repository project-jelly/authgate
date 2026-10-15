package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type MCPLoginHandler struct {
	loginService *service.MCPLoginService
	provider     upstream.Provider
	devMode      bool
	brand        pages.Brand
}

func NewMCPLoginHandler(loginService *service.MCPLoginService, provider upstream.Provider, devMode bool, brand pages.Brand) *MCPLoginHandler {
	return &MCPLoginHandler{
		loginService: loginService,
		provider:     provider,
		devMode:      devMode,
		brand:        brand,
	}
}

// HandleLogin handles GET /mcp/login?authRequestID=xxx
func (h *MCPLoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r, h.devMode)
	info := clientinfo.FromContext(r.Context())

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, info.IP, info.UserAgent)

	if !writeLoginResult(w, r, result, h.provider, h.brand) {
		renderError(w, h.brand, http.StatusInternalServerError, "invalid mcp login action")
	}
}

// HandleCallback handles GET /mcp/callback?code=xxx&state=authRequestID
func (h *MCPLoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	info := clientinfo.FromContext(r.Context())

	h.provider.Callback(w, r, func(w http.ResponseWriter, r *http.Request, state string, userInfo *upstream.UserInfo) {
		result := h.loginService.CompleteMCPLogin(r.Context(), state, userInfo, info.IP, info.UserAgent)

		if !writeCallbackResult(w, r, result, h.devMode, h.brand) {
			renderError(w, h.brand, http.StatusInternalServerError, "invalid mcp callback action")
		}
	})
}
