package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type DeviceHandler struct {
	deviceService *service.DeviceService
	provider      upstream.Provider
	devMode       bool
	brand         pages.Brand
}

func NewDeviceHandler(deviceService *service.DeviceService, provider upstream.Provider, devMode bool, brand pages.Brand) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		provider:      provider,
		devMode:       devMode,
		brand:         brand,
	}
}

// HandleDevicePage handles GET /device and GET /device?user_code=XXXX
func (h *DeviceHandler) HandleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	sessionID := getSessionCookie(r, h.devMode)

	result := h.deviceService.HandleDevicePage(r.Context(), userCode, sessionID)

	switch result.Action {
	case service.DeviceShowEntry:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pages.RenderDeviceEntry(w, pages.DeviceEntryData{
			Brand:    h.brand,
			UserCode: userCode,
			Error:    result.Error,
		})

	case service.DeviceShowApprove:
		csrfToken, err := generateCSRFToken()
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: http.StatusInternalServerError, Message: "internal error"})
			return
		}
		setCSRFCookie(w, deviceCSRFCookie, csrfToken, h.devMode)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pages.RenderDeviceApprove(w, pages.DeviceApproveData{
			Brand:     h.brand,
			UserCode:  result.UserCode,
			CSRFToken: csrfToken,
		})

	case service.DeviceRedirectIdP:
		h.provider.Redirect(w, r, result.UserCode) // UserCode holds the state (user_code)

	case service.DeviceError:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(result.ErrorCode)
		_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: result.ErrorCode, Message: result.Error})
	}
}

// HandleDeviceCallback handles GET /device/auth/callback?code=xxx&state=user_code
func (h *DeviceHandler) HandleDeviceCallback(w http.ResponseWriter, r *http.Request) {
	info := clientinfo.FromContext(r.Context())

	h.provider.Callback(w, r, func(w http.ResponseWriter, r *http.Request, state string, userInfo *upstream.UserInfo) {
		result := h.deviceService.CompleteDeviceLogin(r.Context(), state, userInfo, info.IP, info.UserAgent)

		switch result.Action {
		case service.DeviceRedirectBack:
			if result.SessionID != "" {
				setSessionCookie(w, result.SessionID, h.devMode)
			}
			//nolint:gosec // Internal redirect to the fixed device endpoint with a service-issued user code.
			http.Redirect(w, r, "/device?user_code="+result.UserCode, http.StatusFound)

		case service.DeviceError:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(result.ErrorCode)
			_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: result.ErrorCode, Message: result.Error})
		}
	})
}

// HandleDeviceApprove handles POST /device/approve
func (h *DeviceHandler) HandleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: 400, Message: "invalid form"})
		return
	}

	// CSRF: the browser's own same-origin signal first, then the double-submit
	// token. Either one failing means this POST did not come from the approval
	// page authgate rendered.
	if !sameOriginPost(r, h.devMode) || !validCSRFToken(r, deviceCSRFCookie, r.FormValue("csrf_token"), h.devMode) {
		w.WriteHeader(http.StatusForbidden)
		_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: 403, Message: "CSRF validation failed"})
		return
	}

	userCode := r.FormValue("user_code")
	action := r.FormValue("action")
	sessionID := getSessionCookie(r, h.devMode)
	info := clientinfo.FromContext(r.Context())

	result := h.deviceService.HandleDeviceApprove(r.Context(), userCode, action, sessionID, info.IP, info.UserAgent)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !result.Success && result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
	}
	_ = pages.RenderResult(w, pages.ResultData{
		Brand:   h.brand,
		Success: result.Success,
		Message: result.Message,
	})
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
