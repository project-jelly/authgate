package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// nonceCtxKey carries the expected id_token nonce from the callback request
// into the RP's nonce verifier (registered via WithVerifierOpts/WithNonce).
type nonceCtxKey struct{}

// OIDCProvider uses zitadel/oidc RelyingParty for OIDC Discovery, token exchange, and userinfo.
type OIDCProvider struct {
	name string
	rp   rp.RelyingParty
	// ch is the cookie handler used for the state/PKCE cookies and the
	// per-login nonce cookie. nil when no cookie secret was configured.
	ch              *httphelper.CookieHandler
	nonceCookieName string
}

// Option configures OIDCProvider construction.
type Option func(*options)

type options struct {
	rpOpts       []rp.Option
	internalURL  string
	httpTimeout  time.Duration
	cookieSecret string
	cookieSecure bool
	cookieSet    bool
}

// WithInternalURL rewrites outgoing HTTP requests from issuerURL host to internalURL host.
// Used in Docker/K8s where the browser reaches the IdP at localhost:8082
// but the server reaches it at mock-idp:8082 via internal DNS.
func WithInternalURL(internalURL string) Option {
	return func(o *options) { o.internalURL = internalURL }
}

// WithHTTPTimeout sets outbound HTTP timeout for OIDC discovery/token/userinfo calls.
func WithHTTPTimeout(timeout time.Duration) Option {
	return func(o *options) { o.httpTimeout = timeout }
}

// WithCookieSecret enables the high-level state/PKCE cookie protection. The
// secret seeds the cookie handler's hash and encryption keys (via SHA-256 with
// domain separation). secure=false allows the cookie over plain HTTP (dev mode).
func WithCookieSecret(secret string, secure bool) Option {
	return func(o *options) {
		o.cookieSecret = secret
		o.cookieSecure = secure
		o.cookieSet = true
	}
}

// NewOIDCProvider creates a provider by performing OIDC Discovery on the issuer URL.
func NewOIDCProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURI string, opts ...Option) (*OIDCProvider, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	transport := http.RoundTripper(http.DefaultTransport)
	if o.internalURL != "" {
		issuerParsed, _ := url.Parse(issuerURL)
		internalParsed, _ := url.Parse(o.internalURL)
		if issuerParsed != nil && internalParsed != nil {
			transport = &hostRewriteTransport{
				fromHost:  issuerParsed.Host,
				toHost:    internalParsed.Host,
				toScheme:  internalParsed.Scheme,
				transport: http.DefaultTransport,
			}
		}
	}
	if o.httpTimeout > 0 || o.internalURL != "" {
		client := &http.Client{
			Transport: transport,
		}
		if o.httpTimeout > 0 {
			client.Timeout = o.httpTimeout
		}
		o.rpOpts = append(o.rpOpts, rp.WithHTTPClient(client))
	}

	var ch *httphelper.CookieHandler
	nonceCookieName := "nonce"
	if o.cookieSet {
		if o.cookieSecure {
			nonceCookieName = "__Host-authgate_nonce"
		}
		hashKey := sha256.Sum256([]byte("authgate.upstream.cookie.hash:" + o.cookieSecret))
		encryptKey := sha256.Sum256([]byte("authgate.upstream.cookie.enc:" + o.cookieSecret))
		chOpts := []httphelper.CookieHandlerOpt{httphelper.WithMaxAge(600)}
		if !o.cookieSecure {
			chOpts = append(chOpts, httphelper.WithUnsecure())
		}
		ch = httphelper.NewCookieHandler(hashKey[:], encryptKey[:], chOpts...)
		o.rpOpts = append(o.rpOpts, rp.WithPKCE(ch))
		// Verify the id_token nonce against the per-login value stashed in the
		// request context by Callback (read from the nonce cookie). Binds the
		// id_token to this specific login request (replay/injection defense).
		o.rpOpts = append(o.rpOpts, rp.WithVerifierOpts(rp.WithNonce(func(ctx context.Context) string {
			n, _ := ctx.Value(nonceCtxKey{}).(string)
			return n
		})))
	}

	// Sanitize the high-level handler's failure responses (invalid/missing
	// state cookie, PKCE mismatch, code-exchange error). The library default
	// echoes the internal error string back to the client; replace it with a
	// generic message so upstream OAuth error detail is not disclosed.
	o.rpOpts = append(o.rpOpts, rp.WithUnauthorizedHandler(func(w http.ResponseWriter, _ *http.Request, _ string, _ string) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
	}))

	scopes := []string{"openid", "email", "profile"}
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, issuerURL, clientID, clientSecret, redirectURI, scopes, o.rpOpts...)
	if err != nil {
		return nil, fmt.Errorf("oidc relying party for %s: %w", issuerURL, err)
	}

	return &OIDCProvider{
		name:            deriveProviderName(relyingParty.Issuer()),
		rp:              relyingParty,
		ch:              ch,
		nonceCookieName: nonceCookieName,
	}, nil
}

func (p *OIDCProvider) Name() string { return p.name }

// Redirect sends the user to the upstream IdP, binding state to a CSRF cookie,
// a PKCE challenge cookie, and a per-login nonce cookie (its value is also sent
// as the OIDC `nonce` parameter) via the high-level AuthURLHandler.
func (p *OIDCProvider) Redirect(w http.ResponseWriter, r *http.Request, state string, opts ...RedirectOption) {
	var urlParams []rp.URLParamOpt
	if o := applyRedirectOptions(opts); o.prompt != "" {
		urlParams = append(urlParams, rp.WithPromptURLParam(o.prompt))
	}
	if p.ch != nil {
		nonce, err := generateNonce()
		if err != nil {
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		if err := p.ch.SetCookie(w, p.nonceCookieName, nonce); err != nil {
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		urlParams = append(urlParams, rp.WithURLParam("nonce", nonce))
	}
	rp.AuthURLHandler(func() string { return state }, p.rp, urlParams...).ServeHTTP(w, r)
}

// Callback verifies the state cookie + PKCE + id_token nonce, exchanges the
// code, fetches userinfo, and invokes onSuccess. On failure CodeExchangeHandler
// writes its own error response and onSuccess is not called. A missing or
// invalid nonce cookie is rejected here before CodeExchangeHandler is invoked.
func (p *OIDCProvider) Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo)) {
	if p.ch != nil {
		// Require the expected, authenticated cookie before any code exchange.
		// Never fall back to the unprefixed development cookie in production.
		nonce, err := p.ch.CheckCookie(r, p.nonceCookieName)
		p.ch.DeleteCookie(w, p.nonceCookieName)
		if err != nil || nonce == "" {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), nonceCtxKey{}, nonce))
	}
	cb := rp.UserinfoCallback[*oidc.IDTokenClaims, *oidc.UserInfo](
		func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, _ rp.RelyingParty, info *oidc.UserInfo) {
			onSuccess(w, r, state, mapUserInfo(tokens, info))
		},
	)
	rp.CodeExchangeHandler[*oidc.IDTokenClaims](cb, p.rp).ServeHTTP(w, r)
}

// generateNonce returns a 128-bit URL-safe random nonce.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func mapUserInfo(tokens *oidc.Tokens[*oidc.IDTokenClaims], info *oidc.UserInfo) *UserInfo {
	return &UserInfo{
		Sub:           info.Subject,
		Email:         info.Email,
		EmailVerified: bool(info.EmailVerified),
		Name:          info.Name,
		HostedDomain:  hostedDomain(tokens),
	}
}

// hostedDomain returns Google's hd claim from the ID token only. By the time
// the callback runs, the ID token's signature, issuer, audience, expiry and
// nonce have been verified, and Google documents hd as an ID token claim. The
// userinfo response is not consulted: it carries no signature, and on another
// issuer hd there could be a claim the user controls.
func hostedDomain(tokens *oidc.Tokens[*oidc.IDTokenClaims]) string {
	if tokens != nil && tokens.IDTokenClaims != nil {
		if hd, ok := tokens.IDTokenClaims.Claims["hd"].(string); ok {
			return hd
		}
	}
	return ""
}

// hostRewriteTransport rewrites the host of outgoing HTTP requests.
// Bridges Docker internal DNS (mock-idp:8082) and browser-facing URLs (localhost:8082).
type hostRewriteTransport struct {
	fromHost  string
	toHost    string
	toScheme  string
	transport http.RoundTripper
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.fromHost {
		req = req.Clone(req.Context())
		req.URL.Host = t.toHost
		if t.toScheme != "" {
			req.URL.Scheme = t.toScheme
		}
	}
	return t.transport.RoundTrip(req)
}

// deriveProviderName extracts a short name from the issuer URL.
func deriveProviderName(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	if host == "" {
		return "unknown"
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}
