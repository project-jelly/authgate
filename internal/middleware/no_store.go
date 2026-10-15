package middleware

import "net/http"

// NoStore prevents token responses from being retained by HTTP caches (RFC
// 6749 §5.1). Register it outside rate limiting and token response rewriting
// so early errors and rewritten responses carry the same cache policy.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}
