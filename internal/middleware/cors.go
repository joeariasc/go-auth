package middleware

import (
	"net/http"
	"slices"
)

func NewCORSMiddleware(allowedOrigins []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// If the origin is in our allowed list, set it specifically
			if origin != "" && slices.Contains(allowedOrigins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(allowedOrigins) > 0 {
				// If we have allowed origins but this one isn't in the list,
				// set it to the first allowed origin as a fallback
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigins[0])
			}

			// Set other CORS headers
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-Fingerprint")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
