package web

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/datasektionen/GOrdian/internal/auth"
	"github.com/datasektionen/GOrdian/internal/config"
)

// A bit awkward to place here but idc
type Databases struct {
	DBCF *sql.DB
	DBGO *sql.DB
}

func Cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		h.ServeHTTP(w, r)
	})
}

func Route(databases Databases, handler func(w http.ResponseWriter, r *http.Request, databases Databases) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler(w, r, databases)
		if err != nil {
			slog.Error("Error from handler", "error", err)
			w.WriteHeader(500)
		}
	})
}

func AuthRoute(databases Databases, handler func(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error, requiredPerms []string) http.Handler {
	return Route(databases, func(w http.ResponseWriter, r *http.Request, databases Databases) error {
		env := config.GetEnv()

		// If no permissions required, check session without redirecting
		if len(requiredPerms) == 0 {
			_, perms, loggedIn := auth.CheckAuth(r, env.AppSecretKey)
			if loggedIn {
				// User is logged in
				return handler(w, r, databases, perms, true)
			}
			// User not logged in, but that's okay - allow access
			return handler(w, r, databases, []string{}, false)
		}

		// Permissions required - must authenticate (will redirect if not logged in)
		user, perms, err := auth.Auth(w, r, oidcConfig.OAuth2Config, env.AppSecretKey)
		if err == nil && user != "" {
			// Successfully authenticated with OIDC
			if !sliceContains(requiredPerms, perms...) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden"))
				return nil
			}
			return handler(w, r, databases, perms, true)
		}

		// If OIDC auth fails, it will have redirected, so return
		return nil
	})
}
