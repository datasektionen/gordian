package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"strconv"

	"github.com/datasektionen/GOrdian/internal/auth"
	"github.com/datasektionen/GOrdian/internal/config"
	"github.com/datasektionen/GOrdian/internal/database"
)

type Databases struct {
	DBCF *sql.DB
	DBGO *sql.DB
}

const (
	sessionCookieName = "session"
	stateCookieName   = "oauth_state"
)

var oidcConfig *auth.OIDCConfig

// isSecureContext determines if cookies should use Secure flag based on redirect URL
func isSecureContext() bool {
	env := config.GetEnv()
	// Check if redirect URL starts with https://
	if len(env.OIDCRedirectURL) > 8 && env.OIDCRedirectURL[:8] == "https://" {
		return true
	}
	return false
}

//go:embed templates/*.gohtml
var templatesFS embed.FS

//go:embed static/*
var staticFiles embed.FS

var templates *template.Template

func Mount(mux *http.ServeMux, databases Databases) error {
	var err error
	
	// Initialize OIDC
	ctx := context.Background()
	env := config.GetEnv()
	
	oidcConfig, err = auth.InitOIDC(ctx, env.OIDCProvider, env.OIDCClientID, env.OIDCClientSecret, env.OIDCRedirectURL)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC: %w", err)
	}
	slog.Info("OIDC authentication enabled")
	
	templates, err = template.New("").Funcs(map[string]any{"formatMoney": formatMoney, "add": add, "sliceContains": sliceContains}).ParseFS(templatesFS, "templates/*.gohtml")
	if err != nil {
		return err
	}
	mux.Handle("/static/", http.FileServerFS(staticFiles))
	mux.Handle("/{$}", authRoute(databases, indexPage, []string{}))
	mux.Handle("/costcentre/{costCentreIDPath}", authRoute(databases, costCentrePage, []string{}))
	
	// OIDC Authentication routes
	mux.Handle("/login", route(databases, oidcLoginPage))
	mux.Handle("/auth/callback", route(databases, oidcCallbackPage))
	mux.Handle("/logout", route(databases, oidcLogoutPage))
	mux.Handle("/admin", authRoute(databases, adminPage, []string{"admin", "view-all"}))
	mux.Handle("/admin/upload", authRoute(databases, uploadPage, []string{"admin"}))
	mux.Handle("/api/CostCentres", cors(route(databases, apiCostCentres)))
	mux.Handle("/api/CostCentresByYear", cors(route(databases, apiCostCentresByYear)))
	mux.Handle("/api/SecondaryCostCentres", cors(route(databases, apiSecondaryCostCentre)))
	mux.Handle("/api/BudgetLines", cors(route(databases, apiBudgetLine)))
	mux.Handle("/framebudget", authRoute(databases, framePage, []string{}))
	mux.Handle("/history", authRoute(databases, historyPage, []string{}))

	if databases.DBCF != nil {
		mux.Handle("/resultreport", authRoute(databases, reportPage, []string{}))
	} else {
		mux.HandleFunc("/resultreport", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Cannot load resultatrapport: cashflow database not initialized", http.StatusServiceUnavailable)
		})
	}


	return nil
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		h.ServeHTTP(w, r)
	})
}

func route(databases Databases, handler func(w http.ResponseWriter, r *http.Request, databases Databases) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler(w, r, databases)
		if err != nil {
			slog.Error("Error from handler", "error", err)
			w.WriteHeader(500)
			w.Write([]byte("Internal server error"))
		}
	})
}

func authRoute(databases Databases, handler func(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error, requiredPerms []string) http.Handler {
	return route(databases, func(w http.ResponseWriter, r *http.Request, databases Databases) error {
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

func sliceContains(list1 []string, list2 ...string) bool {
	// Iterate through list1 and check if one object is present in list2
	for _, obj1 := range list1 {
		for _, obj2 := range list2 {
			if obj1 == obj2 {
				return true
			}
		}
	}
	return false
}

func add(x int, y int) int {
	return x + y
}

func formatMoney(value int) string {
	numStr := strconv.Itoa(value)
	length := len(numStr)
	var result string

	for i := 0; i < length; i++ {
		if i > 0 && (length-i)%3 == 0 {
			result += " "
		}
		result += string(numStr[i])
	}

	return result
}

func adminPage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	if err := templates.ExecuteTemplate(w, "admin.gohtml", map[string]any{
		"motd":        motdGenerator(),
		"permissions": perms,
		"loggedIn":    loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func historyPage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	if err := templates.ExecuteTemplate(w, "history.gohtml", map[string]any{
		"motd":        motdGenerator(),
		"permissions": perms,
		"loggedIn":    loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func uploadPage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	file, _, err := r.FormFile("budgetFile")
	if err != nil {
		return fmt.Errorf("could not read file from form: %w", err)
	}
	err = database.SaveBudget(file, databases.DBGO)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
	return nil
}

func motdGenerator() string {
	options := []string{
		"You have very many money:",
		"Sjunde gången gillt:",
		"Kassörens bästa vän:",
		"Brought to you by FIPL consulting:",
		"Kom på hackerkvällarna!",
		"12345690,+",
		"u¡õcÂðÚmäðýòqÔçSegmentation fault (core dumped)",
		"Moo Deng!",
		"Money is really just, like, a social construct, man",
		"Receipts 👏 Proof 👏 Timeline 👏 Screenshots 👏"}
	randomIndex := mathrand.Intn(len(options))
	return options[randomIndex]
}

// generateSecureState generates a cryptographically secure random state string
func generateSecureState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// OIDC handlers
func oidcLoginPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	if oidcConfig == nil {
		return fmt.Errorf("OIDC not configured")
	}
	
	// Generate a secure random state parameter
	state, err := generateSecureState()
	if err != nil {
		return fmt.Errorf("failed to generate state: %w", err)
	}
	
	// Store state in a secure cookie
	stateCookie := http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		HttpOnly: true,
		Secure:   isSecureContext(), // Only use Secure flag with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes - short-lived for security
		Path:     "/",
	}
	http.SetCookie(w, &stateCookie)
	
	http.Redirect(w, r, oidcConfig.OAuth2Config.AuthCodeURL(state), http.StatusFound)
	return nil
}

func oidcCallbackPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	if oidcConfig == nil {
		return fmt.Errorf("OIDC not configured")
	}
	
	// Validate state parameter to prevent CSRF attacks
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil {
		slog.Error("State cookie not found", "error", err)
		return fmt.Errorf("invalid state: cookie not found")
	}
	
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" || stateParam != stateCookie.Value {
		slog.Error("State mismatch", "expected", stateCookie.Value, "got", stateParam)
		return fmt.Errorf("invalid state: CSRF check failed")
	}
	
	// Clear the state cookie after validation
	clearStateCookie := http.Cookie{
		Name:     stateCookieName,
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &clearStateCookie)
	
	env := config.GetEnv()
	ctx := context.Background()
	
	// Handle the callback and get the user
	user, err := oidcConfig.HandleCallback(ctx, r)
	if err != nil {
		slog.Error("OIDC callback failed", "error", err)
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	// Fetch permissions from Hive
	perms, err := auth.GetPermissionsFromHive(user, env.HiveURL, env.HiveToken)
	if err != nil {
		slog.Warn("Failed to get permissions from Hive", "error", err, "user", user)
		perms = []string{} // Continue with no permissions
	}
	
	// Create session token
	tokenString, err := auth.CreateSessionToken(user, perms, env.AppSecretKey)
	if err != nil {
		return fmt.Errorf("failed to create session token: %w", err)
	}
	
	// Set session cookie
	sessionCookie := http.Cookie{
		Name:     sessionCookieName,
		Value:    tokenString,
		HttpOnly: true,
		Secure:   isSecureContext(), // Only use Secure flag with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7, // 7 days
		Path:     "/",
	}
	http.SetCookie(w, &sessionCookie)
	
	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func oidcLogoutPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	// Clear session cookie
	sessionCookie := http.Cookie{
		Name:     sessionCookieName,
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}
