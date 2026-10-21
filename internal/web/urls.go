package web

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"

	auth "github.com/datasektionen/GO-auth-yourself"
	"github.com/datasektionen/GOrdian/internal/database"
)

type Databases struct {
	DBCF *sql.DB
	DBGO *sql.DB
}

//go:embed templates/*.gohtml
var templatesFS embed.FS

//go:embed static/*
var staticFiles embed.FS

var templates *template.Template

func NewHandler(databases Databases) (http.Handler, error) {
	authConfig := auth.ConfigFromEnv()
	authenticator, err := auth.New(context.Background(), authConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth (APP_SECRET_KEY: %d bytes): %w", len(authConfig.SecretKey), err)
	}

	templates, err = template.New("").Funcs(map[string]any{"formatMoney": formatMoney, "add": add}).ParseFS(templatesFS, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServerFS(staticFiles))
	mux.Handle("/{$}", route(databases, indexPage))
	mux.Handle("/costcentre/{costCentreIDPath}", route(databases, costCentrePage))

	authenticator.MountAuthRoutes(mux)
	mux.Handle("/admin", authenticator.RequirePermissions("admin", "view-all")(route(databases, adminPage)))
	mux.Handle("/admin/upload", authenticator.RequirePermissions("admin")(route(databases, uploadPage)))
	mux.Handle("/api/CostCentres", cors(route(databases, apiCostCentres)))
	mux.Handle("/api/CostCentresByYear", cors(route(databases, apiCostCentresByYear)))
	mux.Handle("/api/SecondaryCostCentres", cors(route(databases, apiSecondaryCostCentre)))
	mux.Handle("/api/BudgetLines", cors(route(databases, apiBudgetLine)))
	mux.Handle("/framebudget", route(databases, framePage))
	mux.Handle("/history", route(databases, historyPage))

	if databases.DBCF != nil {
		mux.Handle("/resultreport", route(databases, reportPage))
	} else {
		mux.HandleFunc("/resultreport", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Cannot load resultatrapport: cashflow database not initialized", http.StatusServiceUnavailable)
		})
	}

	// Makes the logged-in user available to every route through auth.FromContext.
	handler := authenticator.SessionMiddleware(mux)
	return http.NewCrossOriginProtection().Handler(handler), nil
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

func adminPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	user, loggedIn := auth.FromContext(r.Context())
	if err := templates.ExecuteTemplate(w, "admin.gohtml", map[string]any{
		"motd":     motdGenerator(),
		"auth":     user,
		"loggedIn": loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func historyPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	user, loggedIn := auth.FromContext(r.Context())
	if err := templates.ExecuteTemplate(w, "history.gohtml", map[string]any{
		"motd":     motdGenerator(),
		"auth":     user,
		"loggedIn": loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func uploadPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
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
		"Receipts 👏 Proof 👏 Timeline 👏 Screenshots 👏",
		"dAnkan is watching you"}
	randomIndex := rand.Intn(len(options))
	return options[randomIndex]
}
