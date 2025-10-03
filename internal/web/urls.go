package web

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/datasektionen/GOrdian/internal/config"
	"github.com/datasektionen/GOrdian/internal/database"
)

type Databases struct {
	DBCF *sql.DB
	DBGO *sql.DB
}

const (
	loginSessionCookieName = "login-session"
)

//go:embed templates/*.gohtml
var templatesFS embed.FS

//go:embed static/*
var staticFiles embed.FS

var templates *template.Template

func Mount(mux *http.ServeMux, databases Databases) error {
	var err error
	tokenURL := config.GetEnv().LoginFrontendURL + "/login?callback=" + config.GetEnv().ServerURL + "/token?token="
	templates, err = template.New("").Funcs(map[string]any{"formatMoney": formatMoney, "add": add, "sliceContains": sliceContains}).ParseFS(templatesFS, "templates/*.gohtml")
	if err != nil {
		return err
	}
	mux.Handle("/static/", http.FileServerFS(staticFiles))
	mux.Handle("/{$}", authRoute(databases, indexPage, []string{}))
	mux.Handle("/costcentre/{costCentreIDPath}", authRoute(databases, costCentrePage, []string{}))
	mux.Handle("/login", http.RedirectHandler(tokenURL, http.StatusSeeOther))
	mux.Handle("/token", route(databases, tokenPage))
	mux.Handle("/logout", route(databases, logoutPage))
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
		loginCookie, err := r.Cookie(loginSessionCookieName)
		if err != nil {
			if len(requiredPerms) == 0 {
				return handler(w, r, databases, []string{}, false)
			}
			slog.Error("failed to get login cookie", "error", err)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Not logged in"))
			return nil
		}
		loginUser, err := http.Get(config.GetEnv().LoginAPIURL + "/verify/" + loginCookie.Value + "?api_key=" + config.GetEnv().LoginToken)
		if err != nil {
			return fmt.Errorf("no response from login: %v", err)
		}
		defer loginUser.Body.Close()

		if loginUser.StatusCode != 200 {
			return handler(w, r, databases, []string{}, false)
		}
		var loginBody struct {
			User string `json:"user"`
		}
		err = json.NewDecoder(loginUser.Body).Decode(&loginBody)
		if err != nil {
			return fmt.Errorf("failed to decode user body from json: %v", err)
		}

		req, err := http.NewRequest("GET", config.GetEnv().HiveURL+"/user/"+loginBody.User+"/permissions", nil)
		if err != nil {
			return fmt.Errorf("failed to create request for hive: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+ config.GetEnv().HiveToken)
		userPerms, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("no response from hive: %v", err)
		}
		defer userPerms.Body.Close()

		perms, err := decodePerms(userPerms.Body)
		if err != nil {
			return fmt.Errorf("failed to decode perms body from json: %v", err)
		}

		if !sliceContains(requiredPerms, perms...) && len(requiredPerms) != 0 {
			slog.Error("Error from handler", "error", err)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return nil
		}
		return handler(w, r, databases, perms, true)
	})
}

func decodePerms(respBody io.Reader) ([]string, error) {
	type permObj struct {
		ID string `json:"id"`
	}

	var permObjs []permObj
	err := json.NewDecoder(respBody).Decode(&permObjs)
	if err != nil {
		return nil, fmt.Errorf("failed to decode perms body from json: %v", err)
	}

	perms := make([]string, len(permObjs))
	for i, p := range permObjs {
		perms[i] = p.ID
	}
	return perms, nil
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

func tokenPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	sessionCookieVal := r.FormValue("token")
	sessionCookie := http.Cookie{Name: loginSessionCookieName, Value: sessionCookieVal}
	http.SetCookie(w, &sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func logoutPage(w http.ResponseWriter, r *http.Request, databases Databases) error {
	sessionCookie := http.Cookie{Name: loginSessionCookieName, MaxAge: -1}
	http.SetCookie(w, &sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
		"u¡õcÂðÚmäðýòqÔçSegmentation fault (core dumped)",
		"Moo Deng!",
		"Receipts 👏 Proof 👏 Timeline 👏 Screenshots 👏"}
	randomIndex := rand.Intn(len(options))
	return options[randomIndex]
}
