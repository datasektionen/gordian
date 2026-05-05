package v1

import (
	"net/http"

	"github.com/datasektionen/GOrdian/internal/web"
)

func RegisterRoutes(mux *http.ServeMux, databases web.Databases) {
	mux.Handle("/api/CostCentres", web.Cors(web.Route(databases, apiCostCentres)))
	mux.Handle("/api/CostCentresByYear", web.Cors(web.Route(databases, apiCostCentresByYear)))
	mux.Handle("/api/SecondaryCostCentres", web.Cors(web.Route(databases, apiSecondaryCostCentre)))
	mux.Handle("/api/BudgetLines", web.Cors(web.Route(databases, apiBudgetLine)))

	// Alias
	mux.Handle("/api/v1/CostCentres", web.Cors(web.Route(databases, apiCostCentres)))
	mux.Handle("/api/v1/CostCentresByYear", web.Cors(web.Route(databases, apiCostCentresByYear)))
	mux.Handle("/api/v1/SecondaryCostCentres", web.Cors(web.Route(databases, apiSecondaryCostCentre)))
	mux.Handle("/api/v1/BudgetLines", web.Cors(web.Route(databases, apiBudgetLine)))
}
