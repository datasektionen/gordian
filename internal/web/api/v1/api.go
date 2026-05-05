package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/datasektionen/GOrdian/internal/web"
)

func apiCostCentresByYear(w http.ResponseWriter, r *http.Request, databases web.Databases) error {
	year := r.FormValue("year")
	if year == "" {
		year = "Alla"
	}

	costCentres, err := web.GetCCList(databases.DBCF, year)
	if err != nil {
		return fmt.Errorf("failed to get cost centres for year %s: %v", year, err)
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(costCentres)
	if err != nil {
		return fmt.Errorf("failed to encode cost centres to json: %v", err)
	}
	return nil
}

func apiCostCentres(w http.ResponseWriter, r *http.Request, databases web.Databases) error {
	costCentres, err := web.GetCostCentres(databases.DBGO)
	if err != nil {
		return fmt.Errorf("failed get scan cost centres information from database: %v", err)
	}
	err = json.NewEncoder(w).Encode(costCentres)
	if err != nil {
		return fmt.Errorf("failed to encode cost centres to json: %v", err)
	}
	return nil
}

func apiSecondaryCostCentre(w http.ResponseWriter, r *http.Request, databases web.Databases) error {
	idCC, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return fmt.Errorf("failed to convert secondary cost centre id to int: %v", err)
	}
	secondaryCostCentres, err := web.GetSecondaryCostCentresByCostCentreID(databases.DBGO, idCC)
	if err != nil {
		return fmt.Errorf("failed get scan sendondary cost centres information from database: %v", err)
	}
	err = json.NewEncoder(w).Encode(secondaryCostCentres)
	if err != nil {
		return fmt.Errorf("failed to encode secondary cost centres to json: %v", err)
	}
	return nil
}

func apiBudgetLine(w http.ResponseWriter, r *http.Request, databases web.Databases) error {
	idSCC, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return fmt.Errorf("failed to convert SCC id fromstring to int: %v", err)
	}
	budgetLines, err := web.GetBudgetLinesBySecondaryCostCentreID(databases.DBGO, idSCC)
	if err != nil {
		return fmt.Errorf("failed get scan budget lines information from database: %v", err)
	}
	err = json.NewEncoder(w).Encode(budgetLines)
	if err != nil {
		return fmt.Errorf("failed to encode budget lines to json: %v", err)
	}
	return nil
}
