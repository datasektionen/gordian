package web

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/datasektionen/GOrdian/internal/excel"
)

func indexPage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	costCentres, err := getCostCentres(databases.DBGO)
	if err != nil {
		return fmt.Errorf("failed get scan cost centre information from database: %v", err)
	}
	committeeCostCentres, partitionCostCentres, projectCostCentres, otherCostCentres, err := splitCostCentresOnType(costCentres)
	if err != nil {
		return fmt.Errorf("failed to split cost centres on type: %v", err)
	}

	//Mörkläggning av mottagningens budget
	darkeningResp, err := http.Get("https://darkmode.datasektionen.se/")
	if err != nil {
		slog.Error("Failed to get status from darkmode", "error", err)
		return fmt.Errorf(": %v", err)
	}
	defer darkeningResp.Body.Close()

	if darkeningResp.StatusCode != http.StatusOK {
		slog.Error("Status error from darkmode", "error", darkeningResp.StatusCode)
	}

	darkeningBody, err := io.ReadAll(darkeningResp.Body)
	if err != nil {
		slog.Error("Failed to read body", "error", err)
	}

	darkeningValue, err := strconv.ParseBool(string(darkeningBody))
	if err != nil {
		slog.Error("Failed to parse bool", "error", err)
	}

	if darkeningValue {
		for index, committeeCostCentre := range committeeCostCentres {
			if committeeCostCentre.CostCentreName == "Mottagningen" {
				committeeCostCentres = append(committeeCostCentres[:index], committeeCostCentres[index+1:]...)
				break
			}
		}
	}
	//end of mörkläggning

	if err := templates.ExecuteTemplate(w, "index.gohtml", map[string]any{
		"motd":        motdGenerator(),
		"committees":  committeeCostCentres,
		"partitions":  partitionCostCentres,
		"projects":    projectCostCentres,
		"others":      otherCostCentres,
		"permissions": perms,
		"loggedIn":    loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func splitCostCentresOnType(costCentres []excel.CostCentre) ([]excel.CostCentre, []excel.CostCentre, []excel.CostCentre, []excel.CostCentre, error) {
	var committeeCostCentres []excel.CostCentre
	var partitionCostCentres []excel.CostCentre
	var projectCostCentres []excel.CostCentre
	var otherCostCentres []excel.CostCentre
	for _, costCentre := range costCentres {
		switch costCentre.CostCentreType {
		case "committee":
			committeeCostCentres = append(committeeCostCentres, costCentre)
		case "partition":
			partitionCostCentres = append(partitionCostCentres, costCentre)
		case "project":
			projectCostCentres = append(projectCostCentres, costCentre)
		case "projectX":
			projectCostCentres = append(projectCostCentres, costCentre)
		case "other":
			otherCostCentres = append(otherCostCentres, costCentre)
		default:
			return nil, nil, nil, nil, fmt.Errorf("faulty cost centre type found when splitting")
		}
	}
	return committeeCostCentres, partitionCostCentres, projectCostCentres, otherCostCentres, nil
}
