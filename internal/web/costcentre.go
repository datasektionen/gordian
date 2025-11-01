package web

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/datasektionen/GOrdian/internal/excel"
)

func costCentrePage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	costCentreIDString := r.PathValue("costCentreIDPath")
	costCentreIDInt, err := strconv.Atoi(costCentreIDString)
	if err != nil {
		return fmt.Errorf("failed to convert cost centre id from string to int: %v", err)
	}

	budgetLines, err := getBudgetLinesByCostCentreID(databases.DBGO, costCentreIDInt)
	if err != nil {
		return fmt.Errorf("failed get scan budget line information from database: %v", err)
	}

	//omg
	secondaryCostCentresWithBudgetLinesList := make([]secondaryCostCentresWithBudgetLines, 1)
	currentSecondaryCostCentre := &secondaryCostCentresWithBudgetLinesList[0]
	for _, budgetLine := range budgetLines {
		if currentSecondaryCostCentre.SecondaryCostCentreName != budgetLine.SecondaryCostCentreName {
			secondaryCostCentresWithBudgetLinesList = append(secondaryCostCentresWithBudgetLinesList, secondaryCostCentresWithBudgetLines{
				SecondaryCostCentreName: budgetLine.SecondaryCostCentreName,
				BudgetLines:             []excel.BudgetLine{},
			})
			currentSecondaryCostCentre = &secondaryCostCentresWithBudgetLinesList[len(secondaryCostCentresWithBudgetLinesList)-1]
		}
		currentSecondaryCostCentre.BudgetLines = append(currentSecondaryCostCentre.BudgetLines, budgetLine)
	}
	secondaryCostCentresWithBudgetLinesList = secondaryCostCentresWithBudgetLinesList[1:]

	costCentre, err := getCostCentreByID(databases.DBGO, costCentreIDInt)
	if err != nil {
		return fmt.Errorf("failed get scan cost centre information from database: %v", err)
	}

	//calc the total incomes, expenses and results of all cost centres in the list
	secondaryCostCentresWithBudgetLinesList, err = calculateSecondaryCostCentres(secondaryCostCentresWithBudgetLinesList)
	if err != nil {
		return fmt.Errorf("failed calculate secondary cost centre values: %v", err)
	}

	// Sort secondary cost centres: "internt" items first, then alphabetically
	sortSecondaryCostCentres(secondaryCostCentresWithBudgetLinesList)

	costCentreTotalIncome, costCentreTotalExpense, costCentreTotalResult, err := calculateCostCentre(secondaryCostCentresWithBudgetLinesList)
	if err != nil {
		return fmt.Errorf("failed calculate cost centre values: %v", err)
	}

	if err := templates.ExecuteTemplate(w, "costcentre.gohtml", map[string]any{
		"motd": motdGenerator(),
		"secondaryCostCentresWithBudgetLinesList": secondaryCostCentresWithBudgetLinesList,
		"costCentre":             costCentre,
		"costCentreTotalIncome":  costCentreTotalIncome,
		"costCentreTotalExpense": costCentreTotalExpense,
		"costCentreTotalResult":  costCentreTotalResult,
		"permissions":            perms,
		"loggedIn":               loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func calculateCostCentre(secondaryCostCentresWithBudgetLinesList []secondaryCostCentresWithBudgetLines) (int, int, int, error) {
	var totalIncome int
	var totalExpense int
	for _, sCCWithBudgetLines := range secondaryCostCentresWithBudgetLinesList {
		totalIncome = totalIncome + sCCWithBudgetLines.SecondaryCostCentreTotalIncome
		totalExpense = totalExpense + sCCWithBudgetLines.SecondaryCostCentreTotalExpense
	}
	totalResult := totalIncome + totalExpense

	return totalIncome, totalExpense, totalResult, nil
}

func calculateSecondaryCostCentres(secondaryCostCentresWithBudgetLinesList []secondaryCostCentresWithBudgetLines) ([]secondaryCostCentresWithBudgetLines, error) {
	for index, sCCWithBudgetLines := range secondaryCostCentresWithBudgetLinesList {
		var totalIncome int
		var totalExpense int
		for _, budgetLine := range sCCWithBudgetLines.BudgetLines {
			totalIncome = totalIncome + budgetLine.BudgetLineIncome
			totalExpense = totalExpense + budgetLine.BudgetLineExpense
		}
		secondaryCostCentresWithBudgetLinesList[index].SecondaryCostCentreTotalIncome = totalIncome
		secondaryCostCentresWithBudgetLinesList[index].SecondaryCostCentreTotalExpense = totalExpense
		secondaryCostCentresWithBudgetLinesList[index].SecondaryCostCentreTotalResult = totalIncome + totalExpense
	}
	return secondaryCostCentresWithBudgetLinesList, nil
}

func sortSecondaryCostCentres(list []secondaryCostCentresWithBudgetLines) {
	sort.SliceStable(list, func(i, j int) bool {
		nameI := strings.ToLower(list[i].SecondaryCostCentreName)
		nameJ := strings.ToLower(list[j].SecondaryCostCentreName)
		
		isExactInterntI := nameI == "internt"
		isExactInterntJ := nameJ == "internt"
		containsInterntI := strings.Contains(nameI, "internt")
		containsInterntJ := strings.Contains(nameJ, "internt")
		
		if isExactInterntI && !isExactInterntJ {
			return true
		}
		if !isExactInterntI && isExactInterntJ {
			return false
		}
		
		if containsInterntI && !containsInterntJ {
			return true
		}
		if !containsInterntI && containsInterntJ {
			return false
		}
		
		return nameI < nameJ
	})
}

type secondaryCostCentresWithBudgetLines struct {
	SecondaryCostCentreName         string
	SecondaryCostCentreTotalIncome  int
	SecondaryCostCentreTotalExpense int
	SecondaryCostCentreTotalResult  int
	BudgetLines                     []excel.BudgetLine
}
