package web

import (
	"database/sql"
	"fmt"

	"github.com/datasektionen/GOrdian/internal/excel"
)

func getBudgetLinesByCostCentreID(db *sql.DB, costCentreID int) ([]excel.BudgetLine, error) {
	var budgetLinesGetStatementStatic = `
		SELECT 
    		budget_lines.id,
    		budget_lines.name,
    		income,
			expense,
			comment,
			account,
			secondary_cost_centres.id,
			secondary_cost_centres.name
		FROM budget_lines
		JOIN secondary_cost_centres ON secondary_cost_centres.id = secondary_cost_centre_id
		WHERE cost_centre_id = $1
		ORDER BY secondary_cost_centre_id
	`
	result, err := db.Query(budgetLinesGetStatementStatic, costCentreID)
	if err != nil {
		return nil, fmt.Errorf("failed to get budget lines from database: %v", err)
	}
	var budgetLines []excel.BudgetLine
	for result.Next() {
		var budgetLine excel.BudgetLine

		err := result.Scan(
			&budgetLine.BudgetLineID,
			&budgetLine.BudgetLineName,
			&budgetLine.BudgetLineIncome,
			&budgetLine.BudgetLineExpense,
			&budgetLine.BudgetLineComment,
			&budgetLine.BudgetLineAccount,
			&budgetLine.SecondaryCostCentreID,
			&budgetLine.SecondaryCostCentreName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan budget line from query result: %v", err)
		}
		budgetLines = append(budgetLines, budgetLine)
	}
	return budgetLines, nil
}

func getCostCentres(db *sql.DB) ([]excel.CostCentre, error) {
	var costCentresGetStatementStatic = `SELECT id, name, type FROM cost_centres ORDER BY name`
	result, err := db.Query(costCentresGetStatementStatic)
	if err != nil {
		return nil, fmt.Errorf("failed to get cost centres from database: %v", err)
	}
	var costCentres []excel.CostCentre
	for result.Next() {
		var costCentre excel.CostCentre

		err := result.Scan(&costCentre.CostCentreID, &costCentre.CostCentreName, &costCentre.CostCentreType)
		if err != nil {
			return nil, fmt.Errorf("failed to scan cost centre from query result: %v", err)
		}
		costCentres = append(costCentres, costCentre)
	}
	return costCentres, nil
}

func getCostCentreByID(db *sql.DB, costCentreID int) (excel.CostCentre, error) {
	var costCentreGetStatementStatic = `SELECT id, name, type FROM cost_centres WHERE id = $1`
	result := db.QueryRow(costCentreGetStatementStatic, costCentreID)
	var costCentre excel.CostCentre
	err := result.Scan(&costCentre.CostCentreID, &costCentre.CostCentreName, &costCentre.CostCentreType)
	if err != nil {
		return excel.CostCentre{}, fmt.Errorf("failed to scan cost centre from query result: %v", err)
	}
	return costCentre, nil
}

func getSecondaryCostCentresByCostCentreID(db *sql.DB, costCentreID int) ([]excel.SecondaryCostCentre, error) {
	var SecondaryCostCentresGetStatementStatic = `
		SELECT 
    		id,
    		name,
    		cost_centre_id
		FROM secondary_cost_centres
		WHERE cost_centre_id = $1
		ORDER BY id
	`
	result, err := db.Query(SecondaryCostCentresGetStatementStatic, costCentreID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secondary cost centres from database: %v", err)
	}
	var secondaryCostCentres []excel.SecondaryCostCentre
	for result.Next() {
		var secondaryCostCentre excel.SecondaryCostCentre

		err := result.Scan(
			&secondaryCostCentre.SecondaryCostCentreID,
			&secondaryCostCentre.SecondaryCostCentreName,
			&secondaryCostCentre.CostCentreID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secondary cost centre from query result: %v", err)
		}
		secondaryCostCentres = append(secondaryCostCentres, secondaryCostCentre)
	}
	return secondaryCostCentres, nil
}

func getBudgetLinesBySecondaryCostCentreID(db *sql.DB, secondaryCostCentreID int) ([]excel.BudgetLine, error) {
	var budgetLinesGetStatementStatic = `
		SELECT 
    		id,
    		name,
    		income,
			expense,
			comment,
			account,
			secondary_cost_centre_id
		FROM budget_lines
		WHERE secondary_cost_centre_id = $1
		ORDER BY id
	`
	result, err := db.Query(budgetLinesGetStatementStatic, secondaryCostCentreID)
	if err != nil {
		return nil, fmt.Errorf("failed to get budgetlines from database: %v", err)
	}
	var budgetLines []excel.BudgetLine
	for result.Next() {
		var budgetLine excel.BudgetLine

		err := result.Scan(
			&budgetLine.BudgetLineID,
			&budgetLine.BudgetLineName,
			&budgetLine.BudgetLineIncome,
			&budgetLine.BudgetLineExpense,
			&budgetLine.BudgetLineComment,
			&budgetLine.BudgetLineAccount,
			&budgetLine.SecondaryCostCentreID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan budget line from query result: %v", err)
		}
		budgetLines = append(budgetLines, budgetLine)
	}
	return budgetLines, nil
}
