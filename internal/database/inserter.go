package database

import (
	"database/sql"
	"fmt"

	"github.com/datasektionen/GOrdian/internal/excel"
	_ "github.com/lib/pq"
)

func InsertCostCentres(db *sql.DB, costCentres []excel.CostCentre) error {
	var costCentresInsertStatementDynamic = `INSERT INTO "cost_centres"("id", "name", "type") values($1, $2, $3)`
	fmt.Println(costCentresInsertStatementDynamic)
	for _, costCentre := range costCentres {
		_, err := db.Exec(costCentresInsertStatementDynamic, costCentre.CostCentreID, costCentre.CostCentreName, costCentre.CostCentreType)
		if err != nil {
			return fmt.Errorf("failed to insert cost centre in database: %v", err)
		}
	}
	fmt.Println(costCentres[0])
	return nil
}

func InsertSecondaryCostCentres(db *sql.DB, secondaryCostCentres []excel.SecondaryCostCentre) error {
	var secondaryCostCentresInsertStatementDynamic = `INSERT INTO "secondary_cost_centres"("id", "name", "cost_centre_id") values($1, $2, $3)`
	fmt.Println(secondaryCostCentresInsertStatementDynamic)
	for _, secondaryCostCentre := range secondaryCostCentres {
		_, err := db.Exec(secondaryCostCentresInsertStatementDynamic, secondaryCostCentre.SecondaryCostCentreID, secondaryCostCentre.SecondaryCostCentreName, secondaryCostCentre.CostCentreID)
		if err != nil {
			return fmt.Errorf("failed to insert secondary cost centre in database: %v", err)
		}
	}
	fmt.Println(secondaryCostCentres[0])
	return nil
}

func InsertBudgetLines(db *sql.DB, budgetLines []excel.BudgetLine) error {
	var insertBudgetLinesStatementDynamic = `INSERT INTO "budget_lines"("id", "name", "income", "expense", "comment", "account", "secondary_cost_centre_id") values($1, $2, $3, $4, $5, $6, $7)`
	fmt.Println(insertBudgetLinesStatementDynamic)
	for _, budgetLine := range budgetLines {
		_, err := db.Exec(insertBudgetLinesStatementDynamic, budgetLine.BudgetLineID, budgetLine.BudgetLineName, budgetLine.BudgetLineIncome, budgetLine.BudgetLineExpense, budgetLine.BudgetLineComment, budgetLine.BudgetLineAccount, budgetLine.SecondaryCostCentreID)
		if err != nil {
			return fmt.Errorf("failed to insert budget line in database: %v", err)
		}
	}
	fmt.Println(budgetLines[0])
	return nil
}

func WipeDatabase(db *sql.DB) error {
	var truncateStatement = `TRUNCATE "budget_lines" , "cost_centres", "secondary_cost_centres"`
	_, err := db.Exec(truncateStatement)
	if err != nil {
		return fmt.Errorf("failed to truncate database: %v", err)
	}
	return nil
}
