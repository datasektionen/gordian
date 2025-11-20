package database

import (
	"database/sql"
	"fmt"
	"io"

	"github.com/datasektionen/GOrdian/internal/excel"
)

func SaveBudget(fileReader io.Reader, db *sql.DB) error {
	fmt.Println("You have very many money")
	//testBudget := "test/Budget_2025.xlsx"
	costCentres, secondaryCostCentres, budgetLines, err := excel.ReadExcel(fileReader)

	if err != nil {
		return fmt.Errorf("error parsing Excel file: %v", err)
	}

	err = WipeDatabase(db)
	if err != nil {
		return fmt.Errorf("error wiping database: %v", err)
	}

	err = InsertCostCentres(db, costCentres)
	if err != nil {
		return fmt.Errorf("error inserting cost centres in database: %v", err)
	}

	err = InsertSecondaryCostCentres(db, secondaryCostCentres)
	if err != nil {
		return fmt.Errorf("error inserting secondary cost centres in database: %v", err)
	}

	err = InsertBudgetLines(db, budgetLines)
	if err != nil {
		return fmt.Errorf("error inserting budget lines in database: %v", err)
	}

	//fmt.Println(budgetLines)
	//fmt.Println(budgetLines[0].CostCentreName)
	return nil
}
