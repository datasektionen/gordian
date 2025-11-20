package excel

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

type CostCentre struct {
	CostCentreID   int
	CostCentreName string
	CostCentreType string
}

type SecondaryCostCentre struct {
	CostCentreID            int
	CostCentreName          string `json:",omitempty"`
	CostCentreType          string `json:",omitempty"`
	SecondaryCostCentreID   int
	SecondaryCostCentreName string
}

type BudgetLine struct {
	CostCentreID            int    `json:",omitempty"`
	CostCentreName          string `json:",omitempty"`
	CostCentreType          string `json:",omitempty"`
	SecondaryCostCentreID   int
	SecondaryCostCentreName string `json:",omitempty"`
	BudgetLineID            int
	BudgetLineName          string
	BudgetLineAccount       string
	BudgetLineIncome        int
	BudgetLineExpense       int
	BudgetLineComment       string
}

const (
	columnSecondaryCostCentres = 1
	columnBudgetLineNames      = 2
	columnAccount              = 3
	columnIncome               = 4
	columnExpense              = 5
	columnComment              = 7
	costCentreNameCell         = "A2"
	costCentreTypeCell         = "A3"
)

func ReadExcel(fileReader io.Reader) ([]CostCentre, []SecondaryCostCentre, []BudgetLine, error) {
	//file, err := excelize.OpenFile(path)
	file, err := excelize.OpenReader(fileReader)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open Excel file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			_ = fmt.Errorf("error closing Excel file: %v", err)
		}
	}()

	sheets := readSheets(file)

	var costCentres []CostCentre
	var secondaryCostCentres []SecondaryCostCentre
	var budgetLines []BudgetLine

	var secondaryCostCentreIDCounter = 0
	var budgetLineIDCounter = 0

	var omegaError error

	//[1:] excludes the first sheet
	for sheetIndex, sheetName := range sheets[1:] {

		fmt.Printf("Sheet Name: %s, Index %d\n", sheetName, sheetIndex)

		//read all rows and columns of a sheet
		_, err := readRows(sheetName, file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read rows for sheet %s: %v", sheetName, err)
		}

		cols, err := readColumns(sheetName, file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read columns for sheet %s: %v", sheetName, err)
		}

		costCentreName, err := readCell(file, sheetName, costCentreNameCell)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read cell for sheet %s: %v", sheetName, err)
		}

		costCentreType, err := readCell(file, sheetName, costCentreTypeCell)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read cell for sheet %s: %v", sheetName, err)
		}

		convertedCostCentreType, err := convertCostCentreTypeToEnglish(costCentreType)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to convert cost centre type \"%s\" to english: %v", costCentreType, err)
		}

		//Create costCentre object
		costCentre := CostCentre{
			CostCentreID:   sheetIndex,
			CostCentreName: costCentreName,
			CostCentreType: convertedCostCentreType,
		}

		//append to costCentres slice
		costCentres = append(costCentres, costCentre)

		//get indices of all secondary cost centres
		var SecondaryCostCentreIndices []int
		SecondaryCostCentreIndices = findSecondaryCostCentreIndices(cols)

		//iterates over the found secondary cost centres indices
		for _, secondaryCostCentreIndex := range SecondaryCostCentreIndices {
			secondaryCostCentreName := getSecondaryCostCentreByIndex(secondaryCostCentreIndex, cols)

			//Create secondaryCostCentre object
			secondaryCostCentre := SecondaryCostCentre{
				CostCentreID:            sheetIndex,
				CostCentreName:          costCentreName,
				CostCentreType:          convertedCostCentreType,
				SecondaryCostCentreID:   secondaryCostCentreIDCounter,
				SecondaryCostCentreName: secondaryCostCentreName,
			}

			//append to costCentres slice
			secondaryCostCentres = append(secondaryCostCentres, secondaryCostCentre)

			//loops over the column containing budget lines. Starting one row below the current sec cost centre
			for colCellIndex, budgetLineName := range cols[columnBudgetLineNames][secondaryCostCentreIndex+1:] {
				if budgetLineName == "" {
					//When encountering an empty cell we have gone through all relevant budget lines
					fmt.Print("\n")
					break
				} else {
					budgetLineAccount, budgetLineIncomeString, budgetLineExpenseString, budgetLineComment :=
						getBudgetLineData(secondaryCostCentreIndex, colCellIndex, cols)

					budgetLineIncome, err := sanitizeBudgetValue(budgetLineIncomeString, secondaryCostCentre)
					if err != nil {
						omegaError = errors.Join(omegaError, err)
						//return nil, nil, nil, fmt.Errorf("failed to sanitize budget value: %v", err)
					}

					budgetLineExpense, err := sanitizeBudgetValue(budgetLineExpenseString, secondaryCostCentre)
					if err != nil {
						omegaError = errors.Join(omegaError, err)
						//return nil, nil, nil, fmt.Errorf("failed to sanitize budget value: %v", err)
					}

					//create BudgetLine object
					budgetLine := BudgetLine{
						CostCentreID:            sheetIndex,
						CostCentreName:          costCentreName,
						CostCentreType:          convertedCostCentreType,
						SecondaryCostCentreID:   secondaryCostCentreIDCounter,
						SecondaryCostCentreName: secondaryCostCentreName,
						BudgetLineID:            budgetLineIDCounter,
						BudgetLineName:          budgetLineName,
						BudgetLineAccount:       budgetLineAccount,
						BudgetLineIncome:        budgetLineIncome,
						BudgetLineExpense:       budgetLineExpense,
						BudgetLineComment:       budgetLineComment,
					}
					//append to budgetLines slice
					budgetLines = append(budgetLines, budgetLine)

					//Print all relevant data
					//We already have sheetName from outmost loop and secondaryCostCentreName from inner loop
					//0s are gotten without kr for some reason
					fmt.Print(strconv.Itoa(sheetIndex) + " ")
					fmt.Print(costCentreName + " ")
					fmt.Print(convertedCostCentreType + "\t")
					fmt.Print(strconv.Itoa(secondaryCostCentreIDCounter) + " ")
					fmt.Print(secondaryCostCentreName + "\t")
					fmt.Print(strconv.Itoa(budgetLineIDCounter) + " ")
					fmt.Print(budgetLineName + " ")
					fmt.Print(budgetLineAccount + "\t")
					fmt.Print(strconv.Itoa(budgetLineIncome) + " ")
					fmt.Print(strconv.Itoa(budgetLineExpense) + "\t")
					fmt.Print(budgetLineComment)
					fmt.Print("\n")

					budgetLineIDCounter++
				}
			}
			secondaryCostCentreIDCounter++
		}
	}
	if omegaError != nil {
		return nil, nil, nil, fmt.Errorf("failed to sanitize budget value(s): \n%w", omegaError)
	}
	return costCentres, secondaryCostCentres, budgetLines, nil
}

func readCell(file *excelize.File, sheetName string, targetCell string) (string, error) {

	cellContent, err := file.GetCellValue(sheetName, targetCell)

	if err != nil {
		return "", fmt.Errorf("failed to read cell: %v", err)
	}
	return cellContent, err
}

func readSheets(file *excelize.File) []string {
	return file.GetSheetList()
}

func readRows(sheetName string, file *excelize.File) ([][]string, error) {
	rows, err := file.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("failed to read rows: %v", err)
	}
	return rows, err
}

func readColumns(sheetName string, file *excelize.File) ([][]string, error) {
	cols, err := file.GetCols(sheetName)
	if err != nil {
		return nil, fmt.Errorf("error closing Excel file: %v", err)
	}
	return cols, err
}

// findSecondaryCostCentreIndices finds indices of secondary cost centers
func findSecondaryCostCentreIndices(cols [][]string) []int {
	var SecondaryCostCentreIndices []int
	//iterates over cells in the second column, skipping the first row
	//finds all Secondary cost centres and appends their index to a slice
	for colCellIndex, colCell := range cols[columnSecondaryCostCentres][1:] {
		if colCell != "" {
			//+1 is needed since 1st row is skipped
			SecondaryCostCentreIndices = append(SecondaryCostCentreIndices, colCellIndex+1)
		}
	}
	return SecondaryCostCentreIndices
}

// getSecondaryCostCentreByIndex retrieves secondary cost center name by index
func getSecondaryCostCentreByIndex(secondaryCostCentreIndex int, cols [][]string) string {
	//Secondary cost centres are always in the second column
	return cols[columnSecondaryCostCentres][secondaryCostCentreIndex]
}

func getBudgetLineData(secondaryCostCentreIndex int, colCellIndex int, cols [][]string) (string, string, string, string) {

	//Find all relevant data
	//0s are gotten without kr for some reason
	account := cols[columnAccount][colCellIndex+secondaryCostCentreIndex+1]
	income := cols[columnIncome][colCellIndex+secondaryCostCentreIndex+1]
	expense := cols[columnExpense][colCellIndex+secondaryCostCentreIndex+1]
	comment := cols[columnComment][colCellIndex+secondaryCostCentreIndex+1]
	return account, income, expense, comment
}

func convertCostCentreTypeToEnglish(costCentreType string) (string, error) {
	switch strings.ToLower(costCentreType) {
	case "nämnd":
		return "committee", nil
	case "partition":
		return "partition", nil
	case "projekt":
		return "project", nil
	case "projekt x":
		return "projectX", nil
	case "övrigt":
		return "other", nil
	default:
		return "", fmt.Errorf("invalid cost centre type: %s", costCentreType)
	}
}

func sanitizeBudgetValue(valueString string, secondaryCostCentreInfo SecondaryCostCentre) (int, error) {
	// 0
	// -72,500 kr
	// 200,000 kr
	// -3,600.00 kr
	// 10,000.00 kr

	valueStringSanitized := strings.ReplaceAll(valueString, " ", "")
	valueStringSanitized = strings.ReplaceAll(valueStringSanitized, ",", "")
	valueStringSanitized = strings.ReplaceAll(valueStringSanitized, "kr", "")

	if strings.Contains(valueStringSanitized, ".") {
		return 0, fmt.Errorf("failed to convert budget string \"%s\" to int in \"%s\" - \"%s\": string contains \".\", check decimal places of incomes and expenses", valueString, secondaryCostCentreInfo.CostCentreName, secondaryCostCentreInfo.SecondaryCostCentreName)
	}

	if valueStringSanitized == "" {
		return 0, fmt.Errorf("failed to convert budget string \"%s\" to int in \"%s\" - \"%s\": budget value is empty, check incomes and expenses for zero-values", valueString, secondaryCostCentreInfo.CostCentreName, secondaryCostCentreInfo.SecondaryCostCentreName)
	}

	valueInt, err := strconv.Atoi(valueStringSanitized)
	if err != nil {
		return 0, fmt.Errorf("failed to convert budget string \"%s\" to int in \"%s\" - \"%s\": %v", valueString, secondaryCostCentreInfo.CostCentreName, secondaryCostCentreInfo.SecondaryCostCentreName, err)
	}

	return valueInt, nil
}
