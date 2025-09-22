package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SimpleBudgetLine struct {
	BudgetLineCostCentreName          string
	BudgetLineSecondaryCostCentreName string
	BudgetLineName                    string
	BudgetLineExpense                 string
}

type CashflowLine struct {
	CashflowLineCostCentre          string
	CashflowLineSecondaryCostCentre string
	CashflowLineBudgetLine          string
	CashflowLineTotal               string
}

type ReportBudgetLine struct {
	BudgetLineName string
	Total          string
	Budget         string
}

type ReportSecondaryCostCentreLine struct {
	SecondaryCostCentreName string
	BudgetLinesList         []ReportBudgetLine
	Total                   string
	Budget                  string
}

type ReportCostCentreLine struct {
	CostCentreName           string
	SecondaryCostCentresList []ReportSecondaryCostCentreLine
	Total                    string
	Budget                   string
}

func getYearsSince2017() []string {
	startYear := 2017
	currentYear := time.Now().Year()
	var years []string

	for year := startYear; year <= currentYear; year++ {
		years = append(years, strconv.Itoa(year))
	}

	return years
}

func reportPage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {

	currentYear := strconv.Itoa(time.Now().Year())
	//currentYear := "2024"

	selectedYear := r.FormValue("year")
	if selectedYear == "" {
		selectedYear = currentYear
	}

	simpleBudgetLines, err := getSimpleBudgetLines(databases.DBGO)
	if err != nil {
		return fmt.Errorf("failed to get simple budget line information from database: %v", err)
	}

	CCList, err := getCCList(databases.DBCF)
	if err != nil {
		return fmt.Errorf("failed get scan CCList information from database: %v", err)
	}

	cashflowLines, err := getCashflowLines(databases.DBCF, selectedYear, r.FormValue("cc"))
	if err != nil {
		return fmt.Errorf("failed to get scan cashflow lines information from database: %v", err)
	}

	structuredReport, err := StructureReportLines(cashflowLines, simpleBudgetLines, selectedYear)
	if err != nil {
		return fmt.Errorf("failed to structure cashflow and simple budget lines: %v", err)
	}
	years := getYearsSince2017()

	if err := templates.ExecuteTemplate(w, "report.gohtml", map[string]any{
		"motd":          motdGenerator(),
		"cashflowLines": cashflowLines,
		"permissions":   perms,
		"loggedIn":      loggedIn,
		"report":        structuredReport,
		"CCList":        CCList,
		"years":         years,
		"SelectedCC":    r.FormValue("cc"),
		"SelectedYear":  selectedYear,
		"CurrentYear":   currentYear,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func getCCList(db *sql.DB) ([]string, error) {
	var result *sql.Rows
	var err error

	result, err = db.Query(uniqueCCGetStatementStatic)
	if err != nil {
		return nil, fmt.Errorf("failed to get CCList from database: %v", err)
	}
	defer result.Close()

	var CCList []string

	for result.Next() {
		var CC string

		err := result.Scan(
			&CC,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CC from query result: %v", err)
		}
		CCList = append(CCList, CC)
	}
	return CCList, nil
}

func getCashflowLines(db *sql.DB, year string, cc string) ([]CashflowLine, error) {

	var result *sql.Rows
	var err error

	result, err = db.Query(CombinedCashflowLinesGetStatementStatic, year, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to get cashflow lines from database: %v", err)
	}
	defer result.Close()

	var cashflowLines []CashflowLine

	for result.Next() {
		var cashflowLine CashflowLine

		err := result.Scan(
			&cashflowLine.CashflowLineCostCentre,
			&cashflowLine.CashflowLineSecondaryCostCentre,
			&cashflowLine.CashflowLineBudgetLine,
			&cashflowLine.CashflowLineTotal,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan cashflow line from query result: %v", err)
		}
		cashflowLines = append(cashflowLines, cashflowLine)
	}
	return cashflowLines, nil
}

func findOrAddCostCentre(costCentres *[]ReportCostCentreLine, name string) *ReportCostCentreLine {
	for i := range *costCentres {
		if (*costCentres)[i].CostCentreName == name {
			return &(*costCentres)[i]
		}
	}
	*costCentres = append(*costCentres, ReportCostCentreLine{
		CostCentreName:           name,
		SecondaryCostCentresList: []ReportSecondaryCostCentreLine{},
		Total:                    "0",
		Budget:                   "0",
	})
	return &(*costCentres)[len(*costCentres)-1]
}

func findOrAddSecondaryCostCentre(secCostCentres *[]ReportSecondaryCostCentreLine, name string) *ReportSecondaryCostCentreLine {
	for i := range *secCostCentres {
		if (*secCostCentres)[i].SecondaryCostCentreName == name {
			return &(*secCostCentres)[i]
		}
	}
	*secCostCentres = append(*secCostCentres, ReportSecondaryCostCentreLine{
		SecondaryCostCentreName: name,
		BudgetLinesList:         []ReportBudgetLine{},
		Total:                   "0",
		Budget:                  "0",
	})
	return &(*secCostCentres)[len(*secCostCentres)-1]
}

// Organize CashflowLines into structured data
func StructureReportLines(cashflowLines []CashflowLine, simpleBudgetLines []SimpleBudgetLine, selectedYear string) ([]ReportCostCentreLine, error) {
	var costCentres []ReportCostCentreLine

	currentYear := strconv.Itoa(time.Now().Year())
	//currentYear := "2024"

	// Process CashflowLines
	for _, line := range cashflowLines {

		costCentre := findOrAddCostCentre(&costCentres, line.CashflowLineCostCentre)

		secCostCentre := findOrAddSecondaryCostCentre(&costCentre.SecondaryCostCentresList, line.CashflowLineSecondaryCostCentre)

		// Convert the total to ensure consistent formatting
		formattedTotal, err := strconv.ParseFloat(strings.Replace(line.CashflowLineTotal, ",", ".", 1), 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cashflow total: %v", err)
		}

		secCostCentre.BudgetLinesList = append(secCostCentre.BudgetLinesList, ReportBudgetLine{
			BudgetLineName: line.CashflowLineBudgetLine,
			Total:          formatNumber(formattedTotal),
		})

		var err1, err2 error

		secCostCentre.Total, err1 = addTotals(secCostCentre.Total, line.CashflowLineTotal)
		costCentre.Total, err2 = addTotals(costCentre.Total, line.CashflowLineTotal)

		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("failed to update totals for SCC or CC: %v%v", err1, err2)
		}
	}

	// Process SimpleBudgetLines
	for _, budgetLine := range simpleBudgetLines {

		existsInCashflow := false
		for _, cashflowLine := range cashflowLines {
			if cashflowLine.CashflowLineCostCentre == budgetLine.BudgetLineCostCentreName &&
				cashflowLine.CashflowLineSecondaryCostCentre == budgetLine.BudgetLineSecondaryCostCentreName &&
				cashflowLine.CashflowLineBudgetLine == budgetLine.BudgetLineName {
				existsInCashflow = true
				break
			}
		}

		if !existsInCashflow {
			continue
		}

		costCentre := findOrAddCostCentre(&costCentres, budgetLine.BudgetLineCostCentreName)

		secCostCentre := findOrAddSecondaryCostCentre(&costCentre.SecondaryCostCentresList, budgetLine.BudgetLineSecondaryCostCentreName)

		budgetValue := "0"
		if selectedYear == currentYear {
			budgetValue = makePositive(budgetLine.BudgetLineExpense)
		}

		found := false
		for i, bl := range secCostCentre.BudgetLinesList {
			if bl.BudgetLineName == budgetLine.BudgetLineName {
				updatedBudget, err := addTotals(secCostCentre.BudgetLinesList[i].Budget, budgetValue)
				if err != nil {
					return nil, fmt.Errorf("failed to update budget value: %v", err)
				}
				secCostCentre.BudgetLinesList[i].Budget = updatedBudget
				found = true
				break
			}
		}
		if !found {
			secCostCentre.BudgetLinesList = append(secCostCentre.BudgetLinesList, ReportBudgetLine{
				BudgetLineName: budgetLine.BudgetLineName,
				Total:          "0",
				Budget:         budgetValue,
			})
		}

		if selectedYear == currentYear {
			var err error
			secCostCentre.Budget, err = addTotals(secCostCentre.Budget, budgetValue)
			if err != nil {
				return nil, fmt.Errorf("failed to update budget total for SCC: %v", err)
			}

			costCentre.Budget, err = addTotals(costCentre.Budget, budgetValue)
			if err != nil {
				return nil, fmt.Errorf("failed to update budget total for CC: %v", err)
			}
		}
	}

	for i := range costCentres {
		if costCentres[i].Budget == "0" {
			costCentres[i].Budget = ""
		}
		for j := range costCentres[i].SecondaryCostCentresList {
			if costCentres[i].SecondaryCostCentresList[j].Budget == "0" {
				costCentres[i].SecondaryCostCentresList[j].Budget = ""
			}
			for k := range costCentres[i].SecondaryCostCentresList[j].BudgetLinesList {
				if costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget == "0" {
					costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget = ""
				}
			}
		}
	}

	return costCentres, nil
}

func getSimpleBudgetLines(db *sql.DB) ([]SimpleBudgetLine, error) {
	var query = `
		SELECT 
			cost_centres.name,
			secondary_cost_centres.name,
			budget_lines.name,
			budget_lines.expense
		FROM budget_lines
		JOIN secondary_cost_centres 
			ON budget_lines.secondary_cost_centre_id = secondary_cost_centres.id
		JOIN cost_centres 
			ON secondary_cost_centres.cost_centre_id = cost_centres.id
		ORDER BY cost_centres.name, secondary_cost_centres.name, budget_lines.name
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get simple budget lines from database: %v", err)
	}
	defer rows.Close()

	var simpleBudgetLines []SimpleBudgetLine

	for rows.Next() {
		var simpleBudgetLine SimpleBudgetLine

		err := rows.Scan(
			&simpleBudgetLine.BudgetLineCostCentreName,
			&simpleBudgetLine.BudgetLineSecondaryCostCentreName,
			&simpleBudgetLine.BudgetLineName,
			&simpleBudgetLine.BudgetLineExpense,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan simple budget line from query result: %v", err)
		}

		simpleBudgetLines = append(simpleBudgetLines, simpleBudgetLine)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through simple budget lines: %v", err)
	}

	return simpleBudgetLines, nil
}

func addTotals(total1, total2 string) (string, error) {
	total1 = strings.TrimSpace(total1)
	total2 = strings.TrimSpace(total2)

	if total1 == "" {
		total1 = "0"
	}
	if total2 == "" {
		total2 = "0"
	}

	// Convert commas back to periods for parsing
	total1 = strings.Replace(total1, ",", ".", 1)
	total2 = strings.Replace(total2, ",", ".", 1)

	t1, err1 := strconv.ParseFloat(total1, 64)
	t2, err2 := strconv.ParseFloat(total2, 64)

	if err1 != nil || err2 != nil {
		return "0", fmt.Errorf("failed to convert totals to float: %v, %v", err1, err2)
	}

	result := t1 + t2
	return formatNumber(result), nil
}

func makePositive(value string) string {
	value = strings.TrimSpace(value)

	// Convert comma back to period for parsing
	value = strings.Replace(value, ",", ".", 1)

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "0"
	}

	if parsed < 0 {
		parsed = -parsed
	}

	return formatNumber(parsed)
}

// removes unnecessary zeros
func formatNumber(value float64) string {
	if value == float64(int(value)) {
		return fmt.Sprintf("%d", int(value))
	}
	formatted := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", value), "0"), ".")
	return strings.Replace(formatted, ".", ",", 1)
}
