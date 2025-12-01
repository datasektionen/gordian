package web

import (
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	Remaining      string
}

type ReportSecondaryCostCentreLine struct {
	SecondaryCostCentreName string
	BudgetLinesList         []ReportBudgetLine
	Total                   string
	Budget                  string
	Remaining               string
}

type ReportCostCentreLine struct {
	CostCentreName           string
	SecondaryCostCentresList []ReportSecondaryCostCentreLine
	Total                    string
	Budget                   string
	Remaining                string
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
	// currentYear := "2024"

	selectedYear := r.FormValue("year")
	if selectedYear == "" {
		selectedYear = currentYear
	}

	simpleBudgetLines, err := getSimpleBudgetLines(databases.DBGO)
	if err != nil {
		return fmt.Errorf("failed to get simple budget line information from database: %v", err)
	}

	CCList, err := getCCList(databases.DBCF, selectedYear)
	if err != nil {
		return fmt.Errorf("failed get scan CCList information from database: %v", err)
	}

	cashflowLines, err := getCashflowLines(databases.DBCF, selectedYear, r.FormValue("cc"))
	if err != nil {
		return fmt.Errorf("failed to get scan cashflow lines information from database: %v", err)
	}

	// Always include unspent budget lines for current year in the data
	// The template will handle showing/hiding them based on showUnspent
	structuredReport, err := StructureReportLines(cashflowLines, simpleBudgetLines, selectedYear, selectedYear == currentYear)
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

func getCCList(db *sql.DB, year string) ([]string, error) {
	var result *sql.Rows
	var err error

	result, err = db.Query(uniqueCCGetStatementStatic, year)
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
		
		// Decode HTML entities immediately when reading from database
		cashflowLine.CashflowLineCostCentre = html.UnescapeString(cashflowLine.CashflowLineCostCentre)
		cashflowLine.CashflowLineSecondaryCostCentre = html.UnescapeString(cashflowLine.CashflowLineSecondaryCostCentre)
		cashflowLine.CashflowLineBudgetLine = html.UnescapeString(cashflowLine.CashflowLineBudgetLine)
		
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
		Remaining:                "0",
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
		Remaining:               "0",
	})
	return &(*secCostCentres)[len(*secCostCentres)-1]
}

// Organize CashflowLines into structured data
func StructureReportLines(cashflowLines []CashflowLine, simpleBudgetLines []SimpleBudgetLine, selectedYear string, showUnspent bool) ([]ReportCostCentreLine, error) {
	var costCentres []ReportCostCentreLine

	currentYear := strconv.Itoa(time.Now().Year())
	// currentYear := "2024"

	// Process CashflowLines
	for _, line := range cashflowLines {

		costCentre := findOrAddCostCentre(&costCentres, line.CashflowLineCostCentre)

		secCostCentre := findOrAddSecondaryCostCentre(&costCentre.SecondaryCostCentresList, line.CashflowLineSecondaryCostCentre)

		// Convert the total to ensure consistent formatting
		formattedTotal, err := strconv.ParseFloat(strings.Replace(line.CashflowLineTotal, ",", ".", 1), 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cashflow total: %v", err)
		}

		// Check if budget line already exists and update it, otherwise append.
		// Needed because of the & fippel
		found := false
		for i, bl := range secCostCentre.BudgetLinesList {
			if bl.BudgetLineName == line.CashflowLineBudgetLine {
				// Budget line exists, add to its total
				existingTotal, err := strconv.ParseFloat(strings.Replace(bl.Total, ",", ".", 1), 64)
				if err != nil {
					existingTotal = 0
				}
				newTotal := existingTotal + formattedTotal
				secCostCentre.BudgetLinesList[i].Total = formatNumber(newTotal)
				found = true
				break
			}
		}
		
		if !found {
			// New budget line, append it
			secCostCentre.BudgetLinesList = append(secCostCentre.BudgetLinesList, ReportBudgetLine{
				BudgetLineName: line.CashflowLineBudgetLine,
				Total:          formatNumber(formattedTotal),
			})
		}

		var err1, err2 error

		secCostCentre.Total, err1 = addTotals(secCostCentre.Total, line.CashflowLineTotal)
		costCentre.Total, err2 = addTotals(costCentre.Total, line.CashflowLineTotal)

		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("failed to update totals for SCC or CC: %v%v", err1, err2)
		}
	}

	// Process SimpleBudgetLines - add budget values to existing lines or create new lines for unspent budgets
	for _, budgetLine := range simpleBudgetLines {
		// Only process expense lines (negative values in the database)
		expenseValue, err := strconv.ParseFloat(strings.Replace(budgetLine.BudgetLineExpense, ",", ".", 1), 64)
		if err != nil || expenseValue >= 0 {
			// Skip if not a valid expense (incomes are positive in the database)
			continue
		}

		// Check if this budget line's cost centre exists in our result set
		// (meaning it either had cashflow or we want to include it)
		costCentreExists := false
		for _, cc := range costCentres {
			if strings.EqualFold(cc.CostCentreName, budgetLine.BudgetLineCostCentreName) {
				costCentreExists = true
				break
			}
		}

		if !costCentreExists {
			// This cost centre doesn't match our filter, skip it
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
			// Only create new budget line entries for the current year (unspent budgets)
			// For past years, only show lines that have cashflow entries
			// Also respect the showUnspent toggle
			if selectedYear != currentYear || !showUnspent {
				continue
			}
			
			// Budget line doesn't exist yet (no cashflow entry), create it with zero total
			secCostCentre.BudgetLinesList = append(secCostCentre.BudgetLinesList, ReportBudgetLine{
				BudgetLineName: budgetLine.BudgetLineName,
				Total:          "0",
				Budget:         budgetValue,
			})
		}

		if selectedYear == currentYear && budgetValue != "0" {
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

	// Format display names and clean up zero budgets
	for i := range costCentres {
		// Properly capitalize cost centre name
		costCentres[i].CostCentreName = properCapitalize(costCentres[i].CostCentreName)
		
		if costCentres[i].Budget == "0" {
			costCentres[i].Budget = ""
		}
		
		// Calculate remaining for cost centre
		if selectedYear == currentYear && costCentres[i].Budget != "" {
			remaining, err := calculateRemaining(costCentres[i].Budget, costCentres[i].Total)
			if err == nil {
				costCentres[i].Remaining = remaining
			}
		}
		
		// Filter out empty secondary cost centres
		filteredSecCostCentres := []ReportSecondaryCostCentreLine{}
		for j := range costCentres[i].SecondaryCostCentresList {
			// Skip secondary cost centres with no budget lines
			if len(costCentres[i].SecondaryCostCentresList[j].BudgetLinesList) == 0 {
				continue
			}
			
			// Properly capitalize secondary cost centre name
			costCentres[i].SecondaryCostCentresList[j].SecondaryCostCentreName = properCapitalize(costCentres[i].SecondaryCostCentresList[j].SecondaryCostCentreName)
			
			if costCentres[i].SecondaryCostCentresList[j].Budget == "0" {
				costCentres[i].SecondaryCostCentresList[j].Budget = ""
			}
			
			// Calculate remaining for secondary cost centre
			if selectedYear == currentYear && costCentres[i].SecondaryCostCentresList[j].Budget != "" {
				remaining, err := calculateRemaining(costCentres[i].SecondaryCostCentresList[j].Budget, costCentres[i].SecondaryCostCentresList[j].Total)
				if err == nil {
					costCentres[i].SecondaryCostCentresList[j].Remaining = remaining
				}
			}
			
			for k := range costCentres[i].SecondaryCostCentresList[j].BudgetLinesList {
				// Properly capitalize budget line name
				costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].BudgetLineName = properCapitalize(costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].BudgetLineName)
				
				if costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget == "0" {
					costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget = ""
				}
				
				// Calculate remaining for budget line
				if selectedYear == currentYear && costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget != "" {
					remaining, err := calculateRemaining(costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Budget, costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Total)
					if err == nil {
						costCentres[i].SecondaryCostCentresList[j].BudgetLinesList[k].Remaining = remaining
					}
				}
			}
			
			filteredSecCostCentres = append(filteredSecCostCentres, costCentres[i].SecondaryCostCentresList[j])
		}
		costCentres[i].SecondaryCostCentresList = filteredSecCostCentres
	}

	return costCentres, nil
}

func getSimpleBudgetLines(db *sql.DB) ([]SimpleBudgetLine, error) {
	var query = `
		SELECT 
			UPPER(cost_centres.name),
			UPPER(secondary_cost_centres.name),
			UPPER(budget_lines.name),
			budget_lines.expense
		FROM budget_lines
		JOIN secondary_cost_centres 
			ON budget_lines.secondary_cost_centre_id = secondary_cost_centres.id
		JOIN cost_centres 
			ON secondary_cost_centres.cost_centre_id = cost_centres.id
		ORDER BY UPPER(cost_centres.name), UPPER(secondary_cost_centres.name), UPPER(budget_lines.name)
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

func calculateRemaining(budget, spent string) (string, error) {
	budget = strings.TrimSpace(budget)
	spent = strings.TrimSpace(spent)

	if budget == "" || budget == "0" {
		return "", nil
	}
	if spent == "" {
		spent = "0"
	}

	// Convert commas back to periods for parsing
	budget = strings.Replace(budget, ",", ".", 1)
	spent = strings.Replace(spent, ",", ".", 1)

	budgetVal, err1 := strconv.ParseFloat(budget, 64)
	spentVal, err2 := strconv.ParseFloat(spent, 64)

	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("failed to parse values: %v, %v", err1, err2)
	}

	remaining := budgetVal - spentVal
	return formatNumber(remaining), nil
}

// removes unnecessary zeros
func formatNumber(value float64) string {
	if value == float64(int(value)) {
		return fmt.Sprintf("%d", int(value))
	}
	formatted := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", value), "0"), ".")
	return strings.Replace(formatted, ".", ",", 1)
}

// List of acronyms that should never be lowercased
var preservedAcronyms = []string{"DEMON", "SM", "(SM)", "DKM", "METAdorerna", "dÅre", "STUDS", "dJulkalendern", "EECS", "dFunk", "DJ", "dJubileet", "META", "DM", "dFunkteambuilding", "dFunklunch", "dFunköverlämning", "dFunkt", "TGT", "DESC", "TB", "VM", "PR", "BÜGG"," DSF", "HTC", "HTD", "RN", "NBF", "INQU", "INDA", "INEK", "TTG", "II", "LQ", "BLB", "SpexM", "MKM", "HLR", "DSF", "INAUG", "GUDAR", "dRama", "METAspexet"}

// properCapitalize converts a string to title case (first letter uppercase, rest lowercase)
// while preserving certain acronyms and special characters like Ø
func properCapitalize(s string) string {
	// HTML entities should already be decoded at this point, but just in case
	s = html.UnescapeString(s)
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Check if the entire string matches a preserved acronym (case-insensitive check)
	for _, acronym := range preservedAcronyms {
		if strings.EqualFold(s, acronym) {
			return acronym
		}
	}

	// Check if the string contains preserved acronyms and handle word by word
	words := strings.Fields(s)
	for i, word := range words {
		found := false
		for _, acronym := range preservedAcronyms {
			if strings.EqualFold(word, acronym) {
				words[i] = acronym
				found = true
				break
			}
		}
		if !found {
			// Check if word contains special delimiters and handle parts separately
			delimiters := []string{"-", "/", "+", "&"}
			hasDelimiter := false
			var delimiter string
			
			for _, delim := range delimiters {
				if strings.Contains(word, delim) {
					hasDelimiter = true
					delimiter = delim
					break
				}
			}
			
			if hasDelimiter {
				parts := strings.Split(word, delimiter)
				for p, part := range parts {
					partFound := false
					// Check if this part is a preserved acronym
					for _, acronym := range preservedAcronyms {
						if strings.EqualFold(part, acronym) {
							parts[p] = acronym
							partFound = true
							break
						}
					}
					if !partFound {
						parts[p] = capitalizePart(part)
					}
				}
				words[i] = strings.Join(parts, delimiter)
			} else {
				words[i] = capitalizePart(word)
			}
		}
	}

	return strings.Join(words, " ")
}

// capitalizePart capitalizes the first letter and lowercases the rest,
// but preserves uppercase Ø and handles special case "nØ"
func capitalizePart(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	
	// Special case: standalone "nø" should always be "nØ"
	if len(runes) == 2 && unicode.ToLower(runes[0]) == 'n' && unicode.ToLower(runes[1]) == 'ø' {
		return "nØ"
	}
	
	result := make([]rune, len(runes))
	result[0] = unicode.ToUpper(runes[0])
	
	for j := 1; j < len(runes); j++ {
		// Handle special case: 'n' followed by 'ø' should be 'nØ'
		if j > 0 && unicode.ToLower(runes[j-1]) == 'n' && unicode.ToLower(runes[j]) == 'ø' {
			result[j-1] = 'n'
			result[j] = 'Ø'
		} else if runes[j] == 'Ø' || runes[j] == 'ø' {
			// Never lowercase Ø
			result[j] = 'Ø'
		} else {
			result[j] = unicode.ToLower(runes[j])
		}
	}
	
	return string(result)
}
