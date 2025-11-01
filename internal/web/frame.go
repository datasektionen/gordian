package web

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/datasektionen/GOrdian/internal/excel"
)

type FrameLine struct {
	FrameLineName     string
	FrameLineIncome   int
	FrameLineExpense  int
	FrameLineInternal int
	FrameLineResult   int
}

func framePage(w http.ResponseWriter, r *http.Request, databases Databases, perms []string, loggedIn bool) error {
	budgetLines, err := getFrameLines(databases.DBGO)
	if err != nil {
		return fmt.Errorf("failed get scan budget lines information from database: %v", err)
	}
	committeeFrameLines, projectFrameLines, otherFrameLines, totalFrameLine, sumCommitteeFrameLine, sumProjectFrameLine, sumOtherFrameLine, err := generateFrameLines(budgetLines)
	if err != nil {
		return fmt.Errorf("failed to generate frame budget lines: %v", err)
	}
	if err := templates.ExecuteTemplate(w, "frame.gohtml", map[string]any{
		"motd":                  motdGenerator(),
		"committeeframelines":   committeeFrameLines,
		"projectframelines":     projectFrameLines,
		"otherframelines":       otherFrameLines,
		"totalframeline":        totalFrameLine,
		"sumcommitteeframeline": sumCommitteeFrameLine,
		"sumprojectframeline":   sumProjectFrameLine,
		"sumotherframeline":     sumOtherFrameLine,
		"permissions":           perms,
		"loggedIn":              loggedIn,
	}); err != nil {
		return fmt.Errorf("could not render template: %w", err)
	}
	return nil
}

func getFrameLines(db *sql.DB) ([]excel.BudgetLine, error) {
	var frameLinesGetStatementStatic = `
		SELECT 
    		SUM(income),
			SUM(expense),
			secondary_cost_centres.name ILIKE '%Internt%',
			cost_centres.id,
			cost_centres.name,
			cost_centres.type
		FROM budget_lines
		JOIN secondary_cost_centres ON secondary_cost_centres.id = secondary_cost_centre_id
		JOIN cost_centres ON secondary_cost_centres.cost_centre_id = cost_centres.id
		GROUP BY cost_centres.id, cost_centres.name, cost_centres.type, secondary_cost_centres.name ILIKE '%Internt%'
		ORDER BY LOWER(cost_centres.name), secondary_cost_centres.name ILIKE '%Internt%'
	`
	result, err := db.Query(frameLinesGetStatementStatic)
	if err != nil {
		return nil, fmt.Errorf("failed to get framelines from database: %v", err)
	}
	var frameLines []excel.BudgetLine
	for result.Next() {
		var frameLine excel.BudgetLine

		err := result.Scan(
			&frameLine.BudgetLineIncome,
			&frameLine.BudgetLineExpense,
			&frameLine.SecondaryCostCentreName,
			&frameLine.CostCentreID,
			&frameLine.CostCentreName,
			&frameLine.CostCentreType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan budget line from query result: %v", err)
		}
		frameLines = append(frameLines, frameLine)
	}
	return frameLines, nil
}

func generateFrameLines(frameLines []excel.BudgetLine) ([]FrameLine, []FrameLine, []FrameLine, FrameLine, FrameLine, FrameLine, FrameLine, error) {
	var committeeFrameLines []FrameLine
	var projectFrameLines []FrameLine
	var otherFrameLines []FrameLine
	var totalFrameLine FrameLine
	var sumCommitteeFrameLine FrameLine
	var sumProjectFrameLine FrameLine
	var sumOtherFrameLine FrameLine

	totalFrameLine.FrameLineName = "Totalt"
	sumCommitteeFrameLine.FrameLineName = "Summa nämnder"
	sumProjectFrameLine.FrameLineName = "Summa projekt"
	sumOtherFrameLine.FrameLineName = "Summa övrigt"

	var skippidi bool
	for i, frameLine := range frameLines {
		if skippidi {
			skippidi = false
			continue
		}
		frameLineIncome := frameLine.BudgetLineIncome
		frameLineExpense := frameLine.BudgetLineExpense
		frameLineName := frameLine.CostCentreName
		frameLineInternal := 0
		frameLineResult := 0

		// each CC appears twice, once for internal costs, once for the rest
		// both are handled i and i+1
		// skippidi makes sure that the loop incements by two
		if i+1 < len(frameLines) && frameLines[i+1].CostCentreName == frameLineName {
			frameLineIncome += frameLines[i+1].BudgetLineIncome
			frameLineExpense += frameLines[i+1].BudgetLineExpense
			frameLineInternal = frameLines[i+1].BudgetLineIncome + frameLines[i+1].BudgetLineExpense
			skippidi = true
		}

		frameLineResult = frameLineIncome + frameLineExpense

		reconstructedFrameLine := FrameLine{frameLineName, frameLineIncome, frameLineExpense, frameLineInternal, frameLineResult}

		totalFrameLine.FrameLineIncome += frameLineIncome
		totalFrameLine.FrameLineExpense += frameLineExpense
		totalFrameLine.FrameLineInternal += frameLineInternal
		totalFrameLine.FrameLineResult += frameLineResult

		switch frameLine.CostCentreType {
		case "committee":
			committeeFrameLines = append(committeeFrameLines, reconstructedFrameLine)
		case "project":
			projectFrameLines = append(projectFrameLines, reconstructedFrameLine)
		case "other":
			otherFrameLines = append(otherFrameLines, reconstructedFrameLine)
		default:
			return nil, nil, nil, FrameLine{}, FrameLine{}, FrameLine{}, FrameLine{}, fmt.Errorf("faulty cost centre type found when splitting")
		}
	}

	for _, committeeFrameLine := range committeeFrameLines {
		sumCommitteeFrameLine.FrameLineIncome += committeeFrameLine.FrameLineIncome
		sumCommitteeFrameLine.FrameLineExpense += committeeFrameLine.FrameLineExpense
		sumCommitteeFrameLine.FrameLineInternal += committeeFrameLine.FrameLineInternal
		sumCommitteeFrameLine.FrameLineResult += committeeFrameLine.FrameLineResult
	}

	for _, ProjectFrameLine := range projectFrameLines {
		sumProjectFrameLine.FrameLineIncome += ProjectFrameLine.FrameLineIncome
		sumProjectFrameLine.FrameLineExpense += ProjectFrameLine.FrameLineExpense
		sumProjectFrameLine.FrameLineInternal += ProjectFrameLine.FrameLineInternal
		sumProjectFrameLine.FrameLineResult += ProjectFrameLine.FrameLineResult
	}

	for _, OtherFrameLine := range otherFrameLines {
		sumOtherFrameLine.FrameLineIncome += OtherFrameLine.FrameLineIncome
		sumOtherFrameLine.FrameLineExpense += OtherFrameLine.FrameLineExpense
		sumOtherFrameLine.FrameLineInternal += OtherFrameLine.FrameLineInternal
		sumOtherFrameLine.FrameLineResult += OtherFrameLine.FrameLineResult
	}

	return committeeFrameLines, projectFrameLines, otherFrameLines, totalFrameLine, sumCommitteeFrameLine, sumProjectFrameLine, sumOtherFrameLine, nil
}
