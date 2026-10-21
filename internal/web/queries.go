package web

var CombinedCashflowLinesGetStatementStatic = `
    SELECT
        UPPER(cost_centre) AS cost_centre,
        UPPER(secondary_cost_centre) AS secondary_cost_centre,
        UPPER(budget_line) AS budget_line,
        SUM(amount) AS total_amount
    FROM (
    SELECT
        cp.cost_centre,
        cp.secondary_cost_centre,
        cp.budget_line,
        cp.amount,
        EXTRACT(YEAR FROM COALESCE(ed.expense_date, inv.invoice_date, inv.paid_at))::text AS date  -- Cast to text
    FROM core_claimpart AS cp
    INNER JOIN core_claim AS c ON cp.claim_id = c.id
    LEFT JOIN expenses_expensedata AS ed ON ed.id = c.expense_data_id
    LEFT JOIN invoices_invoicedata AS inv ON inv.id = c.invoice_data_id
    ) AS combined
    WHERE (COALESCE($1, '') = '' OR $1 = 'Alla' OR date = $1)  -- Filter by year or allow 'Alla' as wildcard
      AND (COALESCE($2, '') = '' OR $2 = 'Alla' OR UPPER(cost_centre) = UPPER($2))  -- Filter by cost_centre or allow 'Alla' as wildcard
    GROUP BY UPPER(cost_centre), UPPER(secondary_cost_centre), UPPER(budget_line)
    ORDER BY UPPER(cost_centre), UPPER(secondary_cost_centre), UPPER(budget_line);
`

var uniqueCCGetStatementStatic = `
	SELECT DISTINCT UPPER(cost_centre) AS cost_centre
	FROM (
		SELECT
			cp.cost_centre,
			EXTRACT(YEAR FROM COALESCE(ed.expense_date, inv.invoice_date, inv.paid_at))::text AS date
		FROM core_claimpart AS cp
		INNER JOIN core_claim AS c ON cp.claim_id = c.id
		LEFT JOIN expenses_expensedata AS ed ON ed.id = c.expense_data_id
		LEFT JOIN invoices_invoicedata AS inv ON inv.id = c.invoice_data_id
	) AS combined
	WHERE (COALESCE($1, '') = '' OR $1 = 'Alla' OR date = $1)
	ORDER BY UPPER(cost_centre);
	`
