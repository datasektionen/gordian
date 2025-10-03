package web

var CombinedCashflowLinesGetStatementStatic = `
    SELECT 
        UPPER(cost_centre) AS cost_centre, 
        UPPER(secondary_cost_centre) AS secondary_cost_centre, 
        UPPER(budget_line) AS budget_line, 
        SUM(amount) AS total_amount
    FROM (
    SELECT 
        ep.cost_centre, 
        ep.secondary_cost_centre, 
        ep.budget_line, 
        ep.amount, 
        EXTRACT(YEAR FROM e.expense_date)::text AS date,  -- Cast to text
        e.description
    FROM expenses_expensepart AS ep
    INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
    UNION ALL
    SELECT 
        ip.cost_centre, 
        ip.secondary_cost_centre, 
        ip.budget_line, 
        ip.amount, 
        EXTRACT(YEAR FROM COALESCE(i.invoice_date, i.payed_at))::text AS date,  -- Cast to text
        i.description
    FROM invoices_invoicepart AS ip
    INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
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
			ep.cost_centre,
			EXTRACT(YEAR FROM e.expense_date)::text AS date
		FROM expenses_expensepart AS ep
		INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
		UNION
		SELECT 
			ip.cost_centre,
			EXTRACT(YEAR FROM COALESCE(i.invoice_date, i.payed_at))::text AS date
		FROM invoices_invoicepart AS ip
		INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
	) AS combined
	WHERE (COALESCE($1, '') = '' OR $1 = 'Alla' OR date = $1)
	ORDER BY UPPER(cost_centre);
	`

// var ReportLinesByYearAllCCGetStatementStatic = `
// 		SELECT 
// 		    cost_centre, 
// 		    secondary_cost_centre, 
// 		    budget_line, 
// 		    SUM(amount) AS total_amount
// 		FROM (
// 		SELECT 
// 		    ep.cost_centre, 
// 		    ep.secondary_cost_centre, 
// 		    ep.budget_line, 
// 		    ep.amount, 
// 		    EXTRACT(YEAR FROM e.expense_date) AS date, 
// 		    e.description
// 		FROM expenses_expensepart AS ep
// 		INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
// 		UNION ALL
// 		SELECT 
// 		    ip.cost_centre, 
// 		    ip.secondary_cost_centre, 
// 		    ip.budget_line, 
// 		    ip.amount, 
// 		    EXTRACT(YEAR FROM (COALESCE(i.invoice_date, i.payed_at))) AS invoice_date, 
// 		    i.description
// 		FROM invoices_invoicepart AS ip
// 		INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
// 		) AS combined
// 		WHERE COALESCE(date = $1, true)
// 		GROUP BY cost_centre, secondary_cost_centre, budget_line
// 		ORDER BY cost_centre, secondary_cost_centre, budget_line;
// 	`

// var ReportLinesAllYearAllCCGetStatementStatic = `
// 	SELECT 
// 		cost_centre, 
// 		secondary_cost_centre, 
// 		budget_line, 
// 		SUM(amount) AS total_amount
// 	FROM (
// 	SELECT 
// 		ep.cost_centre, 
// 		ep.secondary_cost_centre, 
// 		ep.budget_line, 
// 		ep.amount, 
// 		EXTRACT(YEAR FROM e.expense_date) AS date, 
// 		e.description
// 	FROM expenses_expensepart AS ep
// 	INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
// 	UNION ALL
// 	SELECT 
// 		ip.cost_centre, 
// 		ip.secondary_cost_centre, 
// 		ip.budget_line, 
// 		ip.amount, 
// 		EXTRACT(YEAR FROM (COALESCE(i.invoice_date, i.payed_at))) AS invoice_date, 
// 		i.description
// 	FROM invoices_invoicepart AS ip
// 	INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
// 	) AS combined
// 	WHERE COALESCE(date = null, true)
// 	GROUP BY cost_centre, secondary_cost_centre, budget_line
// 	ORDER BY cost_centre, secondary_cost_centre, budget_line;
// `

// var ReportLinesAllYearByCCGetStatementStatic = `
// 		SELECT 
// 		    cost_centre, 
// 		    secondary_cost_centre, 
// 		    budget_line, 
// 		    SUM(amount) AS total_amount
// 		FROM (
// 		SELECT 
// 		    ep.cost_centre, 
// 		    ep.secondary_cost_centre, 
// 		    ep.budget_line, 
// 		    ep.amount, 
// 		    EXTRACT(YEAR FROM e.expense_date) AS date, 
// 		    e.description
// 		FROM expenses_expensepart AS ep
// 		INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
// 		UNION ALL
// 		SELECT 
// 		    ip.cost_centre, 
// 		    ip.secondary_cost_centre, 
// 		    ip.budget_line, 
// 		    ip.amount, 
// 		    EXTRACT(YEAR FROM (COALESCE(i.invoice_date, i.payed_at))) AS invoice_date, 
// 		    i.description
// 		FROM invoices_invoicepart AS ip
// 		INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
// 		) AS combined
// 		WHERE COALESCE(date = null, true)
// 		AND COALESCE(cost_centre = $1, true)
// 		GROUP BY cost_centre, secondary_cost_centre, budget_line
// 		ORDER BY cost_centre, secondary_cost_centre, budget_line;
// 	`

// var ReportLinesByYearByCCGetStatementStatic = `
// 		SELECT 
// 		    cost_centre, 
// 		    secondary_cost_centre, 
// 		    budget_line, 
// 		    SUM(amount) AS total_amount
// 		FROM (
// 		SELECT 
// 		    ep.cost_centre, 
// 		    ep.secondary_cost_centre, 
// 		    ep.budget_line, 
// 		    ep.amount, 
// 		    EXTRACT(YEAR FROM e.expense_date) AS date, 
// 		    e.description
// 		FROM expenses_expensepart AS ep
// 		INNER JOIN expenses_expense AS e ON ep.expense_id = e.id
// 		UNION ALL
// 		SELECT 
// 		    ip.cost_centre, 
// 		    ip.secondary_cost_centre, 
// 		    ip.budget_line, 
// 		    ip.amount, 
// 		    EXTRACT(YEAR FROM (COALESCE(i.invoice_date, i.payed_at))) AS invoice_date, 
// 		    i.description
// 		FROM invoices_invoicepart AS ip
// 		INNER JOIN invoices_invoice AS i ON ip.invoice_id = i.id
// 		) AS combined
// 		WHERE COALESCE(date = $1, true)
// 		AND COALESCE(cost_centre = $2, true)
// 		GROUP BY cost_centre, secondary_cost_centre, budget_line
// 		ORDER BY cost_centre, secondary_cost_centre, budget_line;
// 	`


