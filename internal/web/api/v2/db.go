package v2

import (
	"fmt"
	"strings"

	"github.com/lib/pq"
)

type Join struct {
	Table      string
	Conditions []string
}

type Query struct {
	Table      string
	Fields     []string
	Conditions []string
	Args       []any
	OrderBy    string
	Joins      []Join
}

type QueryModifier = func(q *Query)

func Select(fields ...string) QueryModifier {
	return func(q *Query) {
		q.Fields = fields
	}
}

type Condition = func(q *Query) string

func Where(c Condition) QueryModifier {
	return func(q *Query) {
		q.Conditions = append(q.Conditions, c(q))
	}
}

// Joins

func InnerJoin(table string, conditions ...Condition) QueryModifier {
	return func(q *Query) {
		resolved := make([]string, len(conditions))
		for i, c := range conditions {
			resolved[i] = c(q)
		}
		q.Joins = append(q.Joins, Join{Table: table, Conditions: resolved})
	}
}

// Sorting

func OrderBy(orderBy string) QueryModifier {
	return func(q *Query) {
		q.OrderBy = orderBy
	}
}

// Conditions

type Column string

func Equals(val1, val2 any) Condition {
	return func(q *Query) string {
		return fmt.Sprintf("%s = %s", operand(q, val1), operand(q, val2))
	}
}

func In(col any, values any) Condition {
	return func(q *Query) string {
		q.Args = append(q.Args, pq.Array(values))
		return fmt.Sprintf("%s = ANY($%d)", operand(q, col), len(q.Args))
	}
}

func operand(q *Query, v any) string {
	if c, ok := v.(Column); ok {
		return string(c)
	}
	q.Args = append(q.Args, v)
	return fmt.Sprintf("$%d", len(q.Args))
}

func buildSql(q *Query) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(strings.Join(q.Fields, ", "))
	b.WriteString(" FROM ")
	b.WriteString(q.Table)
	for _, j := range q.Joins {
		b.WriteString(" INNER JOIN ")
		b.WriteString(j.Table)
		b.WriteString(" ON ")
		b.WriteString(strings.Join(j.Conditions, " AND "))
	}
	if len(q.Conditions) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(q.Conditions, " AND "))
	}
	if q.OrderBy != "" {
		b.WriteString(" ORDER BY ")
		b.WriteString(q.OrderBy)
	}
	return b.String()
}

func BuildQuery(table string, mods ...QueryModifier) (string, []any, error) {
	q := Query{Table: table}
	for _, mod := range mods {
		mod(&q)
	}

	// Ensure at least one column is selected
	if len(q.Fields) == 0 {
		return "", []any{}, fmt.Errorf("empty query (no fields selected)")
	}

	s := buildSql(&q)
	return s, q.Args, nil

}
