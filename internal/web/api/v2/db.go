package v2

import (
	"fmt"
	"strings"
)

type Query struct {
	Table      string
	Fields     []string
	Conditions []string
	Args       []any
	OrderBy    string
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

// Conditions

func Equals(field string, value any) Condition {
	return func(q *Query) string {
		q.Args = append(q.Args, value)
		return fmt.Sprintf("%s = $%d", field, len(q.Args))
	}
}

func buildSql(q *Query) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(strings.Join(q.Fields, ", "))
	b.WriteString(" FROM ")
	b.WriteString(q.Table)
	if len(q.Conditions) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(q.Conditions, " AND "))
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
