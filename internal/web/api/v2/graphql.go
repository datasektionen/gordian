package v2

import (
	"database/sql"
	"time"

	"github.com/graphql-go/graphql"
)

type CostCentre struct {
	ID                   int
	Name                 string
	Type                 string
	CreatedAt            *time.Time
	UpdatedAt            *time.Time
	SecondaryCostCentres []SecondaryCostCentre
	BudgetLines          []BudgetLine
}

type SecondaryCostCentre struct {
	ID          int
	Name        string
	CostCentre  CostCentre
	CreatedAt   *time.Time
	UpdatedAt   *time.Time
	BudgetLines []BudgetLine
}
type BudgetLine struct {
	ID                  int
	Name                string
	Income              int
	Expense             int
	Comment             *string
	Account             *string
	SecondaryCostCentre SecondaryCostCentre
	CostCentre          CostCentre
}

func NewSchema(db *sql.DB) (graphql.Schema, error) {

	// Cyclic type handling
	var costCentreType, secondaryCostCentreType, budgetLineType *graphql.Object

	budgetLineType = graphql.NewObject(graphql.ObjectConfig{
		Name: "BudgetLine",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id": &graphql.Field{
					Type: graphql.Int,
				},
				"name": &graphql.Field{
					Type: graphql.String,
				},
				"income": &graphql.Field{
					Type: graphql.Int,
				},
				"expense": &graphql.Field{
					Type: graphql.Int,
				},
				"comment": &graphql.Field{
					Type: graphql.String,
				},
				"account": &graphql.Field{
					Type: graphql.String,
				},
				"secondaryCostCentre": &graphql.Field{
					Type: secondaryCostCentreType,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						bl := p.Source.(BudgetLine)
						stmt, args, err := BuildQuery("secondary_cost_centres", Select("id", "name", "cost_centre_id", "created_at", "updated_at"), Where(Equals(Column("id"), bl.SecondaryCostCentre.ID)))
						if err != nil {
							return nil, err
						}
						row := db.QueryRow(stmt, args...)
						var scc SecondaryCostCentre
						if err := row.Scan(&scc.ID, &scc.Name, &scc.CostCentre.ID, &scc.CreatedAt, &scc.UpdatedAt); err != nil {
							return nil, err
						}
						return scc, nil
					},
				},
				"costCentre": &graphql.Field{
					Type: costCentreType,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						bl := p.Source.(BudgetLine)
						stmt, args, err := BuildQuery("cost_centres cc", Select("cc.id", "cc.name", "cc.type", "cc.created_at", "cc.updated_at"), InnerJoin("secondary_cost_centres scc", Equals(Column("scc.cost_centre_id"), Column("cc.id"))), Where(Equals(Column("scc.id"), bl.SecondaryCostCentre.ID)))
						if err != nil {
							return nil, err
						}
						row := db.QueryRow(stmt, args...)
						var cc CostCentre
						if err := row.Scan(&cc.ID, &cc.Name, &cc.Type, &cc.CreatedAt, &cc.UpdatedAt); err != nil {
							return nil, err
						}
						return cc, nil
					},
				},
				"createdAt": &graphql.Field{
					Type: graphql.DateTime,
				},
				"updatedAt": &graphql.Field{
					Type: graphql.DateTime,
				},
			}
		}),
	})

	secondaryCostCentreType = graphql.NewObject(graphql.ObjectConfig{
		Name: "SecondaryCostCentre",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id": &graphql.Field{
					Type: graphql.Int,
				},
				"name": &graphql.Field{
					Type: graphql.String,
				},
				"createdAt": &graphql.Field{
					Type: graphql.DateTime,
				},
				"updatedAt": &graphql.Field{
					Type: graphql.DateTime,
				},
				"costCentre": &graphql.Field{
					Type: costCentreType,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						scc := p.Source.(SecondaryCostCentre)
						stmt, args, err := BuildQuery("cost_centres", Select("id", "name", "type", "created_at", "updated_at"), Where(Equals(Column("id"), scc.CostCentre.ID)))
						if err != nil {
							return nil, err
						}
						row := db.QueryRow(stmt, args...)
						var cc CostCentre
						if err := row.Scan(&cc.ID, &cc.Name, &cc.Type, &cc.CreatedAt, &cc.UpdatedAt); err != nil {
							return nil, err
						}
						return cc, nil
					},
				},
				"budgetLines": &graphql.Field{
					Type: graphql.NewList(budgetLineType),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						scc := p.Source.(SecondaryCostCentre)
						stmt, args, err := BuildQuery("budget_lines", Select("id", "name", "income", "expense", "comment", "account"), Where(Equals(Column("secondary_cost_centre_id"), scc.ID)))
						if err != nil {
							return nil, err
						}
						rows, err := db.Query(stmt, args...)
						if err != nil {
							return nil, err
						}
						defer rows.Close()

						var lines []BudgetLine
						for rows.Next() {
							var line BudgetLine
							if err := rows.Scan(&line.ID, &line.Name, &line.Income, &line.Expense, &line.Comment, &line.Account); err != nil {
								return nil, err
							}
							lines = append(lines, line)
						}
						if err := rows.Err(); err != nil {
							return nil, err
						}
						return lines, nil
					},
				},
			}
		}),
	})

	costCentreType = graphql.NewObject(graphql.ObjectConfig{
		Name: "CostCentre",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id": &graphql.Field{
					Type: graphql.Int,
				},
				"name": &graphql.Field{
					Type: graphql.String,
				},
				"type": &graphql.Field{
					Type: graphql.String,
				},
				"createdAt": &graphql.Field{
					Type: graphql.DateTime,
				},
				"updatedAt": &graphql.Field{
					Type: graphql.DateTime,
				},
				"secondaryCostCentres": &graphql.Field{
					Type: graphql.NewList(secondaryCostCentreType),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						cc := p.Source.(CostCentre)
						stmt, args, err := BuildQuery("secondary_cost_centres", Select("id", "name", "created_at", "updated_at"), Where(Equals(Column("cost_centre_id"), cc.ID)))
						if err != nil {
							return nil, err
						}
						rows, err := db.Query(stmt, args...)
						if err != nil {
							return nil, err
						}
						defer rows.Close()

						var sccs []SecondaryCostCentre
						for rows.Next() {
							var scc SecondaryCostCentre
							if err := rows.Scan(&scc.ID, &scc.Name, &scc.CreatedAt, &scc.UpdatedAt); err != nil {
								return nil, err
							}
							sccs = append(sccs, scc)
						}
						if err := rows.Err(); err != nil {
							return nil, err
						}
						return sccs, nil
					},
				},
				"budgetLines": &graphql.Field{
					Type: graphql.NewList(budgetLineType),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						cc := p.Source.(CostCentre)
						stmt, args, err := BuildQuery("budget_lines", Select("budget_lines.id", "budget_lines.name", "budget_lines.income", "budget_lines.expense", "budget_lines.comment", "budget_lines.account", "budget_lines.secondary_cost_centre_id"), InnerJoin("secondary_cost_centres", Equals(Column("budget_lines.secondary_cost_centre_id"), Column("secondary_cost_centres.id"))), Where(Equals(Column("secondary_cost_centres.cost_centre_id"), cc.ID)))
						if err != nil {
							return nil, err
						}
						rows, err := db.Query(stmt, args...)
						if err != nil {
							return nil, err
						}
						defer rows.Close()

						var bls []BudgetLine
						for rows.Next() {
							var bl BudgetLine
							if err := rows.Scan(&bl.ID, &bl.Name, &bl.Income, &bl.Expense, &bl.Comment, &bl.Account, &bl.SecondaryCostCentre.ID); err != nil {
								return nil, err
							}
							bls = append(bls, bl)
						}
						if err := rows.Err(); err != nil {
							return nil, err
						}
						return bls, nil
					},
				},
			}
		}),
	})

	var queryType = graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"costCentres": &graphql.Field{
				Type:        graphql.NewList(costCentreType),
				Description: "List cost centres",
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {

					stmt, args, err := BuildQuery("cost_centres", Select("id", "name", "type", "created_at", "updated_at"))

					if err != nil {
						return nil, err
					}
					rows, err := db.Query(stmt, args...)
					if err != nil {
						return nil, err
					}
					defer rows.Close()

					var ccs []CostCentre
					for rows.Next() {
						var cc CostCentre
						if err := rows.Scan(&cc.ID, &cc.Name, &cc.Type, &cc.CreatedAt, &cc.UpdatedAt); err != nil {
							return nil, err
						}
						ccs = append(ccs, cc)
					}

					return ccs, nil

				},
			},
			"secondaryCostCentres": &graphql.Field{
				Type:        graphql.NewList(secondaryCostCentreType),
				Description: "List secondary cost centres",
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					stmt, args, err := BuildQuery("secondary_cost_centres", Select("id", "name", "cost_centre_id", "created_at", "updated_at"))
					if err != nil {
						return nil, err
					}
					rows, err := db.Query(stmt, args...)
					if err != nil {
						return nil, err
					}
					defer rows.Close()
					var sccs []SecondaryCostCentre
					for rows.Next() {
						var scc SecondaryCostCentre
						if err := rows.Scan(&scc.ID, &scc.Name, &scc.CostCentre.ID, &scc.CreatedAt, &scc.UpdatedAt); err != nil {
							return nil, err
						}
						sccs = append(sccs, scc)
					}
					if err := rows.Err(); err != nil {
						return nil, err
					}
					return sccs, nil

				},
			},
			"budgetLines": &graphql.Field{
				Type:        graphql.NewList(budgetLineType),
				Description: "List budget lines",
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					stmt, args, err := BuildQuery("budget_lines", Select("id", "name", "income", "expense", "comment", "account", "secondary_cost_centre_id"))
					if err != nil {
						return nil, err
					}
					rows, err := db.Query(stmt, args...)
					if err != nil {
						return nil, err
					}
					defer rows.Close()
					var bls []BudgetLine
					for rows.Next() {
						var bl BudgetLine
						if err := rows.Scan(&bl.ID, &bl.Name, &bl.Income, &bl.Expense, &bl.Comment, &bl.Account, &bl.SecondaryCostCentre.ID); err != nil {
							return nil, err
						}
						bls = append(bls, bl)
					}
					if err := rows.Err(); err != nil {
						return nil, err
					}
					return bls, nil
				},
			},
		},
	})

	schema, err := graphql.NewSchema(graphql.SchemaConfig{
		Query: queryType,
	})
	if err != nil {
		return graphql.Schema{}, err
	}

	return schema, nil
}
