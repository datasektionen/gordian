package v2

import (
	"database/sql"
	"time"

	"github.com/graphql-go/graphql"
)

var costCentreType = graphql.NewObject(graphql.ObjectConfig{
	Name: "CostCentre",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.Int,
		},
		"name": &graphql.Field{
			Type: graphql.String,
		},
		"type": &graphql.Field{
			Type: graphql.String,
		},
		"created_at": &graphql.Field{
			Type: graphql.DateTime,
		},
		"updated_at": &graphql.Field{
			Type: graphql.DateTime,
		},
	},
})

type CostCentre struct {
	ID        int
	Name      string
	Type      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewSchema(db *sql.DB) (graphql.Schema, error) {
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
		},
	})

	var schema, _ = graphql.NewSchema(graphql.SchemaConfig{
		Query: queryType,
	})

	return schema, nil
}
