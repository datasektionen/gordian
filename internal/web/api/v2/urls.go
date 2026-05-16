package v2

import (
	"net/http"

	"github.com/datasektionen/GOrdian/internal/web"
	"github.com/graphql-go/handler"
)

func RegisterRoutes(mux *http.ServeMux, databases web.Databases) {

	schema, err := NewSchema(databases.DBGO)
	if err != nil {
		panic(err)
	}
	h := handler.New(&handler.Config{
		Schema:   &schema,
		Pretty:   true,
		GraphiQL: true,
	})

	mux.Handle("/api/v2/graphql", h)

}
