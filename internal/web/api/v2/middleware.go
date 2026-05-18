package v2

import (
	"net/http"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
)

// RequireGET restricts the endpoint to GET only, rejects other methods
func RequireGET(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

// GraphQLMiddleware restricts the maximum allowed depth of GraphQL requests before they are processed.
func GraphQLMiddleware(h http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// GraphQL accepts queries in both GET params and POST body, but for now we only allow
		// GET requests, so we only check those.
		q := r.URL.Query().Get("query")
		if q == "" {
			// No query means this is likely a GraphiQL/UI request — let the
			// handler decide what to do.
			h.ServeHTTP(w, r)
			return
		}
		doc, err := parser.Parse(parser.ParseParams{Source: q})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		// To find the maximum depth, we want to traverse the abstract syntax tree and find the deepest
		// level of selection sets
		// https://pkg.go.dev/github.com/graphql-go/graphql@v0.8.1/language/ast#SelectionSet

		// doc is the AST root
		for _, d := range doc.Definitions {

			// doc can contain two types of definitions: OperationDefinition and FragmentDefinition
			// https://spec.graphql.org/October2021/#Document
			if op, ok := d.(*ast.OperationDefinition); ok {
				count := countMaxSelectionSets(op.SelectionSet)
				if count > 4 {
					http.Error(w, "Maximum GraphQL query depth exceeded", http.StatusBadRequest)
					return
				}
			}
			if fd, ok := d.(*ast.FragmentDefinition); ok {
				count := countMaxSelectionSets(fd.SelectionSet)
				if count > 4 {
					http.Error(w, "Maximum GraphQL query depth exceeded", http.StatusBadRequest)
					return
				}
			}
		}

		h.ServeHTTP(w, r)
	})
}

func countMaxSelectionSets(s *ast.SelectionSet) int {
	// TODO: Check inline fragments
	maxDepth := 0
	for _, selection := range s.Selections {

		set := selection.GetSelectionSet()
		if set != nil {
			count := countMaxSelectionSets(set)
			if count > maxDepth {
				maxDepth = count
			}
		}

	}
	return 1 + maxDepth
}
