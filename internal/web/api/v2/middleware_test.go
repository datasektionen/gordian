package v2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

// depthLimit is the maximum allowed nesting for queries in these tests.
const depthLimit = 4

// acceptedQueries are fragment-free queries at or below depthLimit.
var acceptedQueries = []string{
	// depth 1
	`{ a }`,                   // depth 2
	`{ a { b } }`,             // depth 3
	`{ a { b { c } } }`,       // depth 4 — exactly at the limit
	`{ a { b { c { d } } } }`, // depth 2, multiple top-level selections with aliases
	`{ x: a y: a { b } }`,
}

// acceptedQueriesWithFragments are queries using inline fragments or fragment
// spreads whose effective (expanded) depth is at or below depthLimit.
var acceptedQueriesWithFragments = []string{
	// depth 3 with an inline fragment in the middle (does not add depth)
	`{ a { b { ... on T { c } } } }`, // depth 4 reached via a fragment spread (fragment's body is depth 1)
	`query Q { a { b { c { ...frag } } } } fragment frag on T { d }`,
}

// forbiddenQueries are fragment-free queries that exceed depthLimit.
var forbiddenQueries = []string{
	// depth 5
	`{ a { b { c { d { e } } } } }`,       // depth 6
	`{ a { b { c { d { e { f } } } } } }`, // depth 5 buried under an alias
	`{ outer: a { b { c { d { e } } } } }`,
}

// forbiddenQueriesWithFragments exceed depthLimit only after inline fragments
// or fragment spreads are taken into account.
var forbiddenQueriesWithFragments = []string{
	// depth 5 reached via a fragment spread (operation is depth 4, fragment adds 1)
	`query Q { a { b { c { ...frag } } } } fragment frag on T { d { e } }`, // depth 5 via inline fragment + nested selection
	`{ a { b { c { ... on T { d { e } } } } } }`,
}

// testSchema returns a minimal schema with a scalar field and one nested
// object, enough to construct queries at varying depths.
func testSchema(t *testing.T) graphql.Schema {
	t.Helper()

	nested := graphql.NewObject(graphql.ObjectConfig{
		Name: "Nested",
		Fields: graphql.Fields{
			"value": &graphql.Field{
				Type:    graphql.String,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) { return "ok", nil },
			},
		},
	})

	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"hello": &graphql.Field{
				Type:    graphql.String,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) { return "world", nil },
			},
			"nested": &graphql.Field{
				Type:    nested,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) { return struct{}{}, nil },
			},
		},
	})

	s, err := graphql.NewSchema(graphql.SchemaConfig{Query: query})
	if err != nil {
		t.Fatalf("build test schema: %v", err)
	}
	return s
}

func TestPostNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	RequireGET(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// runQueries sends each query through GraphQLMiddleware and asserts the
// resulting status code matches wantStatus.
func runQueries(t *testing.T, queries []string, wantStatus int) {
	t.Helper()
	schema := testSchema(t)
	for i, q := range queries {
		h := handler.New(&handler.Config{Schema: &schema})

		p := url.QueryEscape(q)
		req := httptest.NewRequest(http.MethodGet, "/api/v2/graphql/?query="+p, nil)
		w := httptest.NewRecorder()

		GraphQLMiddleware(h).ServeHTTP(w, req)

		if w.Code != wantStatus {
			t.Errorf("case #%d %q: got %d, want %d", i, q, w.Code, wantStatus)
		}
	}
}

func TestAcceptedQueries(t *testing.T) {
	runQueries(t, acceptedQueries, http.StatusOK)
}

func TestAcceptedQueriesWithFragments(t *testing.T) {
	runQueries(t, acceptedQueriesWithFragments, http.StatusOK)
}

func TestForbiddenQueries(t *testing.T) {
	runQueries(t, forbiddenQueries, http.StatusBadRequest)
}

func TestForbiddenQueriesWithFragments(t *testing.T) {
	runQueries(t, forbiddenQueriesWithFragments, http.StatusBadRequest)
}
