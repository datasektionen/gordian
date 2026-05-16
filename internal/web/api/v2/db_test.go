package v2

import (
	"context"
	"database/sql"
	"log"
	"os"
	"slices"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var sharedDB *sql.DB

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()

	c, err := postgres.Run(ctx, "postgres:16-alpine", postgres.WithDatabase("budget"), postgres.WithUsername("alexander"), postgres.WithPassword("kopis"), postgres.WithInitScripts("../../../../migrations/01_init.up.sql", "testdata/fixture.sql"), testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
		WithOccurrence(2).
		WithStartupTimeout(60*time.Second)))
	if err != nil {
		log.Printf("starting postgres: %v", err)
		return 1
	}
	defer func() { _ = c.Terminate(ctx) }()

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("dsn: %v", err)
		return 1
	}
	sharedDB, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("open: %v", err)
		return 1
	}
	defer sharedDB.Close()

	if err := sharedDB.PingContext(ctx); err != nil {
		log.Printf("ping: %v", err)
		return 1
	}

	return m.Run()
}

func TestSelectAllQuery(t *testing.T) {
	stmt, _, err := BuildQuery("budget_lines", Select("*"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}

	var n int
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Ensure all rows were returned
	if got, want := n, 8; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Ensure all columns were returned
	if got, want := cols, []string{"id", "name", "income", "expense", "comment", "account", "secondary_cost_centre_id", "created_at", "updated_at"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSelectOneColumnQuery(t *testing.T) {
	stmt, _, err := BuildQuery("budget_lines", Select("name"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(cols), 1; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, want := cols[0], "name"; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSelectNoColumnQueryGivesError(t *testing.T) {
	stmt, _, err := BuildQuery("budget_lines")
	if err == nil {
		t.Errorf("got %v, want error", stmt)
	}
}

func TestSelectInnerJoin(t *testing.T) {
	stmt, args, err := BuildQuery("budget_lines", Select("budget_lines.name", "secondary_cost_centres.name"), InnerJoin("secondary_cost_centres", Equals(Column("budget_lines.secondary_cost_centre_id"), Column("secondary_cost_centres.id"))), Where(Equals(Column("budget_lines.name"), "Styrelsemiddag")))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var n int
	for rows.Next() {
		var line, sec string
		if err := rows.Scan(&line, &sec); err != nil {
			t.Fatal(err)
		}
		if got, want := line, "Styrelsemiddag"; got != want {
			t.Errorf("budget line: got %v, want %v", got, want)
		}
		if got, want := sec, "Representation"; got != want {
			t.Errorf("secondary cost centre: got %v, want %v", got, want)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got, want := n, 1; got != want {
		t.Errorf("row count: got %v, want %v", got, want)
	}
}

func TestSelectOrderBy(t *testing.T) {
	stmt, args, err := BuildQuery("budget_lines", Select("id"), OrderBy("id ASC"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []int{100, 101, 102, 103, 104, 105, 106, 107}
	if !slices.Equal(ids, want) {
		t.Errorf("got %v, want %v", ids, want)
	}
}

func TestSelectIn(t *testing.T) {
	stmt, args, err := BuildQuery("budget_lines", Select("id"), Where(In(Column("secondary_cost_centre_id"), []int{10, 40})), OrderBy("id ASC"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []int{100, 106, 107}
	if !slices.Equal(ids, want) {
		t.Errorf("got %v, want %v", ids, want)
	}
}

func TestSelectWhere(t *testing.T) {
	stmt, args, err := BuildQuery("budget_lines", Select("name"), Where(Equals(Column("name"), "Mottagningen")))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sharedDB.Query(stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := rows.Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got, want := got, "Mottagningen"; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	}

}
