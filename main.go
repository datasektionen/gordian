package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/datasektionen/GOrdian/internal/config"
	"github.com/datasektionen/GOrdian/internal/database"

	"github.com/datasektionen/GOrdian/internal/web"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrations embed.FS

func main() {
	envVar := config.GetEnv()
	dbGO, err := database.Connect(envVar.PsqlconnStringGOrdian)
	if err != nil {
		log.Printf("error accessing GOrdian database: %v", err)
	}

	{
		driver, err := postgres.WithInstance(dbGO, &postgres.Config{})
		if err != nil {
			panic(fmt.Errorf("Failed to migrate 1: %v", err))
		}
		migrations, err := iofs.New(migrations, "migrations")
		if err != nil {
			panic(fmt.Errorf("Failed to migrate 2: %v", err))
		}
		migrator, err := migrate.NewWithInstance("iofs", migrations, "gordian-db", driver)
		if err != nil {
			panic(fmt.Errorf("Failed to migrate 3: %v", err))
		}
		if err := migrator.Up(); err != migrate.ErrNoChange && err != nil {
			panic(fmt.Errorf("Failed to migrate 4: %v", err))
		}
	}

	dbCF, err := database.Connect(envVar.PsqlconnStringCashflow)
	if err != nil {
		log.Printf("error accessing Cashflow database: %v", err)
	}

	if err := web.Mount(http.DefaultServeMux, web.Databases{DBCF: dbCF, DBGO: dbGO}); err != nil {
		panic(err)
	}
	panic(http.ListenAndServe("0.0.0.0:"+config.GetEnv().ServerPort, nil))
}
