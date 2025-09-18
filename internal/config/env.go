package config

import "os"

type EnvVar struct {
	PsqlconnStringGOrdian  string
	PsqlconnStringCashflow string
	LoginAPIURL            string
	LoginFrontendURL       string
	LoginToken             string
	HiveURL                string
	HiveToken              string
	ServerPort             string
	ServerURL              string
}

func GetEnv() EnvVar {

	envConfig := EnvVar{
		//prod
		PsqlconnStringGOrdian:  os.Getenv("GO_CONN"),
		PsqlconnStringCashflow: os.Getenv("CF_CONN"),
		LoginAPIURL:            os.Getenv("LOGIN_API_URL"),
		LoginFrontendURL:       os.Getenv("LOGIN_FRONTEND_URL"),
		LoginToken:             os.Getenv("LOGIN_TOKEN"),
		HiveURL:                os.Getenv("HIVE_URL"),
		HiveToken:              os.Getenv("HIVE_TOKEN"),
		ServerPort:             os.Getenv("SERVER_PORT"),
		ServerURL:              os.Getenv("SERVER_URL"),

		// local
		// PsqlconnStringGOrdian:  "host=localhost port=5432 user=alexander password=kopis dbname=budget_local sslmode=disable",
		// PsqlconnStringCashflow: "host=localhost port=54321 user=cashflow password=cashflow dbname=cashflow sslmode=disable",
		// LoginURL:               "https://login.datasektionen.se",
		// LoginToken:             "this is secret fuck you",
		// HiveURL:                "https://hive.datasektionen.se/api/v1",
		// HiveToken:           	"this is secret fuck you",
		// ServerPort:             "3000",
		// ServerURL:              "http://localhost:3000",
	}

	return envConfig
}
