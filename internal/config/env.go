package config

import "os"

type EnvVar struct {
	PsqlconnStringGOrdian  string
	PsqlconnStringCashflow string
	HiveURL                string
	HiveToken              string
	ServerPort             string
	ServerURL              string
	// OIDC Configuration
	OIDCProvider     	   string
	OIDCClientID     	   string
	OIDCClientSecret 	   string
	OIDCRedirectURL  	   string
	AppSecretKey     	   string
}

func GetEnv() EnvVar {

	envConfig := EnvVar{
		//prod
		PsqlconnStringGOrdian:  os.Getenv("GO_CONN"),
		PsqlconnStringCashflow: os.Getenv("CF_CONN"),
		HiveURL:                os.Getenv("HIVE_URL"),
		HiveToken:              os.Getenv("HIVE_TOKEN"),
		ServerPort:             os.Getenv("SERVER_PORT"),
		ServerURL:              os.Getenv("SERVER_URL"),
		// OIDC Configuration
		OIDCProvider:     		os.Getenv("OIDC_PROVIDER"),
		OIDCClientID:     		os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: 		os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  		os.Getenv("OIDC_REDIRECT_URL"),
		AppSecretKey:     		os.Getenv("APP_SECRET_KEY"),
	}

	return envConfig
}
