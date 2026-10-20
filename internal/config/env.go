package config

import "os"

type EnvVar struct {
	PsqlconnStringGOrdian  string
	PsqlconnStringCashflow string
	ServerPort             string
	ServerURL              string
}

func GetEnv() EnvVar {

	envConfig := EnvVar{
		//prod
		PsqlconnStringGOrdian:  os.Getenv("GO_CONN"),
		PsqlconnStringCashflow: os.Getenv("CF_CONN"),
		ServerPort:             os.Getenv("SERVER_PORT"),
		ServerURL:              os.Getenv("SERVER_URL"),
	}

	return envConfig
}
