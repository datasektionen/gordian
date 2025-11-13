job "gordian" {
  namespace = "money"

  type = "service"

  group "gordian" {
    network {
      port "http" {
        to = 3000 # hardcoded (config option never used, see #32)
      }
    }

    service {
      name     = "gordian"
      port     = "http"
      provider = "nomad"
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.gordian.rule=Host(`budget.datasektionen.se`)",
        "traefik.http.routers.gordian.tls.certresolver=default",
      ]
    }

    task "gordian" {
      driver = "docker"

      config {
        image = var.image_tag
        ports = ["http"]
      }

      template {
        data        = <<ENV
SERVER_PORT={{ env "NOMAD_PORT_http" }}
SERVER_URL=https://budget.datasektionen.se
{{ with nomadVar "nomad/jobs/gordian" }}
GO_CONN=postgres://gordian:{{ .db_password }}@postgres.dsekt.internal:5432/gordian?sslmode=disable
CF_CONN=postgres://gordian:{{ .db_password }}@postgres.dsekt.internal:5432/cashflow?sslmode=disable # cursed, should use API
HIVE_TOKEN={{ .hive_token }}
OIDC_CLIENT_SECRET={{.oidc_client_secret}}
APP_SECRET_KEY={{.app_secret_key}}
{{ end }}
OIDC_PROVIDER=http://sso.nomad.dsekt.internal/op
OIDC_CLIENT_ID=gordian
OIDC_REDIRECT_URL=https://budget.datasektionen.se/auth/callback
HIVE_URL=https://hive.datasektionen.se/api/v1
ENV
        destination = "local/.env"
        env         = true
      }
    }
  }
}

variable "image_tag" {
  type = string
  default = "ghcr.io/datasektionen/gordian:latest"
}
