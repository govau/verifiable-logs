# Verifiable Log Server

When deployed this server provides an API that allows access to a an arbitrary number of independent RFC6962-style General Transparency logs. The API used to access these is described [here](./rfc6962-objecthash.md).

This is designed to be deployed on CloudFoundry, backed by PostgreSQL, but can also be run easily locally without CloudFoundry

## Local development

```bash
# Use Docker to start a local Postgresql
docker run -p 5435:5432 --name verifiable -e POSTGRES_USER=verifiable -e POSTGRES_PASSWORD=verifiable -d postgres

# Pretend we are a CloudFoundry environment
export VCAP_APPLICATION='{}'
export VCAP_SERVICES='{"postgres": [{"credentials": {"username": "verifiable", "host": "localhost", "password": "verifiable", "name": "verifiable", "port": 5435}, "tags": ["postgres"]}]}'
export PORT=8080
export VDB_SECRET=secret

# For now, only allow a whitelist of tables to map to log names
export VERIFIABLE_TABLENAME_VALIDATOR=whitelist

# With only one entry: mytable
export VERIFIABLE_TABLENAME_VALIDATOR_PARAM=mytable

# Get dependencies
dep ensure

# Build the app
go install github.com/govau/verifiable-logs/cmd/verifiable-logs-server

# Run it
verifiable-logs-server
```

## Next

[Integrate with your database](./database-integration.md)

## Deployment

The following assumes a CloudFoundry installation:

```bash
# Create database
cf create-service postgres shared verifiablelogs-db

# Create a secret used for authn/authz for adding log entries
cf create-user-provided-service verifiablelogs-ups -p '{"VDB_SECRET":"secret","DB_CONNECTIONS":"20","VERIFIABLE_TABLENAME_VALIDATOR":"uuid"}'
```

Build and push:

```bash
# Get dependencies
dep ensure

# Build
GOOS=linux GOARCH=amd64 go build -o deploy/verifiable-logs-server/verifiable-logs-server cmd/verifiable-logs-server/main-verifiable-logs-server.go

# Push
cf push -f deploy/verifiable-logs-server/manifest.yml -p deploy/verifiable-logs-server
```
