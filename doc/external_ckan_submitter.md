# External CKAN basic integration

When run this will talk to an external CKAN, and find data in it to write to a verifiable log server.

Note this will only pick up new inserts, not updates, and will not write SCTs back into the database.

This is designed to be deployed on CloudFoundry, backed by PostgreSQL, but can also be run easily locally without CloudFoundry

## Local development

```bash
# Use Docker to start a local Postgresql
docker run -p 5438:5432 --name extintegrator -e POSTGRES_USER=extintegrator -e POSTGRES_PASSWORD=extintegrator -d postgres

# Pretend we are a CloudFoundry environment
export VCAP_APPLICATION='{}'
export VCAP_SERVICES='{"postgres": [{"credentials": {"username": "extintegrator", "host": "localhost", "password": "extintegrator", "name": "extintegrator", "port": 5438}, "tags": ["postgres"]}]}'
export PORT=8082

# The base URL of the verifiable log server
export VERIFIABLE_LOG_SERVER=http://localhost:8080

# The Authorization header to add to /add-objecthash requests
export VERIFIABLE_LOG_API_KEY=secret

# Resources to monitor, comma separated
export CKAN_RESOURCE_IDS=b718232a-bc8d-49c0-9c1f-33c31b57cd88
export CKAN_BASE_URL=https://data.gov.au
export QUE_WORKERS=5

# Get dependencies
dep ensure

# Build the app
go install github.com/govau/verifiable-logs/cmd/submit-from-external

# Run it
submit-from-external
```

## Deployment

The following assumes a CloudFoundry installation:

```bash
# Create database
cf create-service postgres shared verifiablesubmitter-db

# Create a secret used for authn/authz for adding log entries
cf create-user-provided-service verifiablesubmitter-ups -p '{"CKAN_RESOURCE_IDS":"b718232a-bc8d-49c0-9c1f-33c31b57cd88","CKAN_BASE_URL":"https://data.gov.au","QUE_WORKERS":"10","VERIFIABLE_LOG_SERVER":"https://verifiable-logs.apps.y.cld.gov.au","VERIFIABLE_LOG_API_KEY":"secret"}'
```

Build and push:

```bash
# Get dependencies
dep ensure

# Build
GOOS=linux GOARCH=amd64 go build -o deploy/verifiable-submitter/submit-from-external cmd/submit-from-external/main-submit-from-external.go

# Push
cf push -f deploy/verifiable-submitter/manifest.yml -p deploy/verifiable-submitter
```
