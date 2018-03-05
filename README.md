# Running locally

```bash
docker run -p 5435:5432 --name verifiable -e POSTGRES_USER=verifiable -e POSTGRES_PASSWORD=verifiable -d postgres

export VCAP_APPLICATION='{}'
export VCAP_SERVICES='{"postgres": [{"credentials": {"username": "verifiable", "host": "localhost", "password": "verifiable", "name": "verifiable", "port": 5435}, "tags": ["postgres"]}]}'
export PORT=8080

go run cmd/verifiable-log/main-verifiable-log.go
```

To checkout database:

```bash
psql "dbname=verifiable host=localhost user=verifiable password=verifiable port=5435"
```

Build and push:

```bash
cfy create-service postgres shared govauverifiabledemo

# Build and push
dep ensure
GOOS=linux GOARCH=amd64 go build -o cf/verifiable-log/certwatch cmd/verifiable-log/main-verifiable-log.go
cfy push -f cf/verifiable-log/manifest.yml -p cf/verifiable-log
```