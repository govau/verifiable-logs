# Submit Rows to Logs

This tool looks for jobs in the database `que_jobs` table, then submits the entries found to logs are the appropriate base URL.

## Build / install

```bash
dep ensure
go install github.com/govau/verifiable-logs/cmd/submit-rows-to-logs
```

## Run

```bash
# The number of threads to process the database
export QUE_WORKERS=5

# The que queue to service, must match what trigger sets
export QUE_QUEUE=verifiable-logs

# See `table_name_validator.go`. "uuid" is another fine option, in which case no _PARAM is needed
export VERIFIABLE_TABLENAME_VALIDATOR=whitelist
export VERIFIABLE_TABLENAME_VALIDATOR_PARAM=mytable

# The base URL of the verifiable log server
export VERIFIABLE_LOG_SERVER=http://localhost:8080

# The Authorization header to add to /add-objecthash requests
export VERIFIABLE_LOG_API_KEY=secret

# Connection info for the PostgreSQL database - all libpq env variables are supported
export PGHOST=localhost
export PGPORT=5435
export PGDATABASE=verifiable
export PGUSER=verifiable
export PGPASSWORD=verifiable

# Run
submit-rows-to-logs
```
