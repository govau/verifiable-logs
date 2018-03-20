# Submit Rows to Logs

This tool looks for jobs in the database `que_jobs` table, then submits the entries found to logs are the appropriate base URL, then updates the original row with the signed certificate timestamp returned.

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

# Connection info for the PostgreSQL database (that has que_jobs in it) - all libpq env variables are supported
export PGHOST=localhost
export PGPORT=5436
export PGDATABASE=mydb
export PGUSER=mydb
export PGPASSWORD=mydb

# Install dependencies
dep ensure

# Build the app
go install github.com/govau/verifiable-logs/cmd/submit-rows-to-logs

# Run
submit-rows-to-logs
```

This should pick up the row added previously. Verify by (in your previous `psql` prompt) seeing the `signed_certificate_timestamp` field now populated:

```sql
SELECT * FROM mytable;
 _id |                                                                   signed_certificate_timestamp                                                                   | foo |              bar              
-----+------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----+-------------------------------
   1 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHtkSYAAAQDAEgwRgIhAJGl3ZuPLM/MJTu4Vhy6zs43I6cExWCzBU9YVoONtEMtAiEA5hn4AckRnntPvGrhSZ7ZEyRt7ZjuaLdBonx9a4oyk0I= | hi  | 2018-03-20 05:40:35.780239+00
(1 row)
```

## Next

Now, let's [play with a log](./log-experiments.md).