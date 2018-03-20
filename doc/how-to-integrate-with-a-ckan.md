# How to integrate with

## Start the Verifiable Log Server

```bash

# No need to initialize the database
docker run -p 5435:5432 --name verifiable -e POSTGRES_USER=verifiable -e POSTGRES_PASSWORD=verifiable -d postgres

export VCAP_APPLICATION='{}'
export VCAP_SERVICES='{"postgres": [{"credentials": {"username": "verifiable", "host": "localhost", "password": "verifiable", "name": "verifiable", "port": 5435}, "tags": ["postgres"]}]}'
export PORT=8080
export VDB_SECRET=secret

go run cmd/verifiable-log/main-verifiable-log.go
```

## Start a CKAN server

### Prep the `datastore` database

This added a new table to the `datastore` database. It is the format defined by [github.com/bgentry/que-go](https://github.com/bgentry/que-go) and used to control adding log jobs.

```bash
docker exec -i db psql -U ckan datastore <<EOF
CREATE TABLE IF NOT EXISTS que_jobs (
    priority    smallint    NOT NULL DEFAULT 100,
    run_at      timestamptz NOT NULL DEFAULT now(),
    job_id      bigserial   NOT NULL,
    job_class   text        NOT NULL,
    args        json        NOT NULL DEFAULT '[]'::json,
    error_count integer     NOT NULL DEFAULT 0,
    last_error  text,
    queue       text        NOT NULL DEFAULT '',
    CONSTRAINT que_jobs_pkey PRIMARY KEY (queue, priority, run_at, job_id)
);
EOF
```

### Create a global trigger function

This is to be done as a CKAN administrator:

```bash
CKAN_KEY=xxx

F="
BEGIN
    INSERT INTO que_jobs (job_class, args)
    VALUES ('update_sct', json_build_object(
        'table', TG_TABLE_NAME,
        'data', NEW
    ));
    RETURN NEW;
END;
"
G=$(echo $F | tr "\n" " ")
D="$(cat <<EOF | jq -c .
{
    "name": "append_to_verifiable_log",
    "or_replace": "true",
    "rettype": "trigger",
    "definition": "${G}"
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" http://localhost:5000/api/3/action/datastore_function_create | jq .
```

### Enable this for a dataset

This can be done as a normal user (table must include a `signed_certificate_timestamp` field as type `text):

```bash
# First time, add: "resource": {"package_id": "xxx"},
# 2nd and subsequent instead use: "resource_id": "xxx",
D="$(cat <<EOF | jq -c .
{
  ...
  "fields": [
    {
      "id": "signed_certificate_timestamp",
      "type": "text"
    },
    {
      "id": "foo",
      "type": "text"
    },
    {
      "id": "bar",
      "type": "text"
    }
  ],
  "primary_key": "foo",
  "triggers": [{
    "function": "append_to_verifiable_log"
  }]
}
EOF
)"

curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}"  http://localhost:5000/api/3/action/datastore_create | jq .
```

### Insert some records to test

This can be done as a normal CKAN user:

```bash
CKAN_RESOURCE=xxx

D="$(cat <<EOF | jq -c .
{
  "method": "upsert",
  "resource_id": "xxx",
  "records": [
    {
      "foo": "1",
      "bar": "2"
    },
    {
      "foo": "3",
      "bar": "4"
    }
  ]
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}"  http://localhost:5000/api/3/action/datastore_upsert | jq .
```

## Start the que_job pusher

```bash
export QUE_WORKERS=5
export VERIFIABLE_LOG_SERVER=http://localhost:8080
export VERIFIABLE_LOG_API_KEY=secret
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=datastore
export PGUSER=ckan
export PGPASSWORD=ckan

go run cmd/que_to_verifiable_pusher/main-que-to-verifiable-pusher.go
```

To checkout database:

```bash
psql "dbname=verifiable host=localhost user=verifiable password=verifiable port=5435"
```

Build and push:

```bash
cfy create-service postgres shared govauverifiabledemo-db
cfy create-user-provided-service govauverifiabledemo-ups -p '{"VDB_SECRET":"secret"}'

# Build and push
dep ensure
GOOS=linux GOARCH=amd64 go build -o cf/verifiable-log/verifiable-log cmd/verifiable-log/main-verifiable-log.go
cfy push -f cf/verifiable-log/manifest.yml -p cf/verifiable-log
```
