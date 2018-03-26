# CKAN integration

If you have CKAN integration, this model can work with it.

The steps are:

1. Define the `que_job` table as per the [database integration guide](./database-integration.md).
2. Have a system administrator create a trigger function that tables can use.
3. Have a dataset owner add a special field to their tables, and opt-in to use the trigger function.

Full demo script is below:

## Run local CKAN

```bash
# Get CKAN
git clone git@github.com:ckan/ckan.git

cd ckan/

# Tweak docker compose to expose database port to local host
git apply <<EOF 
diff --git a/contrib/docker/docker-compose.yml b/contrib/docker/docker-compose.yml
index b40cdfb91..624a2ab2c 100644
--- a/contrib/docker/docker-compose.yml
+++ b/contrib/docker/docker-compose.yml
@@ -58,6 +58,8 @@ services:
       - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
     volumes:
       - pg_data:/var/lib/postgresql/data
+    ports:
+      - "5432:5432"
 
   solr:
     container_name: solr
EOF

# Copy docker compose conf
cp contrib/docker/.env.template contrib/docker/.env

# Start it up
cd contrib/docker/
docker-compose up -d --build

# Check all are running - expect to see 5 - if less, run previous step again
docker ps

# Edit ckan production.ini to include datastore:
# Edit: ckan.plugins = datastore <other stuff>
docker exec -ti ckan vi /etc/ckan/production.ini

# Run this:
docker exec ckan /usr/local/bin/ckan-paster --plugin=ckan datastore set-permissions -c /etc/ckan/production.ini | docker exec -i db psql -U ckan

# Restart CKAN
docker-compose restart ckan

# Add que_jobs table to database
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
    _full_text  text        DEFAULT 'TODO fix, this is ignored but here so as to not interfere with zfulltext',
    CONSTRAINT que_jobs_pkey PRIMARY KEY (queue, priority, run_at, job_id)
);
EOF

# Create admin account
docker exec -it ckan /usr/local/bin/ckan-paster --plugin=ckan sysadmin -c /etc/ckan/production.ini add admin
```

## Run log server

In a new terminal, run the log server:

```bash
# Use Docker to start a local Postgresql
docker run -p 5435:5432 --name verifiable -e POSTGRES_USER=verifiable -e POSTGRES_PASSWORD=verifiable -d postgres

# Pretend we are a CloudFoundry environment
export VCAP_APPLICATION='{}'
export VCAP_SERVICES='{"postgres": [{"credentials": {"username": "verifiable", "host": "localhost", "password": "verifiable", "name": "verifiable", "port": 5435}, "tags": ["postgres"]}]}'
export PORT=8080
export VDB_SECRET=secret
export VERIFIABLE_TABLENAME_VALIDATOR=uuid

verifiable-logs-server
```

## Run log submitter

And in another, the log submitter:

```bash
# The number of threads to process the database
export QUE_WORKERS=5

# The que queue to service, must match what trigger sets
export QUE_QUEUE=verifiable-logs

# See `table_name_validator.go`. "uuid" is another fine option, in which case no _PARAM is needed
export VERIFIABLE_TABLENAME_VALIDATOR=uuid

# The base URL of the verifiable log server
export VERIFIABLE_LOG_SERVER=http://localhost:8080

# The Authorization header to add to /add-objecthash requests
export VERIFIABLE_LOG_API_KEY=secret

# Connection info for the PostgreSQL database (that has que_jobs in it) - all libpq env variables are supported
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=datastore
export PGUSER=ckan
export PGPASSWORD=ckan

# Run
submit-rows-to-logs
```

## Use API to submit data that is logged

Take note of your API key (from a few steps ago), and URL:

```bash
CKAN_KEY=xxx
CKAN_URL=http://localhost:5000
```

Now let's use the API to utilize this:

```bash
# Add global trigger function
D="$(cat <<EOF | jq -c .
{
    "name": "append_to_verifiable_log",
    "or_replace": "true",
    "rettype": "trigger",
    "definition": "BEGIN INSERT INTO que_jobs (queue, job_class, args) VALUES ('verifiable-logs', 'update_sct', json_build_object('table', TG_TABLE_NAME, 'data', NEW)); RETURN NEW; END;"
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" ${CKAN_URL}/api/3/action/datastore_function_create | jq .

# Create organisation
D="$(cat <<EOF | jq -c .
{
  "name": "verifiabledemoorg",
  "title": "Verifiable Demo Organisation"
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" ${CKAN_URL}/api/3/action/organization_create | jq .

# Create package
D="$(cat <<EOF | jq -c .
{
  "name": "verifabledemopackage",
  "title": "Verifable Demo Package",
  "owner_org": "verifiabledemoorg"
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" ${CKAN_URL}/api/3/action/package_create | jq .

# Take note of the package ID:
CKAN_PACKAGE="$(curl ${CKAN_URL}/api/3/action/package_search | jq -r '.result.results[]|select(.name=="verifabledemopackage")|.id')"

# Create a resource with special field, and invoke trigger
D="$(cat <<EOF | jq -c .
{
  "resource": {
    "package_id": "${CKAN_PACKAGE}",
    "name": "verifiabledemoresource"
  },
  "fields": [
    {
      "id": "signed_certificate_timestamp",
      "type": "text"
    },
    {
      "id": "key",
      "type": "text"
    },
    {
      "id": "value",
      "type": "text"
    }
  ],
  "primary_key": "key",
  "triggers": [{
    "function": "append_to_verifiable_log"
  }]
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" ${CKAN_URL}/api/3/action/datastore_create | jq .

# Take note of the ID
CKAN_RESOURCE=xxx

# Insert some stuff
D="$(cat <<EOF | jq -c .
{
  "resource_id": "${CKAN_RESOURCE}",
  "records": [
    {"key": "foo1", "value": "bar"},
    {"key": "foo2", "value": "bar"},
    {"key": "foo3", "value": "bar"},
    {"key": "foo4", "value": "bar"},
    {"key": "foo5", "value": "bar"},
    {"key": "foo6", "value": "bar"},
    {"key": "foo7", "value": "bar"},
    {"key": "foo9", "value": "bar"},
    {"key": "foo10", "value": "bar"},
    {"key": "foo11", "value": "bar"},
    {"key": "foo12", "value": "bar"}
  ]
}
EOF
)"
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" ${CKAN_URL}/api/3/action/datastore_upsert | jq .
```

Watch in CKAN: <http://localhost:5000/dashboard/>

Watch on log server: <http://localhost:5000/dataset/${CKAN_RESOURCE}/>


## Clean up

```bash
# Stop all instances
docker stop $(docker ps -q)

# Delete all instances
docker rm $(docker ps -qa)

# Delete all volumes
docker volume rm $(docker volume ls -q)
```
