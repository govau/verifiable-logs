package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/benlaurie/objecthash/go/objecthash"

	"github.com/govau/verifiable-log/pb"
	"github.com/jackc/pgx"
)

/*
Please set:

PGHOST=localhost
PGPORT=5432
PGDATABASE=datastore
PGUSER=ckan
PGPASSWORD=""

(and any other variables suported by libpq)

# Number of worker threads against database to use, we will open 2x that connection pool objects
QUE_WORKERS=5

# Server to submit data to
VERIFIABLE_LOG_SERVER=xxx

# API key for server
VERIFIABLE_LOG_API_KEY=xxx


Prep in CKAN:

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
curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}"  http://localhost:5000/api/3/action/datastore_function_create | jq .

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

CKAN_RESOURCE=xxx

D="$(cat <<EOF | jq -c .
{
  "method": "upsert",
  "resource_id": "1aadfa79-bf6d-4812-b254-b6df73e92aef",
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

*/

type logAddHandler struct {
	Server string
	APIKey string
}

func (h *logAddHandler) addToVerifiableLog(job *que.Job) error {
	client := pb.NewQueHandlerProtobufClient(h.Server, http.DefaultClient)

	var jd struct {
		Table string                 `json:"table"`
		Data  map[string]interface{} `json:"data"`
	}
	err := json.Unmarshal(job.Args, &jd)
	if err != nil {
		return err
	}

	dataToSend := make(map[string]interface{})
	for k, v := range jd.Data {
		// Don't count the internal fields
		if strings.HasPrefix(k, "_") {
			continue
		}
		// Don't count the SCT itself
		if k == "signed_certificate_timestamp" {
			continue
		}
		// Ignore null values so that columns can be added over time
		if v == nil {
			continue
		}
		dataToSend[k] = v
	}

	oh, err := objecthash.ObjectHash(dataToSend)
	if err != nil {
		return err
	}

	bb, err := json.Marshal(dataToSend)
	if err != nil {
		return err
	}

	currentSCT, _ := jd.Data["signed_certificate_timestamp"].(string)
	id, _ := jd.Data["_id"].(int)
	// TODO - verify if existing SCT matches data, and terminate early if so
	// In fact, given that we'll trigger ourselves, we better do that!

	resp, err := client.AddToLog(context.Background(), &pb.AddToLogReq{
		Auth: &pb.Authorization{
			ApiKey: h.APIKey,
		},
		Table: jd.Table,
		Data:  string(bb),
	})
	if err != nil {
		return err
	}

	if resp.SignedCertificateTimestamp == currentSCT {
		// We're done, no work required, return
		return nil
	}

	_, err = job.Conn().Exec(fmt.Sprintf(`UPDATE "%s" SET signed_certificate_timestamp = $1 WHERE _id = $2`, jd.Table), resp.SignedCertificateTimestamp, id)
	if err != nil {
		return err
	}

	// We're done
	return nil
}

func main() {
	workerCount, err := strconv.Atoi(os.Getenv("QUE_WORKERS"))
	if err != nil {
		log.Fatal(err)
	}

	config, err := pgx.ParseEnvLibpq()
	if err != nil {
		log.Fatal(err)
	}

	pgxPool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		MaxConnections: workerCount * 2,
		ConnConfig:     config,
		AfterConnect:   que.PrepareStatements,
	})
	if err != nil {
		log.Fatal(err)
	}

	qc := que.NewClient(pgxPool)
	workers := que.NewWorkerPool(qc, que.WorkMap{
		"update_sct": (&logAddHandler{
			Server: os.Getenv("VERIFIABLE_LOG_SERVER"),
			APIKey: os.Getenv("VERIFIABLE_LOG_API_KEY"),
		}).addToVerifiableLog,
	}, workerCount)

	// Prepare a shutdown function
	shutdown := func() {
		workers.Shutdown()
		pgxPool.Close()
	}

	// Normal exit (which is dead code really, due to the select {} later)
	// but we leave it here anyway as it's a fine habit
	defer shutdown()

	// Or via signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, starting shutdown...", sig)
		shutdown()
		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	go workers.Start()

	log.Println("Started up... waiting for ctrl-C.")
	select {}
}
