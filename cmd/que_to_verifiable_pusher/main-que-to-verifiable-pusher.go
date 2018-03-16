package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/benlaurie/objecthash/go/objecthash"
	que "github.com/bgentry/que-go"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	uuid "github.com/satori/go.uuid"

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

	verifierMutex sync.RWMutex
	verifiers     map[string]*ct.SignatureVerifier

	logClientMutex sync.RWMutex
	logClients     map[string]*client.LogClient

	publicKeyMutex sync.RWMutex
	publicKeyDERs  map[string][]byte
}

// Table name must already be canonical
func (h *logAddHandler) baseURLForLog(canonTable string) string {
	return fmt.Sprintf("%s/dataset/%s", h.Server, canonTable)
}

// Table name must already be canonical
func (h *logAddHandler) getLogClient(canonTable string) (*client.LogClient, error) {
	var rv *client.LogClient

	h.logClientMutex.RLock()
	if h.logClients != nil {
		rv = h.logClients[canonTable]
	}
	h.logClientMutex.RUnlock()

	if rv != nil {
		return rv, nil
	}

	der, err := h.getPublicKeyDER(canonTable)
	if err != nil {
		return nil, err
	}

	rv, err = client.New(h.baseURLForLog(canonTable), http.DefaultClient, jsonclient.Options{
		PublicKeyDER: der,
	})
	if err != nil {
		return nil, err
	}

	h.logClientMutex.Lock()
	defer h.logClientMutex.Unlock()

	if h.logClients == nil {
		h.logClients = make(map[string]*client.LogClient)
	}
	h.logClients[canonTable] = rv

	return rv, nil
}

// Table name must already be canonical
func (h *logAddHandler) getVerifier(canonTable string) (*ct.SignatureVerifier, error) {
	var rv *ct.SignatureVerifier

	h.verifierMutex.RLock()
	if h.verifiers != nil {
		rv = h.verifiers[canonTable]
	}
	h.verifierMutex.RUnlock()

	if rv != nil {
		return rv, nil
	}

	der, err := h.getPublicKeyDER(canonTable)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	rv, err = ct.NewSignatureVerifier(pubKey)
	if err != nil {
		return nil, err
	}

	h.verifierMutex.Lock()
	defer h.verifierMutex.Unlock()

	if h.verifiers == nil {
		h.verifiers = make(map[string]*ct.SignatureVerifier)
	}
	h.verifiers[canonTable] = rv

	return rv, nil
}

// Table name must already be canonical
func (h *logAddHandler) getPublicKeyDER(canonTable string) ([]byte, error) {
	var rv []byte
	h.publicKeyMutex.RLock()
	if h.publicKeyDERs != nil {
		rv = h.publicKeyDERs[canonTable]
	}
	h.publicKeyMutex.RUnlock()

	if rv != nil {
		return rv, nil
	}

	// Go fetch it, grab a mutex so we don't slam servers
	h.publicKeyMutex.Lock()
	defer h.publicKeyMutex.Unlock()

	if h.publicKeyDERs == nil {
		h.publicKeyDERs = make(map[string][]byte)
	}

	// One last check, since we now have a write mutex
	rv = h.publicKeyDERs[canonTable]
	if rv != nil {
		return rv, nil
	}

	resp, err := http.Get(h.baseURLForLog(canonTable) + "/metadata")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad http status code fetching log metadata")
	}

	var md MetadataResponse
	err = json.NewDecoder(resp.Body).Decode(&md)
	if err != nil {
		return nil, err
	}

	h.publicKeyDERs[canonTable] = md.Key
	return md.Key, nil
}

// MetadataResponse is a subset of a log as defined at: https://www.gstatic.com/ct/log_list/log_list_schema.json
type MetadataResponse struct {
	Key []byte `json:"key"`
}

// table name must already be canonical
func (h *logAddHandler) verifyIt(table, sctBase64 string, hash []byte) error {
	curBytes, err := base64.StdEncoding.DecodeString(sctBase64)
	if err != nil {
		return err
	}
	var sct ct.SignedCertificateTimestamp
	remaining, err := tls.Unmarshal(curBytes, &sct)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("trailing bytes")
	}

	verifier, err := h.getVerifier(table)
	if err != nil {
		return err
	}

	err = verifier.VerifySCTSignature(sct, ct.LogEntry{Leaf: *ct.CreateObjectHashMerkleTreeLeaf(hash, sct.Timestamp)})
	if err != nil {
		return err
	}

	// All good
	return nil
}

func (h *logAddHandler) addToVerifiableLog(job *que.Job) error {
	var jd struct {
		Table string                 `json:"table"`
		Data  map[string]interface{} `json:"data"`
	}
	err := json.Unmarshal(job.Args, &jd)
	if err != nil {
		return err
	}

	// Make sure table is a UUID to prevent us from making an inadvertent call to the wrong path
	u, err := uuid.FromString(jd.Table)
	if err != nil {
		return err
	}
	canonTable := u.String()

	id, ok := jd.Data["_id"].(int)
	if !ok {
		return errors.New("no _id found for object")
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
		// Ignore null values so that columns can be added over time, without affecting the signature
		if v == nil {
			continue
		}
		dataToSend[k] = v
	}

	oh, err := objecthash.ObjectHash(dataToSend)
	if err != nil {
		return err
	}

	currentSCT, _ := jd.Data["signed_certificate_timestamp"].(string)
	if currentSCT != "" {
		err = h.verifyIt(canonTable, currentSCT, oh[:])
		if err != nil {
			return err
		}

		// If we already have a valid one, stop now
		return nil
	}

	logClient, err := h.getLogClient(canonTable)
	if err != nil {
		return err
	}

	sct, err := logClient.AddObjectHash(context.Background(), oh[:], dataToSend)
	if err != nil {
		return err
	}

	tlsEncode, err := tls.Marshal(sct)
	if err != nil {
		return err
	}

	_, err = job.Conn().Exec(fmt.Sprintf(`UPDATE "%s" SET signed_certificate_timestamp = $1 WHERE _id = $2`, jd.Table), base64.StdEncoding.EncodeToString(tlsEncode), id)
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
