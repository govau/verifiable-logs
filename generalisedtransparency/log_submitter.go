package generalisedtransparency

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/benlaurie/objecthash/go/objecthash"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/jackc/pgx"
)

// LogSubmitter takes a server base, URL and an API key, and uses
// this to allow database rows to be submitted to a verifiable log server.
type LogSubmitter struct {
	// Server is the base URL
	Server string

	// APIKey is added an an Authorization header
	APIKey string

	// TableNameValidator validates a table name before processing it
	TableNameValidator TableNameValidator

	logClientMutex sync.Mutex
	logClients     map[string]*LogClient
}

// JSONIntID converts JSON number to an integer
func JSONIntID(val interface{}) (int, error) {
	// Since this data comes from JSON normally, it is braindead regarding integers
	idAsFloat, ok := val.(float64)
	if !ok {
		return 0, errors.New("expected float64")
	}
	id := int(idAsFloat)
	if (idAsFloat - float64(id)) != 0.0 {
		return 0, errors.New("json (which cannot represent an integer) has defeated us")
	}
	return id, nil
}

// SubmitToLogAndUpdateRecord submits the given data to a verifiable log,
// then updates the original record if it hasn't been changed since.
// If conn is nil, then we do not attempt to update a database, we just submit to the log.
// If the SCT was already set correctly for the record, nothing is submitted.
// As such, it is OK if running this triggers itself again.
func (h *LogSubmitter) SubmitToLogAndUpdateRecord(ctx context.Context, tableName string, dataToSubmit map[string]interface{}, conn *pgx.Conn) error {
	id, err := JSONIntID(dataToSubmit["_id"])
	if err != nil {
		return err
	}

	dataToSend, oh, err := filterAndHash(dataToSubmit)
	if err != nil {
		return err
	}

	// Make sure table is a valid to prevent us from making an inadvertent call to the wrong path
	canonTable, err := h.TableNameValidator.ValidateAndCanonicaliseTableName(tableName)
	if err != nil {
		return err
	}

	currentSCT, _ := dataToSubmit["signed_certificate_timestamp"].(string)
	if currentSCT != "" && h.verifyIt(canonTable, currentSCT, oh) == nil {
		// If we already have a valid one, stop now
		return nil
	}

	logClient, err := h.getLogClient(canonTable).GetAddClient()
	if err != nil {
		return err
	}

	sct, err := logClient.AddObjectHash(ctx, oh, dataToSend)
	if err != nil {
		return err
	}

	// If conn is nil, then we are done, we will not attempt to
	// save into our database (we might not have one!)
	if conn == nil {
		return nil
	}

	tlsEncode, err := tls.Marshal(*sct)
	if err != nil {
		return err
	}

	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(fmt.Sprintf(`SELECT * FROM "%s" WHERE _id = $1 FOR UPDATE`, canonTable), id)
	if err != nil {
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		// must have been deleted since, return nil as there's nothing more for us to do
		return nil
	}

	// We should now be at the first row
	vals, err := rows.Values()
	if err != nil {
		return err
	}

	// Turn into map
	rowData := make(map[string]interface{})
	for i, field := range rows.FieldDescriptions() {
		rowData[field.Name] = vals[i]
	}

	// Make sure we don't have another row...
	if rows.Next() {
		return errors.New("multiple records found with same _id")
	}

	// Now filter and hash it
	_, newObjHash, err := filterAndHash(rowData)
	if err != nil {
		return err
	}

	// Is our SCT valid for the state the row is now in?
	if !bytes.Equal(newObjHash[:], oh[:]) {
		// must have changed since, nothing more we can do
		return nil
	}

	toSetSCT := base64.StdEncoding.EncodeToString(tlsEncode)

	// Is the SCT we want to set identical to what is already set?
	if toSetSCT == rowData["signed_certificate_timestamp"] {
		return nil // nothing to do ehre
	}

	// We are good to go, so save it out
	_, err = tx.Exec(fmt.Sprintf(`UPDATE "%s" SET signed_certificate_timestamp = $1 WHERE _id = $2`, canonTable), toSetSCT, id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// Table name must already be canonical
func (h *LogSubmitter) baseURLForLog(canonTable string) string {
	return fmt.Sprintf("%s/dataset/%s", h.Server, canonTable)
}

// Table name must already be canonical
func (h *LogSubmitter) getLogClient(canonTable string) *LogClient {
	h.logClientMutex.Lock()
	defer h.logClientMutex.Unlock()

	if h.logClients == nil {
		h.logClients = make(map[string]*LogClient)
	}

	rv := h.logClients[canonTable]
	if rv != nil {
		return rv
	}

	rv = &LogClient{
		URL:       h.baseURLForLog(canonTable),
		AddAPIKey: h.APIKey,
	}
	h.logClients[canonTable] = rv

	return rv
}

// table name must already be canonical
func (h *LogSubmitter) verifyIt(table, currentSCT string, hash ct.ObjectHash) error {
	curBytes, err := base64.StdEncoding.DecodeString(currentSCT)
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

	verifier, err := h.getLogClient(table).GetVerifier()
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

func filterAndHash(data map[string]interface{}) (map[string]interface{}, ct.ObjectHash, error) {
	dataToSend := make(map[string]interface{})
	for k, v := range data {
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

		// We need to canonicalize some types, e.g. by default our DB driver seems to
		// return times without zones to localtime, whereas the json operator in postgres seems
		// to use UTC.
		switch vv := v.(type) {
		case time.Time:
			dataToSend[k] = vv.UTC().Format("2006-01-02T15:04:05.999999-07:00") // appears to match the postgres format
		default:
			dataToSend[k] = vv
		}
	}

	// Marshal, then unmarshal so that things like time.Time turn into a consistent format
	rdBytes, err := json.Marshal(dataToSend)
	if err != nil {
		return nil, ct.ObjectHash{}, err
	}
	var rdFresh map[string]interface{}
	err = json.Unmarshal(rdBytes, &rdFresh)
	if err != nil {
		return nil, ct.ObjectHash{}, err
	}

	oh, err := objecthash.ObjectHash(rdFresh)
	if err != nil {
		return nil, ct.ObjectHash{}, err
	}

	return rdFresh, oh, nil
}
