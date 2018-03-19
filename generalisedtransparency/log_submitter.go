package generalisedtransparency

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/benlaurie/objecthash/go/objecthash"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/jackc/pgx"
	uuid "github.com/satori/go.uuid"
)

// LogSubmitter takes a server base, URL and an API key, and uses
// this to allow database rows to be submitted to a verifiable log server.
type LogSubmitter struct {
	// Server is the base URL
	Server string

	// APIKey is added an an Authorization header
	APIKey string

	verifierMutex sync.RWMutex
	verifiers     map[string]*ct.SignatureVerifier

	logClientMutex sync.RWMutex
	logClients     map[string]*client.LogClient

	publicKeyMutex sync.RWMutex
	publicKeyDERs  map[string][]byte
}

// SubmitToLogAndUpdateRecord submits the given data to a verifiable log,
// then updates the original record if it hasn't been changed since.
// If the SCT was already set correctly for the record, nothing is submitted.
// As such, it is OK if running this triggers itself again.
func (h *LogSubmitter) SubmitToLogAndUpdateRecord(ctx context.Context, tableName string, dataToSubmit map[string]interface{}, conn *pgx.Conn) error {
	// Since this data comes from JSON normally, it is braindead regarding integers
	idAsFloat, ok := dataToSubmit["_id"].(float64)
	if !ok {
		return errors.New("no primary found for object")
	}
	id := int(idAsFloat)
	if (idAsFloat - float64(id)) != 0.0 {
		return errors.New("json (which cannot represent an integer) has defeated us")
	}

	dataToSend := filterRow(dataToSubmit)
	oh, err := objecthash.ObjectHash(dataToSend)
	if err != nil {
		return err
	}

	// Make sure table is a UUID to prevent us from making an inadvertent call to the wrong path
	u, err := uuid.FromString(tableName)
	if err != nil {
		return err
	}
	canonTable := u.String()

	currentSCT, _ := dataToSubmit["signed_certificate_timestamp"].(string)
	if currentSCT != "" && h.verifyIt(canonTable, currentSCT, oh) == nil {
		// If we already have a valid one, stop now
		return nil
	}

	logClient, err := h.getLogClient(canonTable)
	if err != nil {
		return err
	}

	sct, err := logClient.AddObjectHash(ctx, oh, dataToSend)
	if err != nil {
		return err
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
	newObjHash, err := objecthash.ObjectHash(filterRow(rowData))
	if err != nil {
		return err
	}

	// Is our SCT valid for the state the row is now in?
	if newObjHash != oh {
		// must have changed since, nothing more we can do
		return nil
	}

	// We are good to go, so save it out
	_, err = tx.Exec(fmt.Sprintf(`UPDATE "%s" SET signed_certificate_timestamp = $1 WHERE _id = $2`, canonTable), base64.StdEncoding.EncodeToString(tlsEncode), id)
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
func (h *LogSubmitter) getLogClient(canonTable string) (*client.LogClient, error) {
	var rv *client.LogClient

	h.logClientMutex.RLock()
	if h.logClients != nil {
		rv = h.logClients[canonTable]
	}
	h.logClientMutex.RUnlock()

	if rv != nil {
		return rv, nil
	}

	// NOTE that the log client we get does NOT do verification.
	// This is deliberate, as may otherwise have a bootstrap problem whereby we
	// don't create a log until the first item is added to it, and thus do not have
	// a public key.
	rv, err := client.New(h.baseURLForLog(canonTable), &http.Client{
		Transport: &authRT{
			APIKey: h.APIKey,
		},
	}, jsonclient.Options{})
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
func (h *LogSubmitter) getVerifier(canonTable string) (*ct.SignatureVerifier, error) {
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
func (h *LogSubmitter) getPublicKeyDER(canonTable string) ([]byte, error) {
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

	resp, err := http.Get(h.baseURLForLog(canonTable) + "/ct/v1/metadata")
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

func filterRow(data map[string]interface{}) map[string]interface{} {
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
		dataToSend[k] = v
	}

	return dataToSend
}

type authRT struct {
	APIKey string
}

func (a *authRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", a.APIKey)
	return http.DefaultTransport.RoundTrip(req)
}
