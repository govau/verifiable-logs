package generalisedtransparency

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

// LogClient provides an wrapper for interacting with our generalised logs
type LogClient struct {
	URL       string
	AddAPIKey string

	verifierMutex sync.Mutex
	verifier      *ct.SignatureVerifier
	pubKeyDER     []byte

	addClientMutex sync.Mutex
	addClient      *client.LogClient

	readClientMutex sync.Mutex
	readClient      *client.LogClient
}

// AddClient contains the subset of LogClient functionality needed for adding things
type AddClient interface {
	AddObjectHash(ctx context.Context, hash ct.ObjectHash, extraData interface{}) (*ct.SignedCertificateTimestamp, error)
}

// GetAddClient returns a client that will add the authorization header, but will
// not perform verification, and as such, we only return an interface with a subset
// of actually functionality.
func (c *LogClient) GetAddClient() (AddClient, error) {
	c.addClientMutex.Lock()
	defer c.addClientMutex.Unlock()

	if c.addClient != nil {
		return c.addClient, nil
	}

	rv, err := client.New(c.URL, &http.Client{
		Transport: &authRT{
			Authorization: c.AddAPIKey,
		},
	}, jsonclient.Options{})
	if err != nil {
		return nil, err
	}
	c.addClient = rv

	return rv, nil
}

// AuditClient gives subset of methods suitable for auditing a log
type AuditClient interface {
	GetSTH(ctx context.Context) (*ct.SignedTreeHead, error)
	GetSTHConsistency(ctx context.Context, first, second uint64) ([][]byte, error)
	GetProofByHash(ctx context.Context, hash []byte, treeSize uint64) (*ct.GetProofByHashResponse, error)
	GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error)
	GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error)
}

// GetReadClient returns a client suitable for auditing the log
func (c *LogClient) GetReadClient() (AuditClient, error) {
	c.readClientMutex.Lock()
	defer c.readClientMutex.Unlock()

	if c.readClient != nil {
		return c.readClient, nil
	}

	_, publicKeyDer, err := c.getVerifierAndDER()
	if err != nil {
		return nil, err
	}

	rv, err := client.New(c.URL, http.DefaultClient, jsonclient.Options{
		PublicKeyDER: publicKeyDer,
	})
	if err != nil {
		return nil, err
	}
	c.readClient = rv

	return rv, nil
}

// GetVerifier returns a SignatureVerifier
func (c *LogClient) GetVerifier() (*ct.SignatureVerifier, error) {
	rv, _, err := c.getVerifierAndDER()
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (c *LogClient) getVerifierAndDER() (*ct.SignatureVerifier, []byte, error) {
	c.verifierMutex.Lock()
	defer c.verifierMutex.Unlock()

	if c.verifier != nil {
		return c.verifier, c.pubKeyDER, nil
	}
	resp, err := http.Get(c.URL + "/ct/v1/metadata")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("bad http status code fetching log metadata")
	}

	var md MetadataResponse
	err = json.NewDecoder(resp.Body).Decode(&md)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(md.Key)
	if err != nil {
		return nil, nil, err
	}

	rv, err := ct.NewSignatureVerifier(pubKey)
	if err != nil {
		return nil, nil, err
	}

	c.verifier = rv
	c.pubKeyDER = md.Key

	return rv, md.Key, nil
}

type authRT struct {
	Authorization string
}

func (a *authRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", a.Authorization)
	return http.DefaultTransport.RoundTrip(req)
}
