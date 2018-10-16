package generalisedtransparency

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/fullsailor/pkcs7"
	ct "github.com/google/certificate-transparency-go"
)

// APIKeyValidator accepts any JSON input where an authorization header is present with the API key
type APIKeyValidator string

// ValidateSubmission in this case does not check the object hash matches the data- this is an authorization decision only
func (v APIKeyValidator) ValidateSubmission(vlog *verifiable.Log, r *http.Request) ([]byte, *ct.MerkleTreeLeaf, []byte, error) {
	if r.Header.Get("Authorization") != string(v) {
		return nil, nil, nil, verifiable.ErrNotAuthorized
	}

	var ohr ct.AddObjectHashRequest
	err := json.NewDecoder(r.Body).Decode(&ohr)
	if err != nil {
		return nil, nil, nil, verifiable.ErrInvalidRequest
	}

	edBytes, err := json.Marshal(ohr.ExtraData)
	if err != nil {
		return nil, nil, nil, err
	}

	return ohr.Hash[:], ct.CreateObjectHashMerkleTreeLeaf(ohr.Hash, 0), edBytes, nil
}

func CreateTrustedCAValidator(caPem string, dataVerifier DataVerifier) (SubmissionValidator, error) {
	verifyOptions := x509.VerifyOptions{
		Roots:     x509.NewCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	if !verifyOptions.Roots.AppendCertsFromPEM([]byte(caPem)) {
		return nil, errors.New("cannot load CAs from cert. expected list of PEM certificates")
	}

	return &caVerifier{
		verifyOptions: verifyOptions,
		dataVerifier:  dataVerifier,
	}, nil
}

type DataVerifier func(cert *x509.Certificate, data []byte) error

type caVerifier struct {
	verifyOptions x509.VerifyOptions
	dataVerifier  DataVerifier
}

func (v *caVerifier) ValidateSubmission(vlog *verifiable.Log, r *http.Request) ([]byte, *ct.MerkleTreeLeaf, []byte, error) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, nil, nil, err
	}

	sd, err := pkcs7.Parse(b)
	if err != nil {
		return nil, nil, nil, err
	}

	// This verifies that the data is in fact signed by the cert within
	err = sd.Verify()
	if err != nil {
		return nil, nil, nil, err
	}

	cert := sd.GetOnlySigner()
	if cert == nil {
		return nil, nil, nil, errors.New("expected single signer")
	}

	// Verify that the cert itself is one we trust
	// While the PKCS7 library says it doesn't validate the time,
	// doing the cert verification will verify that this cert is valid now,
	// which is nearly good enough.
	_, err = cert.Verify(v.verifyOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify the data itself is good, ie usually this should check timestamps and subject against the cert
	err = v.dataVerifier(cert, sd.Content)
	if err != nil {
		return nil, nil, nil, err
	}

	// Finally, we'll make the original data our leaf input
	h := sha256.Sum256(b)
	return h[:], ct.CreateCMSMerkleTreeLeaf(b, 0), nil, nil
}
