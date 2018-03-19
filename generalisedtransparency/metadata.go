package generalisedtransparency

import (
	"net/http"

	"github.com/continusec/verifiabledatastructures/verifiable"
)

// MetadataResponse is a subset of a log as defined at: https://www.gstatic.com/ct/log_list/log_list_schema.json
type MetadataResponse struct {
	// Key is the ASN.1 DER encoded ECDSA public key for the log
	Key []byte `json:"key"`
}

func (cts *Server) handleMetadata(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	sk, err := cts.getSigningKey(vlog, r, false)
	if err != nil {
		return nil, err
	}
	return &MetadataResponse{
		Key: sk.PublicDER,
	}, nil
}
