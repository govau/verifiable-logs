package generalisedtransparency

import (
	"net/http"

	"github.com/continusec/verifiabledatastructures/verifiable"
	verifiablelogs "github.com/govau/verifiable-logs"
)

func (cts *Server) handleMetadata(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	sk, err := cts.getSigningKey(vlog, r, false)
	if err != nil {
		return nil, err
	}
	return &verifiablelogs.MetadataResponse{
		Key: sk.PublicDER,
	}, nil
}
