package generalisedtransparency

import (
	"net/http"
	"strconv"

	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
)

func (cts *Server) handleSTHConsistency(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	first, err := strconv.Atoi(r.FormValue("first"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	second, err := strconv.Atoi(r.FormValue("second"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	answer, err := vlog.ConsistencyProof(r.Context(), int64(first), int64(second))
	if err != nil {
		return nil, err
	}

	return &ct.GetSTHConsistencyResponse{
		Consistency: answer.AuditPath,
	}, nil
}
