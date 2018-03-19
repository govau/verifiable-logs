package generalisedtransparency

import (
	"net/http"
	"strconv"

	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
)

func (cts *Server) handleGetEntryAndProof(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	treeSize, err := strconv.Atoi(r.FormValue("tree_size"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	leafIndex, err := strconv.Atoi(r.FormValue("leaf_index"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	proof, err := vlog.InclusionProofByIndex(r.Context(), int64(treeSize), int64(leafIndex))
	if err != nil {
		return nil, err
	}

	entry, err := vlog.Entry(r.Context(), int64(leafIndex))
	if err != nil {
		return nil, err
	}

	return &ct.GetEntryAndProofResponse{
		LeafInput: entry.LeafInput,
		ExtraData: entry.ExtraData,
		AuditPath: proof.AuditPath,
	}, nil
}
