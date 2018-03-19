package generalisedtransparency

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
)

func (cts *Server) handleProofByHash(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	treeSize, err := strconv.Atoi(r.FormValue("tree_size"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	hash, err := base64.StdEncoding.DecodeString(r.FormValue("hash"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	proof, err := vlog.InclusionProof(r.Context(), int64(treeSize), hash)
	if err != nil {
		return nil, err
	}

	return &ct.GetProofByHashResponse{
		LeafIndex: proof.LeafIndex,
		AuditPath: proof.AuditPath,
	}, nil
}
