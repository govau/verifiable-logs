package generalisedtransparency

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
	govpb "github.com/govau/verifiable-logs/pb"
)

func (cts *Server) handleGetObjectHash(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	hash, err := base64.StdEncoding.DecodeString(r.FormValue("hash"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	rv, err := cts.findSCT(r.Context(), vlog, hash)
	if err != nil {
		return nil, err
	}

	return rv, err
}

func (cts *Server) getNs(vlog *verifiable.Log) ([sha256.Size]byte, error) {
	return objecthash.ObjectHash(map[string]interface{}{
		"account": vlog.Log.Account.Id,
		"name":    vlog.Log.Name,
		"type":    "ctlog",
	})
}

// returns verifiable.ErrNotFound if not found
// else returns SCT, ns for database,
func (cts *Server) findSCT(ctx context.Context, vlog *verifiable.Log, hash []byte) (*ct.AddChainResponse, error) {
	// See if we have an SCT for this
	ns, err := cts.getNs(vlog)
	if err != nil {
		return nil, err
	}
	tsKey := append([]byte("sct"), hash...)

	var sct govpb.AddResponse
	err = cts.Reader.ExecuteReadOnly(ctx, ns[:], func(ctx context.Context, kr verifiable.KeyReader) error {
		return kr.Get(ctx, tsKey, &sct)
	})
	switch err {
	case nil:
		// continue
	case verifiable.ErrNoSuchKey:
		return nil, verifiable.ErrNotFound
	default:
		return nil, err
	}

	// Get log ID and we're done
	sk, err := cts.getSigningKey(ctx, vlog, false)
	if err != nil {
		return nil, err
	}

	// we're done!
	return &ct.AddChainResponse{
		ID:         sk.LogID[:],
		SCTVersion: ct.V1,
		Signature:  sct.Signature,
		Timestamp:  uint64(sct.Timestamp),
		Extensions: "",
	}, nil
}
