package generalisedtransparency

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	govpb "github.com/govau/verifiable-logs/pb"
)

func (cts *Server) handleAdd(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	if r.Header.Get("Authorization") != cts.ExternalAddKey {
		return nil, verifiable.ErrNotAuthorized
	}

	if r.Method != http.MethodPost {
		return nil, verifiable.ErrInvalidRequest
	}

	var ohr ct.AddObjectHashRequest
	err := json.NewDecoder(r.Body).Decode(&ohr)
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	// See if we have an SCT for this, and if so, we will return that
	ns, err := objecthash.ObjectHash(map[string]interface{}{
		"account": vlog.Log.Account.Id,
		"name":    vlog.Log.Name,
		"type":    "ctlog",
	})
	if err != nil {
		return nil, err
	}
	tsKey := append([]byte("sct"), ohr.Hash[:]...)
	var sct govpb.AddResponse
	err = cts.Reader.ExecuteReadOnly(r.Context(), ns[:], func(ctx context.Context, kr verifiable.KeyReader) error {
		return kr.Get(ctx, tsKey, &sct)
	})
	switch err {
	case nil:
		// Get log ID and we're done
		sk, err := cts.getSigningKey(vlog, r, false)
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
	case verifiable.ErrNoSuchKey:
	// pass, continue, we'll make one
	default:
		return nil, err
	}

	// Now, add it
	edBytes, err := json.Marshal(ohr.ExtraData)
	if err != nil {
		return nil, err
	}

	ts := time.Now().UnixNano() / (1000 * 1000)
	mtl := ct.CreateObjectHashMerkleTreeLeaf(ohr.Hash, uint64(ts))
	mtlBytes, err := tls.Marshal(*mtl)
	if err != nil {
		return nil, err
	}

	_, err = vlog.Add(r.Context(), &pb.LeafData{
		LeafInput: mtlBytes,
		ExtraData: edBytes,
	})
	if err != nil {
		return nil, err
	}

	// Grab the signing key
	sk, err := cts.getSigningKey(vlog, r, true)
	if err != nil {
		return nil, err
	}

	// Then promise we'll add it
	tbs, err := ct.SerializeSCTSignatureInput(ct.SignedCertificateTimestamp{
		LogID:      ct.LogID{KeyID: sk.LogID},
		SCTVersion: ct.V1,
		Timestamp:  uint64(ts),
	}, ct.LogEntry{
		Leaf: *mtl,
	})
	if err != nil {
		return nil, err
	}

	dss, err := tls.CreateSignature(*sk.PrivateKey, tls.SHA256, tbs)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow crypto errs
	}

	sigBytes, err := tls.Marshal(dss)
	if err != nil {
		return nil, err
	}

	sct = govpb.AddResponse{
		Signature: sigBytes,
		Timestamp: ts,
	}

	// Save it out
	err = cts.Writer.ExecuteUpdate(r.Context(), ns[:], func(ctx context.Context, kw verifiable.KeyWriter) error {
		return kw.Set(ctx, tsKey, &sct)
	})
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
