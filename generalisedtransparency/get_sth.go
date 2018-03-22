package generalisedtransparency

import (
	"context"
	"encoding/binary"
	"net/http"
	"strconv"
	"time"

	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	govpb "github.com/govau/verifiable-logs/pb"
)

func toIntBinary(i uint64) []byte {
	rv := make([]byte, 8)
	binary.BigEndian.PutUint64(rv, i)
	return rv
}

func (cts *Server) handleSTH(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	sizeToFetch := int(verifiable.Head)

	ts := r.FormValue("tree_size")
	if ts != "" {
		var err error
		sizeToFetch, err = strconv.Atoi(ts)
		if err != nil {
			return nil, verifiable.ErrInvalidRequest
		}
	}

	root, err := vlog.TreeHead(r.Context(), int64(sizeToFetch))
	if err != nil {
		return nil, err
	}

	// See if we have an STH, and if so, we will return that
	ns, err := cts.getNs(vlog)
	if err != nil {
		return nil, err
	}

	tsKey := append([]byte("sth"), toIntBinary(uint64(root.TreeSize))...)
	var sth govpb.SignedTreeHead
	err = cts.Reader.ExecuteReadOnly(r.Context(), ns[:], func(ctx context.Context, kr verifiable.KeyReader) error {
		return kr.Get(ctx, tsKey, &sth)
	})
	switch err {
	case nil:
		// we're done!
		return &ct.GetSTHResponse{
			TreeSize:          uint64(sth.TreeSize),
			Timestamp:         uint64(sth.Timestamp),
			SHA256RootHash:    sth.Sha256RootHash,
			TreeHeadSignature: sth.TreeHeadSignature,
		}, nil
	case verifiable.ErrNoSuchKey:
	// pass, continue, we'll make one
	default:
		return nil, err
	}

	sk, err := cts.getSigningKey(r.Context(), vlog, false)
	if err != nil {
		return nil, err
	}

	// Else we write one
	ctSTH := ct.SignedTreeHead{
		Version:   ct.V1,
		TreeSize:  uint64(root.TreeSize),
		Timestamp: uint64(time.Now().UnixNano() / (1000 * 1000)),
		LogID:     sk.LogID,
	}
	copy(ctSTH.SHA256RootHash[:], root.RootHash)
	tbs, err := ct.SerializeSTHSignatureInput(ctSTH)
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

	sth = govpb.SignedTreeHead{
		Sha256RootHash:    root.RootHash,
		Timestamp:         int64(ctSTH.Timestamp),
		TreeHeadSignature: sigBytes,
		TreeSize:          root.TreeSize,
	}

	// Save it out
	err = cts.Writer.ExecuteUpdate(r.Context(), ns[:], func(ctx context.Context, kw verifiable.KeyWriter) error {
		return kw.Set(ctx, tsKey, &sth)
	})
	if err != nil {
		return nil, err
	}

	// we're done!
	return &ct.GetSTHResponse{
		TreeSize:          uint64(sth.TreeSize),
		Timestamp:         uint64(sth.Timestamp),
		SHA256RootHash:    sth.Sha256RootHash,
		TreeHeadSignature: sth.TreeHeadSignature,
	}, nil
}
