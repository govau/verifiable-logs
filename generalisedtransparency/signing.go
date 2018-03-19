package generalisedtransparency

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"net/http"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/verifiable"

	govpb "github.com/govau/verifiable-logs/pb"
)

type signingKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicDER  []byte
	LogID      [sha256.Size]byte
}

func makeKeyForLog(log *pb.LogRef) ([]byte, error) {
	h, err := objecthash.ObjectHash(map[string]interface{}{
		"account": log.Account.Id,
		"name":    log.Name,
		"type":    "log",
	})
	if err != nil {
		return nil, err
	}
	return h[:], nil
}

func (cts *Server) cacheSigningKey(logKeyString string, logMetadata *govpb.LogMetadata) (*signingKey, error) {
	pkey, err := x509.ParseECPrivateKey(logMetadata.PrivateKeyDer)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow real error please
	}

	pubKey, err := x509.MarshalPKIXPublicKey(&pkey.PublicKey)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow real error please
	}

	rv := &signingKey{
		PrivateKey: pkey,
		PublicDER:  pubKey,
		LogID:      sha256.Sum256(pubKey),
	}

	cts.knownLogMutex.Lock()
	if cts.knownLogs == nil {
		cts.knownLogs = make(map[string]*signingKey)
	}
	cts.knownLogs[logKeyString] = rv
	cts.knownLogMutex.Unlock()

	return rv, nil
}

func (cts *Server) getSigningKey(vlog *verifiable.Log, r *http.Request, create bool) (*signingKey, error) {
	logKey, err := makeKeyForLog(vlog.Log)
	if err != nil {
		return nil, err
	}

	logKeyString := string(logKey)

	var rv *signingKey
	cts.knownLogMutex.RLock()
	if cts.knownLogs != nil {
		rv = cts.knownLogs[logKeyString]
	}
	cts.knownLogMutex.RUnlock()

	if rv != nil {
		return rv, nil
	}

	// Weird, but same convention we use inside of verifiable data library
	ns, err := objecthash.ObjectHash(map[string]interface{}{
		"type": "metadata",
	})
	if err != nil {
		return nil, err
	}

	var logMetadata govpb.LogMetadata
	err = cts.Reader.ExecuteReadOnly(r.Context(), ns[:], func(ctx context.Context, kr verifiable.KeyReader) error {
		return kr.Get(ctx, logKey, &logMetadata)
	})
	switch err {
	case nil:
		return cts.cacheSigningKey(logKeyString, &logMetadata)
	case verifiable.ErrNoSuchKey:
		if !create {
			return nil, err
		}
		// else, continue, we'll create
	default:
		return nil, err
	}

	// Ok, time to create one
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow crypto errs
	}

	der, err := x509.MarshalECPrivateKey(pkey)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow crypto errs
	}

	err = cts.Writer.ExecuteUpdate(r.Context(), ns[:], func(ctx context.Context, kw verifiable.KeyWriter) error {
		// Check to see if anyone else has created one
		err := kw.Get(ctx, logKey, &logMetadata)
		switch err {
		case nil:
			// Exit early, we'll use this one instead
			return nil
		case verifiable.ErrNoSuchKey:
			// continue, we will create
		default:
			return err
		}

		logMetadata.PrivateKeyDer = der
		return kw.Set(ctx, logKey, &logMetadata)
	})
	if err != nil {
		return nil, err
	}

	return cts.cacheSigningKey(logKeyString, &logMetadata)
}
