package generalisedtransparency

import (
	"sync"

	"github.com/continusec/verifiabledatastructures/verifiable"
)

// Server implements an RFC6962-style set of verifiable logs servers over REST
type Server struct {
	// Service is the underlying verifiabledatastructures client used for log management
	Service *verifiable.Client

	// Account is verifiabledatastructures account to use with Service
	Account string

	// ReadAPIKey is the API key to use to read from Service
	ReadAPIKey string

	// ReadAPIKey is the API key to use to write to Service (used by /add-objecthash only)
	WriteAPIKey string

	// ExternalAddKey is the API key that clients need to send us in order to be allowed to call /add-objecthash
	ExternalAddKey string

	// Reader is a storage layer where we can read log signing keys, as well as published STHes and an index of objecthash to MerkleTreeLeaf.
	Reader verifiable.StorageReader

	// Writer is a storage layer where we can write for the same reasons we need to read above
	Writer verifiable.StorageWriter

	// Known logs - here we caching the signing key. TODO, consider caching all sorts of other things!
	// We actually use this on every request, if nothing else but an indication of if a log exists, and thus whether
	// we should allow a read-only operation to do (to stop creating new tables on read of a non-existent log)
	knownLogMutex sync.RWMutex
	knownLogs     map[string]*signingKey
}
