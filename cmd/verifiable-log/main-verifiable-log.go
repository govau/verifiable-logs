package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/govau/verifiable-log"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/continusec/verifiabledatastructures/assets"
	"github.com/continusec/verifiabledatastructures/pb"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/govau/cf-common/env"
	"github.com/govau/verifiable-log/db"
	govpb "github.com/govau/verifiable-log/pb"
	"github.com/govau/verifiable-log/postgres"
)

const (
	maxEntriesToReturn = 100
)

type ctServer struct {
	Service *verifiable.Client
	// To use in wrapped logs
	Account string

	// To use with wrapped logs
	ReadAPIKey string

	// To use with wrapped logs
	WriteAPIKey string

	// To check to allow adding
	ExternalAddKey string

	// To read metadata
	Reader verifiable.StorageReader

	// To write metadata
	Writer verifiable.StorageWriter

	// Known logs
	knownLogMutex sync.RWMutex
	knownLogs     map[string]*signingKey
}

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

func (cts *ctServer) cacheSigningKey(logKeyString string, logMetadata *govpb.LogMetadata) (*signingKey, error) {
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

func (cts *ctServer) getSigningKey(vlog *verifiable.Log, r *http.Request, create bool) (*signingKey, error) {
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

func (cts *ctServer) handleMetadata(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	sk, err := cts.getSigningKey(vlog, r, false)
	if err != nil {
		return nil, err
	}
	return &verifiablelog.MetadataResponse{
		Key: sk.PublicDER,
	}, nil
}

func (cts *ctServer) handleAdd(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
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
	tsKey := append([]byte("sct"), ohr.Hash...)
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
	mtlBytes, err := tls.Marshal(mtl)
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
	digest := sha256.Sum256(tbs)
	sig, err := sk.PrivateKey.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow crypto errs
	}

	sct = govpb.AddResponse{
		Signature: sig,
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

func toIntBinary(i uint64) []byte {
	rv := make([]byte, 8)
	binary.BigEndian.PutUint64(rv, i)
	return rv
}

func (cts *ctServer) handleSTH(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	root, err := vlog.TreeHead(r.Context(), verifiable.Head)
	if err != nil {
		return nil, err
	}

	// See if we have an STH, and if so, we will return that
	ns, err := objecthash.ObjectHash(map[string]interface{}{
		"account": vlog.Log.Account.Id,
		"name":    vlog.Log.Name,
		"type":    "ctlog",
	})
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

	sk, err := cts.getSigningKey(vlog, r, false)
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
	digest := sha256.Sum256(tbs)
	sig, err := sk.PrivateKey.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, verifiable.ErrInternalError // swallow crypto errs
	}
	sth = govpb.SignedTreeHead{
		Sha256RootHash:    root.RootHash,
		Timestamp:         int64(ctSTH.Timestamp),
		TreeHeadSignature: sig,
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

func (cts *ctServer) wrapCall(apiKey string, ensureExists bool, f func(log *verifiable.Log, r *http.Request) (interface{}, error)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := uuid.FromString(mux.Vars(r)["uuid"])
		if err != nil {
			http.Error(w, "bad dataset id", http.StatusBadRequest)
			return
		}
		vlog := cts.Service.Account(cts.Account, apiKey).VerifiableLog(u.String())
		if ensureExists {
			// This is to make sure we don't spuriously create way too many tables in postgresql for logs that don't exists
			_, err = cts.getSigningKey(vlog, r, false)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
			}
		}
		obj, err := f(vlog, r)
		switch err {
		case nil:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(obj)
		case verifiable.ErrInvalidRequest, verifiable.ErrInvalidRange, verifiable.ErrInvalidTreeRange:
			http.Error(w, err.Error(), http.StatusBadRequest)
		case verifiable.ErrNotFound:
			http.Error(w, err.Error(), http.StatusNotFound)
		case verifiable.ErrNotAuthorized:
			http.Error(w, err.Error(), http.StatusForbidden)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (cts *ctServer) handleSTHConsistency(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
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

func (cts *ctServer) handleProofByHash(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
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

func (cts *ctServer) handleGetEntries(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
	start, err := strconv.Atoi(r.FormValue("start"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	end, err := strconv.Atoi(r.FormValue("end"))
	if err != nil {
		return nil, verifiable.ErrInvalidRequest
	}

	// Don't return more than a reasonable number at once.
	lastEntry := start + maxEntriesToReturn - 1
	if end > lastEntry {
		end = lastEntry
	}

	rv := &ct.GetEntriesResponse{}
	for entry := range vlog.Entries(r.Context(), int64(start), int64(end+1)) { // add one, as underlying API is not inclusive
		rv.Entries = append(rv.Entries, ct.LeafEntry{
			LeafInput: entry.LeafInput,
			ExtraData: entry.ExtraData,
		})
	}

	return rv, nil
}

func (cts *ctServer) handleGetEntryAndProof(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
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

func (cts *ctServer) addCallToRouter(r *mux.Router, path, apiKey string, ensureExists bool, f func(log *verifiable.Log, r *http.Request) (interface{}, error)) {
	r.HandleFunc("/dataset/{uuid}/ct/v1"+path, cts.wrapCall(apiKey, ensureExists, f))
}

func (cts *ctServer) CreateRESTHandler() http.Handler {
	r := mux.NewRouter()

	cts.addCallToRouter(r, "/metadata", cts.ReadAPIKey, true, cts.handleMetadata)
	cts.addCallToRouter(r, "/add-object-hash", cts.WriteAPIKey, false, cts.handleAdd)
	cts.addCallToRouter(r, "/get-sth", cts.ReadAPIKey, true, cts.handleSTH)
	cts.addCallToRouter(r, "/get-sth-consistency", cts.ReadAPIKey, true, cts.handleSTHConsistency)
	cts.addCallToRouter(r, "/get-proof-by-hash", cts.ReadAPIKey, true, cts.handleProofByHash)
	cts.addCallToRouter(r, "/get-entries", cts.ReadAPIKey, true, cts.handleGetEntries)
	cts.addCallToRouter(r, "/get-entry-and-proof", cts.ReadAPIKey, true, cts.handleGetEntryAndProof)

	return r
}

func altHomePage(h http.Handler) http.Handler {
	css := append(assets.MustAsset("assets/static/main.css"), []byte(`
		#topheaderpart, #bottomfooterpart {
			display: none;
		}
	`)...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/main.css" {
			w.Header().Set("Content-Type", "text/css")
			w.Write(css)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func main() {
	app, err := cfenv.Current()
	if err != nil {
		log.Fatal(err)
	}
	envLookup := env.NewVarSet(
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "govauverifiabledemo-ups"),
	)

	pgxPool, err := db.GetPGXPool(2)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare a shutdown function
	shutdown := func() {
		pgxPool.Close()
	}

	// Normal exit
	defer shutdown()

	// Or via signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, starting shutdown...", sig)
		shutdown()
		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	db := &postgres.Storage{
		Pool: pgxPool,
	}

	service := &verifiable.Service{
		AccessPolicy: &policy.Static{
			Policy: []*pb.ResourceAccount{
				{
					Id: "data.gov.au",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch: "*",
							Permissions: []pb.Permission{
								pb.Permission_PERM_LOG_PROVE_INCLUSION,
								pb.Permission_PERM_LOG_READ_ENTRY,
								pb.Permission_PERM_LOG_READ_HASH,
							},
							ApiKey:        "read",
							AllowedFields: []string{"*"},
						},
						{
							NameMatch: "*",
							Permissions: []pb.Permission{
								pb.Permission_PERM_LOG_RAW_ADD,
							},
							ApiKey:        "write",
							AllowedFields: []string{"*"},
						},
					},
				},
			},
		},
		Mutator: &instant.Mutator{
			Writer: db,
		},
		Reader: db,
	}

	server, err := service.Create()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Started up... waiting for ctrl-C.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envLookup.String("PORT", "8080")), (&ctServer{
		Service: &verifiable.Client{
			Service: server,
		},
		ReadAPIKey:     "read",
		WriteAPIKey:    "write",
		Reader:         db,
		Writer:         db,
		ExternalAddKey: envLookup.MustString("VDB_SECRET"),
	}).CreateRESTHandler()))
}
