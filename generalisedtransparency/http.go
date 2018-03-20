package generalisedtransparency

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/continusec/verifiabledatastructures/verifiable"
)

// CreateRESTHandler returns an http.Handler for our REST API
func (cts *Server) CreateRESTHandler() http.Handler {
	r := mux.NewRouter()

	cts.addCallToRouter(r, "/metadata", cts.ReadAPIKey, true, cts.handleMetadata)
	cts.addCallToRouter(r, "/add-objecthash", cts.WriteAPIKey, false, cts.handleAdd)
	cts.addCallToRouter(r, "/get-sth", cts.ReadAPIKey, true, cts.handleSTH)
	cts.addCallToRouter(r, "/get-sth-consistency", cts.ReadAPIKey, true, cts.handleSTHConsistency)
	cts.addCallToRouter(r, "/get-proof-by-hash", cts.ReadAPIKey, true, cts.handleProofByHash)
	cts.addCallToRouter(r, "/get-entries", cts.ReadAPIKey, true, cts.handleGetEntries)
	cts.addCallToRouter(r, "/get-entry-and-proof", cts.ReadAPIKey, true, cts.handleGetEntryAndProof)

	return r
}

func (cts *Server) wrapCall(apiKey string, ensureExists bool, f func(log *verifiable.Log, r *http.Request) (interface{}, error)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL.String())

		// Make sure table is a valid to prevent us from making an inadvertent call to the wrong path
		canonTable, err := cts.TableNameValidator.ValidateAndCanonicaliseTableName(mux.Vars(r)["logname"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		vlog := cts.Service.Account(cts.Account, apiKey).VerifiableLog(canonTable)
		if ensureExists {
			// This is to make sure we don't spuriously create way too many tables in postgresql for logs that don't exists
			_, err = cts.getSigningKey(vlog, r, false)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
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

func (cts *Server) addCallToRouter(r *mux.Router, path, apiKey string, ensureExists bool, f func(log *verifiable.Log, r *http.Request) (interface{}, error)) {
	r.HandleFunc("/dataset/{logname}/ct/v1"+path, cts.wrapCall(apiKey, ensureExists, f))
}
