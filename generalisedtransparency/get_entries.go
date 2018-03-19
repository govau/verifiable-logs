package generalisedtransparency

import (
	"net/http"
	"strconv"

	"github.com/continusec/verifiabledatastructures/verifiable"
	ct "github.com/google/certificate-transparency-go"
)

const (
	maxEntriesToReturn = 100
)

func (cts *Server) handleGetEntries(vlog *verifiable.Log, r *http.Request) (interface{}, error) {
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
	if len(rv.Entries) == 0 { // typically if the size were sent in wrong
		return nil, verifiable.ErrInvalidRange
	}

	return rv, nil
}
